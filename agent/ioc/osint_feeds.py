"""
OSINT feed adapters.

Supported feeds:
  - Abuse.ch URLhaus   (recent malicious URLs)
  - Abuse.ch MalwareBazaar  (recent malware samples with hashes)
  - Feodo Tracker      (C2 IP blocklist)
  - AlienVault OTX     (threat intelligence pulses)

Each adapter returns a list[IOC] and is safe to call repeatedly; timestamps
are used to avoid re-processing indicators already seen.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Optional

import requests

from .normalizer import IOC

logger = logging.getLogger(__name__)

_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "ThreatHuntingAgent/1.0"})
_TIMEOUT = 30


# ---------------------------------------------------------------------------
# Abuse.ch URLhaus
# ---------------------------------------------------------------------------

def fetch_urlhaus(
    api_url: str = "https://urlhaus-api.abuse.ch/v1/urls/recent/",
    since: Optional[datetime] = None,
) -> list[IOC]:
    """
    Pull recent malicious URLs from Abuse.ch URLhaus.
    Returns IOCs of type 'url'.
    """
    iocs: list[IOC] = []
    try:
        resp = _SESSION.post(api_url, data={"limit": 1000}, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.error("URLhaus fetch failed: %s", exc)
        return iocs

    for entry in data.get("urls", []):
        if entry.get("url_status") not in ("online", "unknown"):
            continue
        added_dt_str = entry.get("date_added", "")
        if since and added_dt_str:
            try:
                added_dt = datetime.fromisoformat(added_dt_str.replace(" ", "T")).replace(tzinfo=timezone.utc)
                if added_dt < since:
                    continue
            except ValueError:
                pass

        url = entry.get("url", "")
        if not url:
            continue

        tags = [t for t in (entry.get("tags") or []) if t]

        iocs.append(IOC(
            ioc_type="url",
            value=url,
            source="osint",
            confidence=0.75,
            context=f"Abuse.ch URLhaus — threat: {entry.get('threat', 'unknown')}",
            tags=["urlhaus"] + tags,
            first_seen=entry.get("date_added", ""),
        ))

    logger.info("URLhaus: fetched %d IOCs", len(iocs))
    return iocs


# ---------------------------------------------------------------------------
# Abuse.ch MalwareBazaar
# ---------------------------------------------------------------------------

def fetch_malwarebazaar(
    api_url: str = "https://mb-api.abuse.ch/api/v1/",
    limit: int = 1000,
    since: Optional[datetime] = None,
) -> list[IOC]:
    """
    Pull recent malware samples from MalwareBazaar.
    Returns SHA256, SHA1, MD5 IOCs for each sample.
    """
    iocs: list[IOC] = []
    try:
        resp = _SESSION.post(
            api_url,
            data={"query": "get_recent", "selector": "time"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.error("MalwareBazaar fetch failed: %s", exc)
        return iocs

    for sample in (data.get("data") or [])[:limit]:
        first_seen_str = sample.get("first_seen", "")
        if since and first_seen_str:
            try:
                first_seen_dt = datetime.fromisoformat(first_seen_str.replace(" ", "T")).replace(tzinfo=timezone.utc)
                if first_seen_dt < since:
                    continue
            except ValueError:
                pass

        tags = list(sample.get("tags") or [])
        context = (
            f"MalwareBazaar — family: {sample.get('signature', 'unknown')}, "
            f"file: {sample.get('file_name', '')}"
        )
        common = dict(source="osint", confidence=0.8, context=context,
                      tags=["malwarebazaar"] + tags, first_seen=first_seen_str)

        for hash_type, field in [("hash_sha256", "sha256_hash"),
                                  ("hash_sha1", "sha1_hash"),
                                  ("hash_md5", "md5_hash")]:
            value = sample.get(field, "")
            if value:
                iocs.append(IOC(ioc_type=hash_type, value=value, **common))

    logger.info("MalwareBazaar: fetched %d IOCs", len(iocs))
    return iocs


# ---------------------------------------------------------------------------
# Feodo Tracker C2 IP blocklist
# ---------------------------------------------------------------------------

def fetch_feodo_tracker(
    url: str = "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
) -> list[IOC]:
    """
    Pull C2 IP addresses from Feodo Tracker.
    Returns IOCs of type 'ip'.
    """
    iocs: list[IOC] = []
    try:
        resp = _SESSION.get(url, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.error("Feodo Tracker fetch failed: %s", exc)
        return iocs

    for entry in data:
        ip = entry.get("ip_address", "")
        if not ip:
            continue
        malware = entry.get("malware", "unknown")
        iocs.append(IOC(
            ioc_type="ip",
            value=ip,
            source="osint",
            confidence=0.85,
            context=f"Feodo Tracker C2 — malware: {malware}, port: {entry.get('port', '?')}",
            tags=["feodo", "c2", malware.lower()],
            first_seen=entry.get("first_seen", ""),
        ))

    logger.info("Feodo Tracker: fetched %d IOCs", len(iocs))
    return iocs


# ---------------------------------------------------------------------------
# AlienVault OTX
# ---------------------------------------------------------------------------

def fetch_otx_pulses(
    api_key: str,
    base_url: str = "https://otx.alienvault.com",
    limit: int = 20,
    since: Optional[datetime] = None,
) -> list[IOC]:
    """
    Pull indicators from AlienVault OTX subscribed pulses.
    Returns mixed IOC types based on indicator type.
    """
    _OTX_TYPE_MAP = {
        "IPv4": "ip",
        "IPv6": "ip",
        "domain": "domain",
        "hostname": "domain",
        "URL": "url",
        "FileHash-MD5": "hash_md5",
        "FileHash-SHA1": "hash_sha1",
        "FileHash-SHA256": "hash_sha256",
        "email": "email",
    }

    headers = {"X-OTX-API-KEY": api_key}
    iocs: list[IOC] = []
    url = f"{base_url}/api/v1/pulses/subscribed?limit={limit}"
    if since:
        url += f"&modified_since={since.isoformat()}"

    while url:
        try:
            resp = _SESSION.get(url, headers=headers, timeout=_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.error("OTX fetch failed: %s", exc)
            break

        for pulse in data.get("results", []):
            pulse_name = pulse.get("name", "")
            tags = list(pulse.get("tags") or [])

            for indicator in pulse.get("indicators", []):
                ind_type = indicator.get("type", "")
                ioc_type = _OTX_TYPE_MAP.get(ind_type)
                if ioc_type is None:
                    continue

                value = indicator.get("indicator", "")
                if not value:
                    continue

                iocs.append(IOC(
                    ioc_type=ioc_type,
                    value=value,
                    source="osint",
                    confidence=0.7,
                    context=f"OTX pulse: {pulse_name}",
                    tags=["otx"] + tags,
                    first_seen=indicator.get("created", ""),
                ))

        url = data.get("next")  # pagination

    logger.info("OTX: fetched %d IOCs", len(iocs))
    return iocs


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def fetch_all_osint(config: dict, since: Optional[datetime] = None) -> list[IOC]:
    """
    Fetch from all enabled OSINT sources defined in config['ioc_sources']['osint'].
    """
    all_iocs: list[IOC] = []
    sources: list[dict] = config.get("ioc_sources", {}).get("osint", [])

    for src in sources:
        if not src.get("enabled", True):
            continue
        name = src.get("name", "")

        if name == "abuse_ch_urlhaus":
            all_iocs += fetch_urlhaus(api_url=src.get("url", "https://urlhaus-api.abuse.ch/v1/urls/recent/"), since=since)

        elif name == "abuse_ch_malwarebazaar":
            all_iocs += fetch_malwarebazaar(api_url=src.get("url", "https://mb-api.abuse.ch/api/v1/"), since=since)

        elif name == "feodo_tracker":
            all_iocs += fetch_feodo_tracker(url=src.get("url", "https://feodotracker.abuse.ch/downloads/ipblocklist.json"))

        elif name == "alientvault_otx":
            api_key = src.get("api_key", "")
            if not api_key:
                logger.warning("OTX skipped — no api_key configured")
                continue
            all_iocs += fetch_otx_pulses(api_key=api_key, since=since)

        else:
            logger.warning("Unknown OSINT source: %s", name)

    return all_iocs
