"""
LLM-powered IOC extractor.

Uses the Claude API to parse CVE advisories, threat intelligence blog posts,
and news articles and extract structured IOCs (indicators + TTPs + context).

Sources supported:
  - NIST NVD CVE API  (CVE artifacts and affected products)
  - Arbitrary URLs    (threat blogs, vendor advisories, news)
"""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Optional

import anthropic
import requests

from .normalizer import IOC

logger = logging.getLogger(__name__)

_HTTP = requests.Session()
_HTTP.headers.update({"User-Agent": "ThreatHuntingAgent/1.0"})
_TIMEOUT = 30

# ---------------------------------------------------------------------------
# Prompt template
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are a threat intelligence analyst specialising in
extracting Indicators of Compromise (IOCs) and MITRE ATT&CK TTPs from
unstructured security text. Extract only information that is explicitly present
in the provided text — do not hallucinate or infer indicators.

Return your response as a JSON array of indicator objects. Each object must have:
  "ioc_type"          : one of: ttp, cve, cmdline, file_path, registry, ip,
                        domain, url, hash_md5, hash_sha1, hash_sha256, ja3, email
  "value"             : the exact indicator value (technique ID for ttp, CVE-XXXX-XXXXX for cve, etc.)
  "confidence"        : float 0.0–1.0 based on how explicitly stated it is
  "mitre_techniques"  : list of ATT&CK technique IDs (e.g. ["T1059.001"]), empty list if none
  "context"           : one sentence explaining why this indicator is significant
  "tags"              : list of relevant tags (e.g. ["ransomware", "persistence"])

Return ONLY the JSON array, no markdown, no explanation.
If no IOCs are found return an empty JSON array: []
"""

_USER_TEMPLATE = """Extract all IOCs and TTPs from the following security text:

---
{text}
---"""

# ---------------------------------------------------------------------------
# NIST NVD CVE fetcher
# ---------------------------------------------------------------------------

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_recent_cves(
    lookback_days: int = 7,
    min_cvss: float = 7.0,
) -> list[dict]:
    """
    Fetch recently published CVEs from NIST NVD.
    Returns raw CVE dicts (not yet converted to IOCs).
    """
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=lookback_days)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 100,
    }

    cves = []
    start_index = 0

    while True:
        params["startIndex"] = start_index
        try:
            resp = _HTTP.get(_NVD_BASE, params=params, timeout=_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.error("NVD CVE fetch failed: %s", exc)
            break

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})

            # Extract CVSS score (v3.1 preferred, fall back to v3.0, v2.0)
            score = 0.0
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                for metric in metrics.get(key, []):
                    score = metric.get("cvssData", {}).get("baseScore", 0.0)
                    if score:
                        break
                if score:
                    break

            if score < min_cvss:
                continue

            cves.append({
                "id": cve.get("id"),
                "score": score,
                "description": next(
                    (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                    "",
                ),
                "published": cve.get("published", ""),
            })

        total = data.get("totalResults", 0)
        start_index += data.get("resultsPerPage", 100)
        if start_index >= total:
            break

    logger.info("NVD: fetched %d CVEs (min CVSS %.1f, last %d days)", len(cves), min_cvss, lookback_days)
    return cves


# ---------------------------------------------------------------------------
# URL content fetcher
# ---------------------------------------------------------------------------

def fetch_url_text(url: str) -> str:
    """Fetch the plain text of a URL, stripping HTML tags."""
    try:
        resp = _HTTP.get(url, timeout=_TIMEOUT)
        resp.raise_for_status()
        text = resp.text
        # Naive HTML tag removal
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s{2,}", " ", text).strip()
        # Cap at ~8000 chars to keep LLM context reasonable
        return text[:8000]
    except Exception as exc:
        logger.error("URL fetch failed (%s): %s", url, exc)
        return ""


# ---------------------------------------------------------------------------
# LLM extraction core
# ---------------------------------------------------------------------------

def _call_llm(client: anthropic.Anthropic, text: str, model: str, max_tokens: int) -> list[dict]:
    """Send text to Claude and parse the returned JSON array of IOC dicts."""
    if not text.strip():
        return []

    try:
        message = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": _USER_TEMPLATE.format(text=text)}],
        )
        raw = message.content[0].text.strip()
        # Strip markdown code fences if present
        raw = re.sub(r"^```(?:json)?", "", raw).rstrip("`").strip()
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.error("LLM returned invalid JSON: %s", exc)
        return []
    except Exception as exc:
        logger.error("LLM call failed: %s", exc)
        return []


def _dicts_to_iocs(raw_iocs: list[dict], source_context: str) -> list[IOC]:
    """Convert raw LLM output dicts into IOC objects, skipping invalid entries."""
    from .normalizer import VALID_IOC_TYPES

    result: list[IOC] = []
    for item in raw_iocs:
        try:
            ioc_type = str(item.get("ioc_type", "")).strip()
            value = str(item.get("value", "")).strip()

            if ioc_type not in VALID_IOC_TYPES or not value:
                continue

            result.append(IOC(
                ioc_type=ioc_type,
                value=value,
                source="llm",
                confidence=float(item.get("confidence", 0.7)),
                mitre_techniques=list(item.get("mitre_techniques") or []),
                context=f"{source_context} | {item.get('context', '')}",
                tags=list(item.get("tags") or []) + ["llm-extracted"],
            ))
        except Exception as exc:
            logger.debug("Skipping malformed IOC dict: %s — %s", item, exc)

    return result


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

class LLMExtractor:
    """
    Extract IOCs from CVE advisories and arbitrary URLs using Claude.

    Usage:
        extractor = LLMExtractor(config)
        iocs = extractor.extract_from_cves()
        iocs += extractor.extract_from_url("https://example.com/threat-report")
    """

    def __init__(self, config: dict) -> None:
        llm_cfg = config.get("llm", {})
        self._client = anthropic.Anthropic(api_key=llm_cfg.get("api_key", ""))
        self._model = llm_cfg.get("model", "claude-opus-4-6")
        self._max_tokens = int(llm_cfg.get("max_tokens", 4096))
        self._config = config

    def extract_from_cves(self, since: Optional[datetime] = None) -> list[IOC]:
        """Fetch recent high-severity CVEs from NVD and extract IOCs via LLM."""
        cve_cfg = {}
        for src in self._config.get("ioc_sources", {}).get("cve_feeds", []):
            if src.get("name") == "nist_nvd" and src.get("enabled", True):
                cve_cfg = src
                break

        if not cve_cfg:
            return []

        lookback = int(cve_cfg.get("lookback_days", 7))
        min_cvss = float(cve_cfg.get("min_cvss_score", 7.0))
        cves = fetch_recent_cves(lookback_days=lookback, min_cvss=min_cvss)

        all_iocs: list[IOC] = []
        for cve in cves:
            cve_id = cve["id"]
            description = cve["description"]
            if not description:
                continue

            logger.debug("Extracting IOCs from %s (CVSS %.1f)", cve_id, cve["score"])
            raw = _call_llm(self._client, description, self._model, self._max_tokens)
            iocs = _dicts_to_iocs(raw, source_context=cve_id)

            # Ensure the CVE ID itself is always an IOC
            if not any(i.ioc_type == "cve" and i.value == cve_id for i in iocs):
                iocs.append(IOC(
                    ioc_type="cve",
                    value=cve_id,
                    source="llm",
                    confidence=0.95,
                    context=f"{cve_id} (CVSS {cve['score']:.1f}): {description[:200]}",
                    tags=["nvd", "cve"],
                    first_seen=cve.get("published", ""),
                ))

            all_iocs.extend(iocs)

        logger.info("LLM CVE extraction: %d IOCs from %d CVEs", len(all_iocs), len(cves))
        return all_iocs

    def extract_from_url(self, url: str) -> list[IOC]:
        """Fetch a URL and extract IOCs from its text content via LLM."""
        text = fetch_url_text(url)
        if not text:
            return []

        logger.debug("Extracting IOCs from URL: %s", url)
        raw = _call_llm(self._client, text, self._model, self._max_tokens)
        iocs = _dicts_to_iocs(raw, source_context=f"URL:{url}")
        logger.info("LLM URL extraction (%s): %d IOCs", url, len(iocs))
        return iocs

    def extract_from_urls(self, urls: list[str]) -> list[IOC]:
        """Extract IOCs from multiple URLs."""
        all_iocs: list[IOC] = []
        for url in urls:
            all_iocs.extend(self.extract_from_url(url))
        return all_iocs

    def extract_from_text(self, text: str, source_label: str = "manual") -> list[IOC]:
        """Extract IOCs from arbitrary text provided directly."""
        raw = _call_llm(self._client, text, self._model, self._max_tokens)
        return _dicts_to_iocs(raw, source_context=source_label)
