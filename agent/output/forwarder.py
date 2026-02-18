"""
Pluggable SIEM forwarder base class and routing logic.

Each adapter receives enriched events:
    {
        "original_event": {...},
        "matched_ioc": {...},
        "detection_rule": "...",
        "det_strategies": [...],
        "analyst_notes": "...",
        "hit_id": "...",
        "forwarded_at": "ISO8601"
    }

Adapters: Sentinel | Splunk HEC | syslog
"""

import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class SIEMAdapter(ABC):
    """Base class for all SIEM output adapters."""

    @abstractmethod
    def send(self, events: list[dict]) -> int:
        """
        Forward enriched events to the SIEM.
        Returns the count of successfully forwarded events.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...


# ---------------------------------------------------------------------------
# Event enrichment
# ---------------------------------------------------------------------------

def enrich_event(
    raw_event: dict,
    hit_id: str,
    ioc_value: str,
    ioc_type: str,
    description: str,
    matched_rules: list[str],
    det_strategies: list[str],
    analyst_note: str,
) -> dict:
    """Wrap a raw Cribl event with hunt context for SIEM ingestion."""
    return {
        "forwarded_at": datetime.now(timezone.utc).isoformat(),
        "hit_id": hit_id,
        "matched_ioc": {"type": ioc_type, "value": ioc_value},
        "detection_rules": matched_rules,
        "det_strategies": det_strategies,
        "description": description,
        "analyst_note": analyst_note,
        "original_event": raw_event,
    }


# ---------------------------------------------------------------------------
# Microsoft Sentinel adapter (Azure Monitor HTTP Data Collector API)
# ---------------------------------------------------------------------------

class SentinelAdapter(SIEMAdapter):
    """
    Forward events to Microsoft Sentinel via the HTTP Data Collector API.
    Docs: https://learn.microsoft.com/azure/azure-monitor/logs/data-collector-api
    """

    def __init__(self, workspace_id: str, shared_key: str, log_type: str = "ThreatHuntingFindings") -> None:
        import hashlib, hmac, base64
        self._workspace_id = workspace_id
        self._shared_key = shared_key
        self._log_type = log_type
        self._url = (
            f"https://{workspace_id}.ods.opinsights.azure.com"
            f"/api/logs?api-version=2016-04-01"
        )

    @property
    def name(self) -> str:
        return "sentinel"

    def _build_signature(self, date: str, content_length: int) -> str:
        import hashlib, hmac, base64
        string_to_hash = "\n".join([
            "POST",
            str(content_length),
            "application/json",
            f"x-ms-date:{date}",
            "/api/logs",
        ])
        bytes_to_hash = string_to_hash.encode("utf-8")
        decoded_key = base64.b64decode(self._shared_key)
        sig = base64.b64encode(
            hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
        ).decode("utf-8")
        return f"SharedKey {self._workspace_id}:{sig}"

    def send(self, events: list[dict]) -> int:
        import requests
        from email.utils import formatdate

        if not events:
            return 0

        body = json.dumps(events)
        date = formatdate(usegmt=True)
        signature = self._build_signature(date, len(body))

        headers = {
            "Content-Type": "application/json",
            "Log-Type": self._log_type,
            "x-ms-date": date,
            "Authorization": signature,
        }

        try:
            resp = requests.post(self._url, data=body, headers=headers, timeout=30)
            resp.raise_for_status()
            logger.info("Sentinel: forwarded %d events to log type %s", len(events), self._log_type)
            return len(events)
        except Exception as exc:
            logger.error("Sentinel forwarding failed: %s", exc)
            return 0


# ---------------------------------------------------------------------------
# Splunk HEC adapter
# ---------------------------------------------------------------------------

class SplunkHECAdapter(SIEMAdapter):
    """
    Forward events to Splunk via the HTTP Event Collector.
    """

    def __init__(self, hec_url: str, token: str, index: str = "threat_hunting", sourcetype: str = "cribl:hunt:finding") -> None:
        self._hec_url = hec_url.rstrip("/") + "/services/collector/event"
        self._token = token
        self._index = index
        self._sourcetype = sourcetype

    @property
    def name(self) -> str:
        return "splunk"

    def send(self, events: list[dict]) -> int:
        import requests

        if not events:
            return 0

        # Splunk HEC expects newline-delimited JSON objects, each with a wrapper
        batch = "\n".join(
            json.dumps({
                "sourcetype": self._sourcetype,
                "index": self._index,
                "event": ev,
            })
            for ev in events
        )

        headers = {
            "Authorization": f"Splunk {self._token}",
            "Content-Type": "application/json",
        }

        try:
            resp = requests.post(self._hec_url, data=batch, headers=headers, timeout=30)
            resp.raise_for_status()
            logger.info("Splunk HEC: forwarded %d events", len(events))
            return len(events)
        except Exception as exc:
            logger.error("Splunk HEC forwarding failed: %s", exc)
            return 0


# ---------------------------------------------------------------------------
# Generic syslog adapter (RFC 5424)
# ---------------------------------------------------------------------------

class SyslogAdapter(SIEMAdapter):
    """
    Forward events as RFC 5424 syslog messages over UDP or TCP.
    """

    def __init__(self, host: str = "localhost", port: int = 514, protocol: str = "udp") -> None:
        self._host = host
        self._port = port
        self._protocol = protocol.lower()

    @property
    def name(self) -> str:
        return "syslog"

    def send(self, events: list[dict]) -> int:
        import socket

        sent = 0
        for ev in events:
            msg = f"<134>1 {datetime.now(timezone.utc).isoformat()} - ThreatHunt - - - {json.dumps(ev)}"
            encoded = msg.encode("utf-8", errors="replace")

            try:
                if self._protocol == "udp":
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.sendto(encoded, (self._host, self._port))
                else:
                    with socket.create_connection((self._host, self._port), timeout=10) as s:
                        s.sendall(encoded + b"\n")
                sent += 1
            except Exception as exc:
                logger.error("Syslog send failed: %s", exc)

        logger.info("Syslog: forwarded %d/%d events", sent, len(events))
        return sent


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def build_forwarder(config: dict) -> SIEMAdapter:
    """Construct a SIEMAdapter from agent config."""
    siem_cfg = config.get("siem", {})
    adapter_name = siem_cfg.get("adapter", "syslog").lower()

    if adapter_name == "sentinel":
        s = siem_cfg.get("sentinel", {})
        return SentinelAdapter(
            workspace_id=s["workspace_id"],
            shared_key=s["shared_key"],
            log_type=s.get("log_type", "ThreatHuntingFindings"),
        )
    elif adapter_name == "splunk":
        s = siem_cfg.get("splunk", {})
        return SplunkHECAdapter(
            hec_url=s["hec_url"],
            token=s["token"],
            index=s.get("index", "threat_hunting"),
            sourcetype=s.get("sourcetype", "cribl:hunt:finding"),
        )
    elif adapter_name == "syslog":
        s = siem_cfg.get("syslog", {})
        return SyslogAdapter(
            host=s.get("host", "localhost"),
            port=int(s.get("port", 514)),
            protocol=s.get("protocol", "udp"),
        )
    else:
        raise ValueError(f"Unknown SIEM adapter: {adapter_name!r}. Supported: sentinel, splunk, syslog")
