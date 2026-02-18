"""
Pluggable commercial threat intelligence adapter.

Defines the CommercialTIAdapter ABC so that any commercial TI platform
(Recorded Future, CrowdStrike Falcon Intelligence, VirusTotal Enterprise, etc.)
can be integrated by implementing a single subclass.

A stub/no-op adapter is provided when no commercial source is configured.
"""

import logging
from abc import ABC, abstractmethod
from typing import Optional

from .normalizer import IOC

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class CommercialTIAdapter(ABC):
    """
    Interface for commercial threat intelligence sources.

    Implementors must override fetch_iocs() to return a list[IOC].
    The agent calls this on a schedule; use `since` to fetch only new data.
    """

    @abstractmethod
    def fetch_iocs(self, since: Optional[object] = None) -> list[IOC]:  # since: datetime | None
        """Return newly available IOCs, optionally filtered by timestamp."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of this adapter."""
        ...


# ---------------------------------------------------------------------------
# No-op adapter (used when commercial TI is disabled)
# ---------------------------------------------------------------------------

class NullAdapter(CommercialTIAdapter):
    @property
    def name(self) -> str:
        return "null"

    def fetch_iocs(self, since=None) -> list[IOC]:
        return []


# ---------------------------------------------------------------------------
# Example stub: Recorded Future
# ---------------------------------------------------------------------------

class RecordedFutureAdapter(CommercialTIAdapter):
    """
    Stub for Recorded Future Connect API.

    To implement:
      - Authenticate via API key: Authorization: Token <api_key>
      - Fetch alerts from GET /v2/alert/search or risklist endpoints
      - Map RF entity types to IOC types
      - Fill in fetch_iocs() with actual HTTP calls

    See: https://api.recordedfuture.com/v2/
    """

    def __init__(self, api_key: str, base_url: str = "https://api.recordedfuture.com") -> None:
        self._api_key = api_key
        self._base_url = base_url

    @property
    def name(self) -> str:
        return "recorded_future"

    def fetch_iocs(self, since=None) -> list[IOC]:
        # TODO: implement RF Connect API calls
        logger.warning("RecordedFutureAdapter.fetch_iocs() is a stub — not yet implemented")
        return []


# ---------------------------------------------------------------------------
# Example stub: CrowdStrike Falcon Intelligence
# ---------------------------------------------------------------------------

class CrowdStrikeAdapter(CommercialTIAdapter):
    """
    Stub for CrowdStrike Falcon Intelligence API.

    To implement:
      - Authenticate via OAuth2 (client_id + client_secret → bearer token)
      - Fetch indicators from GET /intel/combined/indicators/v1
      - Map CS indicator types to IOC types

    See: https://falconpy.io/Service-Collections/Intel.html
    """

    def __init__(self, client_id: str, client_secret: str) -> None:
        self._client_id = client_id
        self._client_secret = client_secret

    @property
    def name(self) -> str:
        return "crowdstrike"

    def fetch_iocs(self, since=None) -> list[IOC]:
        # TODO: implement CrowdStrike OAuth + indicator fetch
        logger.warning("CrowdStrikeAdapter.fetch_iocs() is a stub — not yet implemented")
        return []


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_ADAPTER_REGISTRY: dict[str, type[CommercialTIAdapter]] = {
    "recorded_future": RecordedFutureAdapter,
    "crowdstrike": CrowdStrikeAdapter,
}


def build_adapter(config: dict) -> CommercialTIAdapter:
    """
    Construct a CommercialTIAdapter from agent config.

    Config shape (under ioc_sources.commercial):
        enabled: true
        adapter: recorded_future
        api_key: ...
    """
    commercial_cfg = config.get("ioc_sources", {}).get("commercial", {})

    if not commercial_cfg.get("enabled", False):
        return NullAdapter()

    adapter_name = commercial_cfg.get("adapter") or ""
    if not adapter_name:
        logger.info("No commercial TI adapter configured")
        return NullAdapter()

    cls = _ADAPTER_REGISTRY.get(adapter_name)
    if cls is None:
        logger.warning("Unknown commercial TI adapter: %r. Available: %s", adapter_name, list(_ADAPTER_REGISTRY))
        return NullAdapter()

    api_key = commercial_cfg.get("api_key", "")
    try:
        adapter = cls(api_key=api_key) if "api_key" in cls.__init__.__code__.co_varnames else cls()
        logger.info("Commercial TI adapter loaded: %s", adapter.name)
        return adapter
    except Exception as exc:
        logger.error("Failed to instantiate %s adapter: %s", adapter_name, exc)
        return NullAdapter()
