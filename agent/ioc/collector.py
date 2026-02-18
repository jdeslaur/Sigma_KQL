"""
IOC Collector — orchestrates all configured IOC sources.

Calls OSINT feeds, LLM extractor, MITRE Detection Strategies, and commercial TI,
then deduplicates everything into the IOCStore.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from .commercial_adapter import build_adapter
from .llm_extractor import LLMExtractor
from .mitre_det_strategies import MitreDetectionStrategies
from .normalizer import IOC, IOCStore
from .osint_feeds import fetch_all_osint

logger = logging.getLogger(__name__)


class IOCCollector:
    """
    Collects IOCs from all enabled sources and persists them in the IOCStore.

    Usage:
        collector = IOCCollector(config, store)
        new_iocs = collector.collect()          # one full collection cycle
    """

    def __init__(self, config: dict, store: IOCStore) -> None:
        self._config = config
        self._store = store
        self._last_run: Optional[datetime] = None

        # Initialise sub-components
        self._llm = LLMExtractor(config)
        self._commercial = build_adapter(config)
        self._mitre: Optional[MitreDetectionStrategies] = None

        mitre_cfg = config.get("ioc_sources", {}).get("mitre_detection_strategies", {})
        if mitre_cfg.get("enabled", True):
            try:
                self._mitre = MitreDetectionStrategies(config)
                logger.info("MITRE Detection Strategies loaded: %s", self._mitre.summary())
            except Exception as exc:
                logger.warning("Could not initialise MITRE Detection Strategies: %s", exc)

    # ------------------------------------------------------------------

    def collect(self, since: Optional[datetime] = None) -> list[IOC]:
        """
        Run one full collection cycle across all sources.

        Args:
            since: only fetch indicators seen/published after this timestamp.
                   Defaults to self._last_run (i.e., incremental).

        Returns:
            List of IOCs that were *newly* added to the store during this cycle.
        """
        effective_since = since or self._last_run
        newly_added: list[IOC] = []

        # ---- 1. OSINT feeds ----
        logger.info("Collecting from OSINT feeds…")
        osint_iocs = fetch_all_osint(self._config, since=effective_since)
        newly_added += self._ingest(osint_iocs, "OSINT")

        # ---- 2. LLM — CVE advisories ----
        logger.info("Collecting from NVD CVE feed (LLM extraction)…")
        cve_iocs = self._llm.extract_from_cves(since=effective_since)
        newly_added += self._ingest(cve_iocs, "LLM/CVE")

        # ---- 3. LLM — analyst-supplied URLs ----
        news_urls = self._config.get("ioc_sources", {}).get("news_urls", [])
        if news_urls:
            logger.info("Collecting from %d analyst-supplied URLs (LLM extraction)…", len(news_urls))
            url_iocs = self._llm.extract_from_urls(news_urls)
            newly_added += self._ingest(url_iocs, "LLM/URL")

        # ---- 4. MITRE Detection Strategies ----
        if self._mitre:
            mitre_cfg = self._config.get("ioc_sources", {}).get("mitre_detection_strategies", {})
            scan_all = mitre_cfg.get("scan_all_on_startup", False)

            if scan_all or self._last_run is None:
                logger.info("Collecting TTP IOCs from MITRE Detection Strategies…")
                mitre_iocs = self._mitre.as_iocs()
                newly_added += self._ingest(mitre_iocs, "MITRE/DETxxxx")
            else:
                logger.debug("Skipping MITRE DETxxxx sweep (scan_all_on_startup=false and not first run)")

        # ---- 5. Commercial TI ----
        if self._commercial.name != "null":
            logger.info("Collecting from commercial TI (%s)…", self._commercial.name)
            commercial_iocs = self._commercial.fetch_iocs(since=effective_since)
            newly_added += self._ingest(commercial_iocs, "Commercial")

        self._last_run = datetime.now(timezone.utc)
        logger.info(
            "Collection cycle complete. %d new IOCs added (total in store: %d)",
            len(newly_added), self._store.count(),
        )
        return newly_added

    def add_manual(self, text: str, label: str = "manual") -> list[IOC]:
        """Add IOCs extracted from analyst-supplied free text via LLM."""
        iocs = self._llm.extract_from_text(text, source_label=label)
        return self._ingest(iocs, f"Manual/{label}")

    def add_manual_ioc(self, ioc: IOC) -> bool:
        """Directly add a single hand-crafted IOC. Returns True if new."""
        new = self._store.add(ioc)
        if new:
            logger.info("Manual IOC added: %s", ioc.dedup_key())
        return new

    # ------------------------------------------------------------------

    def _ingest(self, iocs: list[IOC], source_label: str) -> list[IOC]:
        """Add a list of IOCs to the store and return those that were new."""
        new_iocs: list[IOC] = []
        for ioc in iocs:
            if self._store.add(ioc):
                new_iocs.append(ioc)
        logger.debug("%s: %d/%d were new", source_label, len(new_iocs), len(iocs))
        return new_iocs
