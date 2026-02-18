"""
MITRE ATT&CK Detection Strategies loader (ATT&CK v18+).

ATT&CK v18 (October 2025) introduced Detection Strategies (DETxxxx) and
Analytics (ANxxxx) as first-class STIX objects. This module:

  1. Downloads the Enterprise ATT&CK STIX 2.1 bundle from GitHub if not cached.
  2. Parses Detection Strategy objects and their linked Analytics.
  3. Provides lookup by technique ID to drive Cribl Search query generation.
  4. Optionally emits TTP-type IOCs for every DETxxxx entry to seed the hunt queue.

Dependencies:
    pip install mitreattack-python stix2 requests
"""

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_HTTP = requests.Session()
_HTTP.headers.update({"User-Agent": "ThreatHuntingAgent/1.0"})
_TIMEOUT = 60


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AnalyticEntry:
    analytic_id: str             # e.g. "AN0001"
    name: str
    description: str
    platforms: list[str] = field(default_factory=list)
    data_components: list[str] = field(default_factory=list)
    log_sources: list[str] = field(default_factory=list)
    detection_logic: str = ""    # free-text or pseudo-code from the STIX object


@dataclass
class DetectionStrategy:
    det_id: str                  # e.g. "DET0001"
    name: str
    description: str
    technique_ids: list[str] = field(default_factory=list)   # ATT&CK technique(s)
    analytics: list[AnalyticEntry] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    url: str = ""


# ---------------------------------------------------------------------------
# STIX bundle downloader
# ---------------------------------------------------------------------------

_DEFAULT_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)


def download_stix_bundle(
    dest_path: str | Path,
    url: str = _DEFAULT_BUNDLE_URL,
    force: bool = False,
) -> bool:
    """
    Download the ATT&CK Enterprise STIX bundle to *dest_path*.
    Returns True on success, False on failure.
    Skips download if the file already exists and force=False.
    """
    dest = Path(dest_path)
    if dest.exists() and not force:
        logger.info("ATT&CK STIX bundle already cached at %s", dest)
        return True

    logger.info("Downloading ATT&CK STIX bundle from %s …", url)
    try:
        with _HTTP.get(url, stream=True, timeout=_TIMEOUT) as resp:
            resp.raise_for_status()
            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(dest, "wb") as f:
                for chunk in resp.iter_content(chunk_size=1 << 20):
                    f.write(chunk)
        logger.info("ATT&CK STIX bundle saved to %s", dest)
        return True
    except Exception as exc:
        logger.error("Failed to download ATT&CK STIX bundle: %s", exc)
        return False


# ---------------------------------------------------------------------------
# STIX parser
# ---------------------------------------------------------------------------

_STIX_DET_TYPE = "x-mitre-detection-strategy"
_STIX_AN_TYPE = "x-mitre-analytic"
_STIX_TECHNIQUE_TYPE = "attack-pattern"
_STIX_REL_TYPE = "relationship"


def _get_external_id(obj: dict) -> str:
    """Extract the DETxxxx / ANxxxx / Txxxx identifier from external_references."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _parse_bundle(bundle_path: str | Path) -> tuple[dict[str, DetectionStrategy], dict[str, AnalyticEntry]]:
    """
    Parse the STIX bundle and return:
      - strategies: dict[det_id → DetectionStrategy]
      - analytics:  dict[an_id  → AnalyticEntry]
    """
    logger.info("Parsing ATT&CK STIX bundle at %s …", bundle_path)

    with open(bundle_path, encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])

    # Index objects by STIX id for relationship resolution
    by_stix_id: dict[str, dict] = {o["id"]: o for o in objects}

    # --- Parse Analytics (ANxxxx) ---
    analytics: dict[str, AnalyticEntry] = {}
    for obj in objects:
        if obj.get("type") != _STIX_AN_TYPE:
            continue
        an_id = _get_external_id(obj)
        if not an_id:
            continue

        entry = AnalyticEntry(
            analytic_id=an_id,
            name=obj.get("name", ""),
            description=obj.get("description", ""),
            platforms=obj.get("x_mitre_platforms", []),
            data_components=[
                dc.get("name", "") for dc in obj.get("x_mitre_data_components", [])
            ] if isinstance(obj.get("x_mitre_data_components"), list) else [],
            log_sources=[
                ls if isinstance(ls, str) else ls.get("name", "")
                for ls in obj.get("x_mitre_log_sources", [])
            ],
            detection_logic=obj.get("x_mitre_detection", obj.get("description", "")),
        )
        analytics[an_id] = entry

    # --- Parse Detection Strategies (DETxxxx) ---
    strategies: dict[str, DetectionStrategy] = {}
    for obj in objects:
        if obj.get("type") != _STIX_DET_TYPE:
            continue
        det_id = _get_external_id(obj)
        if not det_id:
            continue

        strategy = DetectionStrategy(
            det_id=det_id,
            name=obj.get("name", ""),
            description=obj.get("description", ""),
            platforms=obj.get("x_mitre_platforms", []),
            url=next(
                (r.get("url", "") for r in obj.get("external_references", [])
                 if r.get("source_name") == "mitre-attack"),
                f"https://attack.mitre.org/detectionstrategies/{det_id}/",
            ),
        )
        strategies[det_id] = strategy

    # --- Resolve relationships ---
    # Relationship types to look for (ATT&CK v18 schema)
    for obj in objects:
        if obj.get("type") != _STIX_REL_TYPE:
            continue

        rel_type = obj.get("relationship_type", "")
        src_id = obj.get("source_ref", "")
        tgt_id = obj.get("target_ref", "")

        src = by_stix_id.get(src_id, {})
        tgt = by_stix_id.get(tgt_id, {})

        src_type = src.get("type", "")
        tgt_type = tgt.get("type", "")

        # Detection Strategy → detects → Technique
        if src_type == _STIX_DET_TYPE and tgt_type == _STIX_TECHNIQUE_TYPE:
            det_id = _get_external_id(src)
            tech_id = _get_external_id(tgt)
            if det_id in strategies and tech_id:
                if tech_id not in strategies[det_id].technique_ids:
                    strategies[det_id].technique_ids.append(tech_id)

        # Analytic → implements → Detection Strategy
        if src_type == _STIX_AN_TYPE and tgt_type == _STIX_DET_TYPE:
            an_id = _get_external_id(src)
            det_id = _get_external_id(tgt)
            if an_id in analytics and det_id in strategies:
                analytic = analytics[an_id]
                if analytic not in strategies[det_id].analytics:
                    strategies[det_id].analytics.append(analytic)

    logger.info(
        "Parsed %d Detection Strategies and %d Analytics from ATT&CK bundle",
        len(strategies), len(analytics),
    )
    return strategies, analytics


# ---------------------------------------------------------------------------
# Main interface
# ---------------------------------------------------------------------------

class MitreDetectionStrategies:
    """
    Load and query MITRE ATT&CK Detection Strategies (DETxxxx).

    Usage:
        mds = MitreDetectionStrategies(config)
        strategies = mds.get_strategies_for_technique("T1059.001")
        all_iocs   = mds.as_iocs()   # emit all strategies as TTP IOCs
    """

    def __init__(self, config: dict) -> None:
        mitre_cfg = config.get("mitre", {})
        self._bundle_path = Path(mitre_cfg.get("stix_bundle_path", "enterprise-attack.json"))
        self._bundle_url = mitre_cfg.get("stix_data_repo", _DEFAULT_BUNDLE_URL)
        self._auto_refresh = mitre_cfg.get("auto_refresh", True)

        self._strategies: dict[str, DetectionStrategy] = {}
        self._analytics: dict[str, AnalyticEntry] = {}
        # Index: technique_id → list[DetectionStrategy]
        self._by_technique: dict[str, list[DetectionStrategy]] = {}

        self._ensure_bundle()
        self._load()

    def _ensure_bundle(self) -> None:
        if not self._bundle_path.exists():
            success = download_stix_bundle(self._bundle_path, self._bundle_url)
            if not success:
                logger.warning("Could not download ATT&CK STIX bundle. Detection Strategies will be unavailable.")

    def _load(self) -> None:
        if not self._bundle_path.exists():
            return
        self._strategies, self._analytics = _parse_bundle(self._bundle_path)

        # Build technique index
        self._by_technique = {}
        for strategy in self._strategies.values():
            for tech_id in strategy.technique_ids:
                self._by_technique.setdefault(tech_id, []).append(strategy)

    def refresh(self) -> None:
        """Re-download and re-parse the STIX bundle."""
        download_stix_bundle(self._bundle_path, self._bundle_url, force=True)
        self._load()

    # --- Query methods ---

    def get_strategies_for_technique(self, technique_id: str) -> list[DetectionStrategy]:
        """Return all Detection Strategies that target the given ATT&CK technique."""
        return self._by_technique.get(technique_id, [])

    def get_strategy(self, det_id: str) -> Optional[DetectionStrategy]:
        """Return a single Detection Strategy by DETxxxx ID."""
        return self._strategies.get(det_id)

    def get_all_strategies(self) -> list[DetectionStrategy]:
        """Return all 691 (Enterprise) Detection Strategies."""
        return list(self._strategies.values())

    def get_covered_techniques(self) -> list[str]:
        """Return sorted list of ATT&CK technique IDs that have at least one Detection Strategy."""
        return sorted(self._by_technique.keys())

    # --- IOC emission ---

    def as_iocs(self, only_techniques: Optional[list[str]] = None) -> list:
        """
        Emit TTP-type IOCs for every Detection Strategy (or a filtered subset).
        These IOCs seed the hunt queue so the query builder generates Cribl queries
        for all covered ATT&CK techniques.
        """
        from .normalizer import IOC

        iocs = []
        strategies = (
            [s for t in only_techniques for s in self._by_technique.get(t, [])]
            if only_techniques
            else self.get_all_strategies()
        )

        seen_techniques: set[str] = set()
        for strategy in strategies:
            for tech_id in strategy.technique_ids:
                if tech_id in seen_techniques:
                    continue
                seen_techniques.add(tech_id)

                iocs.append(IOC(
                    ioc_type="ttp",
                    value=tech_id,
                    source="mitre_det",
                    confidence=0.9,
                    mitre_techniques=[tech_id],
                    det_strategies=[strategy.det_id],
                    context=(
                        f"{strategy.det_id}: {strategy.name} — "
                        f"{strategy.description[:200]}"
                    ),
                    tags=["mitre", "detection-strategy", strategy.det_id.lower()],
                ))

        logger.info("Emitted %d TTP IOCs from MITRE Detection Strategies", len(iocs))
        return iocs

    # --- Summary ---

    def summary(self) -> dict:
        return {
            "total_strategies": len(self._strategies),
            "total_analytics": len(self._analytics),
            "covered_techniques": len(self._by_technique),
            "bundle_path": str(self._bundle_path),
        }
