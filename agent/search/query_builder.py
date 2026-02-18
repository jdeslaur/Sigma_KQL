"""
Query Builder — translates IOCs and TTPs into Cribl Search queries.

Produces a list of HuntQuery objects, each containing:
  - A Cribl SPL query string
  - Metadata (source IOC, matched rules, time range)

Two paths:
  1. TTP / behavioral IOCs → look up matching Sigma rules + MITRE DETxxxx analytics
  2. CVE / exploit artifacts → synthesise targeted search patterns from IOC metadata
  3. Simple indicators (IP, domain, hash, etc.) → field-search queries
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from ..ioc.normalizer import IOC
from .sigma_mapper import SigmaRule, SigmaRuleIndex, sigma_rule_to_cribl_query

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data class for a hunt query ready to submit to Cribl Search
# ---------------------------------------------------------------------------

@dataclass
class HuntQuery:
    query: str                          # Cribl SPL query string
    ioc_id: str                         # Source IOC id
    ioc_type: str
    ioc_value: str
    sigma_rules: list[str] = field(default_factory=list)   # matched rule titles
    det_strategies: list[str] = field(default_factory=list) # DETxxxx IDs used
    time_range: dict = field(default_factory=dict)
    description: str = ""


# ---------------------------------------------------------------------------
# Query builder
# ---------------------------------------------------------------------------

_CRIBL_INDICATOR_FIELDS: dict[str, list[str]] = {
    "ip":         ["src_ip", "dst_ip", "RemoteIP", "LocalIP"],
    "domain":     ["domain", "query", "RemoteUrl", "url", "dnsQuery"],
    "url":        ["url", "RemoteUrl"],
    "hash_md5":   ["hash_md5", "MD5", "FileHash"],
    "hash_sha1":  ["hash_sha1", "SHA1"],
    "hash_sha256":["hash_sha256", "SHA256"],
    "email":      ["email", "senderAddress", "recipientAddress"],
    "cmdline":    ["cmdline", "ProcessCommandLine", "parent_cmdline"],
    "file_path":  ["file_path", "FolderPath", "ObjectName"],
    "registry":   ["registry_key", "RegistryKey"],
}


class QueryBuilder:
    """
    Build Cribl Search queries from IOCs.

    Usage:
        builder = QueryBuilder(config, sigma_index, mitre_strategies)
        queries = builder.build_queries(iocs)
    """

    def __init__(
        self,
        config: dict,
        sigma_index: SigmaRuleIndex,
        mitre_strategies=None,  # MitreDetectionStrategies | None
    ) -> None:
        self._config = config
        self._sigma = sigma_index
        self._mitre = mitre_strategies
        self._time_range_days = int(config.get("cribl", {}).get("time_range_days", 90))
        self._default_dataset = config.get("cribl", {}).get("default_dataset", "archived_logs")

    def build_queries(self, iocs: list[IOC]) -> list[HuntQuery]:
        """Generate Cribl Search queries for a list of IOCs."""
        queries: list[HuntQuery] = []
        for ioc in iocs:
            queries.extend(self._build_for_ioc(ioc))
        # Deduplicate identical query strings
        seen: set[str] = set()
        deduped: list[HuntQuery] = []
        for q in queries:
            if q.query not in seen:
                seen.add(q.query)
                deduped.append(q)
        logger.info("Built %d unique Cribl queries from %d IOCs", len(deduped), len(iocs))
        return deduped

    def _build_for_ioc(self, ioc: IOC) -> list[HuntQuery]:
        if ioc.ioc_type == "ttp":
            return self._build_ttp_queries(ioc)
        elif ioc.ioc_type == "cve":
            return self._build_cve_queries(ioc)
        else:
            return self._build_indicator_queries(ioc)

    # ------------------------------------------------------------------
    # TTP-based queries (Sigma rules + MITRE analytics)
    # ------------------------------------------------------------------

    def _build_ttp_queries(self, ioc: IOC) -> list[HuntQuery]:
        """
        For a TTP IOC (MITRE technique ID), generate queries from:
          1. Matching Sigma/KQL rules in kql_output/
          2. Analytics (ANxxxx) from the corresponding Detection Strategy
        """
        tech_id = ioc.value.upper()
        queries: list[HuntQuery] = []
        tr = self._default_time_range()

        # --- Sigma rules matching this technique ---
        rules = self._sigma.get_by_technique(tech_id)

        # Prioritise critical/high severity rules, cap at 10
        rules = sorted(
            rules,
            key=lambda r: {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
                          .get(r.severity, 5),
        )[:10]

        for rule in rules:
            try:
                cribl_query = sigma_rule_to_cribl_query(rule)
                queries.append(HuntQuery(
                    query=cribl_query,
                    ioc_id=ioc.id,
                    ioc_type=ioc.ioc_type,
                    ioc_value=ioc.value,
                    sigma_rules=[rule.title],
                    det_strategies=ioc.det_strategies,
                    time_range=tr,
                    description=f"Sigma rule: {rule.title} [{rule.severity}]",
                ))
            except Exception as exc:
                logger.debug("Skipping rule %s: %s", rule.title, exc)

        # --- MITRE Detection Strategy analytics ---
        if self._mitre:
            strategies = self._mitre.get_strategies_for_technique(tech_id)
            for strategy in strategies[:3]:  # cap to avoid query explosion
                for analytic in strategy.analytics[:3]:
                    if analytic.detection_logic:
                        q = self._analytic_to_query(analytic, ioc)
                        if q:
                            queries.append(HuntQuery(
                                query=q,
                                ioc_id=ioc.id,
                                ioc_type=ioc.ioc_type,
                                ioc_value=ioc.value,
                                det_strategies=[strategy.det_id],
                                time_range=tr,
                                description=f"{strategy.det_id}/{analytic.analytic_id}: {strategy.name}",
                            ))

        # Fallback: if no rules/analytics found, emit a generic field scan
        if not queries:
            queries.append(HuntQuery(
                query=f'dataset="{self._default_dataset}" | where mitre_technique="{tech_id}"',
                ioc_id=ioc.id,
                ioc_type=ioc.ioc_type,
                ioc_value=ioc.value,
                time_range=tr,
                description=f"Generic technique scan: {tech_id}",
            ))

        return queries

    def _analytic_to_query(self, analytic, ioc: IOC) -> Optional[str]:
        """
        Convert a MITRE analytic's detection_logic text into a best-effort Cribl query.
        The detection logic is usually English prose or pseudo-code; we extract key
        field patterns mentioned in the text.
        """
        logic = analytic.detection_logic
        if not logic:
            return None

        # Build field filters from data components
        filters: list[str] = []
        for dc in analytic.data_components:
            dc_lower = dc.lower()
            if "process" in dc_lower:
                filters.append('_raw LIKE "*proc*"')
            elif "network" in dc_lower:
                filters.append('_raw LIKE "*network*"')
            elif "registry" in dc_lower:
                filters.append('_raw LIKE "*registry*"')
            elif "file" in dc_lower:
                filters.append('_raw LIKE "*file*"')

        # Extract quoted strings from detection logic as search terms (heuristic)
        quoted = re.findall(r'"([^"]{4,64})"', logic)
        for term in quoted[:3]:
            filters.append(f'_raw LIKE "*{term}*"')

        if not filters:
            return None

        filter_str = " OR ".join(filters)
        dataset = self._default_dataset
        return f'dataset="{dataset}" | where ({filter_str})'

    # ------------------------------------------------------------------
    # CVE-based queries
    # ------------------------------------------------------------------

    def _build_cve_queries(self, ioc: IOC) -> list[HuntQuery]:
        """
        For a CVE IOC, search for:
          - The CVE ID string in raw log data
          - Any cmdline/file_path/registry patterns extracted in the IOC context
        """
        cve_id = ioc.value
        tr = self._default_time_range()
        dataset = self._default_dataset
        queries: list[HuntQuery] = []

        # Broad CVE ID search
        queries.append(HuntQuery(
            query=f'dataset="{dataset}" | where _raw LIKE "*{cve_id}*"',
            ioc_id=ioc.id,
            ioc_type=ioc.ioc_type,
            ioc_value=cve_id,
            time_range=tr,
            description=f"CVE ID string search: {cve_id}",
        ))

        # If the IOC context contains exploit artifacts, search for those too
        context = ioc.context
        # Look for file paths, command fragments, or registry keys in the context
        file_paths = re.findall(r'[A-Za-z]:\\(?:[^"<>|\s\\]+\\)*[^"<>|\s\\]+', context)
        for fp in file_paths[:3]:
            queries.append(HuntQuery(
                query=f'dataset="{dataset}" | where _raw LIKE "*{fp}*"',
                ioc_id=ioc.id,
                ioc_type=ioc.ioc_type,
                ioc_value=cve_id,
                time_range=tr,
                description=f"CVE file path artifact: {fp}",
            ))

        # Also search via matching Sigma rules from related MITRE techniques
        for tech_id in ioc.mitre_techniques:
            rules = self._sigma.get_by_technique(tech_id)[:3]
            for rule in rules:
                try:
                    cribl_query = sigma_rule_to_cribl_query(rule)
                    queries.append(HuntQuery(
                        query=cribl_query,
                        ioc_id=ioc.id,
                        ioc_type=ioc.ioc_type,
                        ioc_value=cve_id,
                        sigma_rules=[rule.title],
                        time_range=tr,
                        description=f"CVE-linked Sigma rule ({tech_id}): {rule.title}",
                    ))
                except Exception:
                    pass

        return queries

    # ------------------------------------------------------------------
    # Simple indicator queries (IP, domain, hash, etc.)
    # ------------------------------------------------------------------

    def _build_indicator_queries(self, ioc: IOC) -> list[HuntQuery]:
        """
        For atomic indicators (IP, domain, hash, URL, etc.),
        generate targeted field-search queries.
        """
        ioc_type = ioc.ioc_type
        value = ioc.value
        tr = self._default_time_range()
        dataset = self._default_dataset
        queries: list[HuntQuery] = []

        fields = _CRIBL_INDICATOR_FIELDS.get(ioc_type, [])
        if not fields:
            # Fallback: full-text search
            queries.append(HuntQuery(
                query=f'dataset="{dataset}" | where _raw LIKE "*{value}*"',
                ioc_id=ioc.id,
                ioc_type=ioc_type,
                ioc_value=value,
                time_range=tr,
                description=f"Full-text search: {ioc_type}={value}",
            ))
            return queries

        # Build an OR across known field names
        conditions = " OR ".join(f'{f}="{value}"' for f in fields)
        queries.append(HuntQuery(
            query=f'dataset="{dataset}" | where {conditions}',
            ioc_id=ioc.id,
            ioc_type=ioc_type,
            ioc_value=value,
            time_range=tr,
            description=f"Indicator search: {ioc_type}={value}",
        ))

        return queries

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _default_time_range(self) -> dict:
        return {
            "earliest": f"-{self._time_range_days}d",
            "latest": "now",
        }
