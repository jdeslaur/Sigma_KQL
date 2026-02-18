"""
Sigma/KQL → Cribl Search query mapper.

Reads the pre-converted KQL rules from kql_output/ and adapts them for
Cribl Search's SPL-compatible query syntax.

Key transformations:
  KQL table references  → Cribl dataset field filters
  KQL field names       → Cribl common schema field names
  | where X contains Y  → | where X="*Y*"  (SPL wildcard)
  | where X =~ "Y"      → | where X="Y"    (case-insensitive: SPL uses LIKE)
  endswith / startswith → SPL wildcard equivalents
"""

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# KQL table → Cribl dataset / log type hint mapping
# ---------------------------------------------------------------------------

_TABLE_TO_DATASET: dict[str, str] = {
    # Microsoft XDR / Defender 365
    "DeviceProcessEvents":      "process",
    "DeviceFileEvents":         "file",
    "DeviceRegistryEvents":     "registry",
    "DeviceNetworkEvents":      "network",
    "DeviceImageLoadEvents":    "image_load",
    "DeviceLogonEvents":        "logon",
    "DeviceAlertEvents":        "alert",
    # Sentinel ASIM
    "imProcessCreate":          "process",
    "imFileEvent":              "file",
    "imRegistry":               "registry",
    "imNetworkSession":         "network",
    "imAuthentication":         "logon",
    # Azure Monitor
    "SecurityEvent":            "windows_security",
    "Syslog":                   "syslog",
    "AzureActivity":            "azure_activity",
}

# ---------------------------------------------------------------------------
# KQL → Cribl field name translation
# ---------------------------------------------------------------------------

_FIELD_MAP: dict[str, str] = {
    # Process fields
    "ProcessCommandLine":           "cmdline",
    "InitiatingProcessCommandLine": "parent_cmdline",
    "FileName":                     "process_name",
    "FolderPath":                   "process_path",
    "ProcessVersionInfoOriginalFileName": "process_original_name",
    "InitiatingProcessFileName":    "parent_process_name",
    "InitiatingProcessFolderPath":  "parent_process_path",
    "SHA256":                       "hash_sha256",
    "SHA1":                         "hash_sha1",
    "MD5":                          "hash_md5",
    # File fields
    "FileName":                     "file_name",
    "FolderPath":                   "file_path",
    "ObjectName":                   "file_path",
    # Registry fields
    "RegistryKey":                  "registry_key",
    "RegistryValueName":            "registry_value_name",
    "RegistryValueData":            "registry_value_data",
    # Network fields
    "RemoteIP":                     "dst_ip",
    "RemotePort":                   "dst_port",
    "LocalIP":                      "src_ip",
    "RemoteUrl":                    "url",
    # Account fields
    "AccountName":                  "user",
    "AccountDomain":                "domain",
    # Common
    "DeviceName":                   "hostname",
    "MachineName":                  "hostname",
    "Computer":                     "hostname",
}

# ---------------------------------------------------------------------------
# KQL operator → SPL-style operator
# ---------------------------------------------------------------------------

def _kql_to_cribl_expression(expr: str) -> str:
    """
    Best-effort conversion of a KQL where-clause expression to Cribl SPL syntax.
    This is a heuristic approach — complex nested expressions may need manual tuning.
    """
    # Translate field names
    for kql_field, cribl_field in _FIELD_MAP.items():
        expr = re.sub(rf'\b{re.escape(kql_field)}\b', cribl_field, expr)

    # contains "X"  →  ="*X*"
    expr = re.sub(
        r'(\w+)\s+contains\s+"([^"]*)"',
        lambda m: f'{m.group(1)}="*{m.group(2)}*"',
        expr,
    )
    # startswith "X"  →  ="X*"
    expr = re.sub(
        r'(\w+)\s+startswith\s+"([^"]*)"',
        lambda m: f'{m.group(1)}="{m.group(2)}*"',
        expr,
    )
    # endswith "X"  →  ="*X"
    expr = re.sub(
        r'(\w+)\s+endswith\s+"([^"]*)"',
        lambda m: f'{m.group(1)}="*{m.group(2)}"',
        expr,
    )
    # =~ (case-insensitive) → = (Cribl is case-insensitive by default in many sources)
    expr = re.sub(r'=~', '=', expr)
    # has_any / has  →  IN / = (simplified)
    expr = re.sub(r'\bhas_any\b', 'IN', expr)
    expr = re.sub(r'\bhas\b', '=', expr)
    # in~ → in
    expr = re.sub(r'\bin~\b', 'IN', expr)
    # !contains → != "*X*"  (handle negations)
    expr = re.sub(
        r'(\w+)\s+!contains\s+"([^"]*)"',
        lambda m: f'{m.group(1)}!="*{m.group(2)}*"',
        expr,
    )

    return expr


def kql_to_cribl_query(kql_body: str, dataset_hint: Optional[str] = None) -> str:
    """
    Convert a KQL query body to a Cribl Search SPL-compatible query string.

    Args:
        kql_body:     Full KQL query text (may include table name as first line)
        dataset_hint: Optional Cribl dataset to prepend as a filter

    Returns:
        Cribl SPL query string
    """
    lines = kql_body.strip().splitlines()
    cribl_lines: list[str] = []
    dataset_filter: Optional[str] = dataset_hint

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        # First non-comment line might be a KQL table name
        if cribl_lines == [] and not stripped.startswith("|"):
            table_name = stripped.split()[0]
            if table_name in _TABLE_TO_DATASET:
                if not dataset_filter:
                    dataset_filter = _TABLE_TO_DATASET[table_name]
                continue  # drop the table reference line

        # Convert | where clauses
        if stripped.startswith("| where"):
            expr = stripped[len("| where"):].strip()
            expr = _kql_to_cribl_expression(expr)
            cribl_lines.append(f"| where {expr}")
        elif stripped.startswith("|"):
            # Other pipe operators (project, extend, etc.) — pass through with field mapping
            converted = _kql_to_cribl_expression(stripped)
            cribl_lines.append(converted)
        else:
            cribl_lines.append(stripped)

    # Prepend dataset filter
    prefix = ""
    if dataset_filter:
        prefix = f'dataset="{dataset_filter}" '

    return prefix + " ".join(cribl_lines) if cribl_lines else f'dataset="{dataset_filter or "archived_logs"}"'


# ---------------------------------------------------------------------------
# Rule index loader
# ---------------------------------------------------------------------------

@dataclass
class SigmaRule:
    rule_id: str
    title: str
    severity: str
    tags: list[str]
    category: str
    product: str
    pipeline: str
    source_path: str
    kql_body: str
    mitre_techniques: list[str]


def _extract_techniques_from_tags(tags: list[str]) -> list[str]:
    """Extract ATT&CK technique IDs from Sigma tags like 'attack.t1059.001'."""
    techniques = []
    for tag in tags:
        m = re.match(r'attack\.(t\d{4}(?:\.\d{3})?)', tag, re.IGNORECASE)
        if m:
            techniques.append(m.group(1).upper())
    return techniques


class SigmaRuleIndex:
    """
    Loads and indexes the pre-converted KQL rules from kql_output/.

    Usage:
        idx = SigmaRuleIndex("/path/to/kql_output")
        rules = idx.get_by_technique("T1059.001")
        rules = idx.get_by_severity("critical")
    """

    def __init__(self, kql_output_dir: str | Path) -> None:
        self._root = Path(kql_output_dir)
        self._rules: list[SigmaRule] = []
        self._by_technique: dict[str, list[SigmaRule]] = {}
        self._by_severity: dict[str, list[SigmaRule]] = {}
        self._load()

    def _load(self) -> None:
        total = 0
        for index_file in self._root.glob("*/index.json"):
            pipeline = index_file.parent.name
            try:
                with open(index_file, encoding="utf-8") as f:
                    index = json.load(f)
            except Exception as exc:
                logger.warning("Could not load %s: %s", index_file, exc)
                continue

            for entry in index:
                kql_path = index_file.parent / entry.get("file", "")
                if not kql_path.exists():
                    continue

                try:
                    kql_body = kql_path.read_text(encoding="utf-8")
                except Exception:
                    continue

                tags = list(entry.get("tags") or [])
                techniques = _extract_techniques_from_tags(tags)

                rule = SigmaRule(
                    rule_id=entry.get("id", ""),
                    title=entry.get("title", kql_path.stem),
                    severity=entry.get("severity", "informational").lower(),
                    tags=tags,
                    category=entry.get("category", ""),
                    product=entry.get("product", ""),
                    pipeline=pipeline,
                    source_path=str(kql_path),
                    kql_body=kql_body,
                    mitre_techniques=techniques,
                )
                self._rules.append(rule)

                for tech in techniques:
                    self._by_technique.setdefault(tech, []).append(rule)
                self._by_severity.setdefault(rule.severity, []).append(rule)
                total += 1

        logger.info("Loaded %d Sigma/KQL rules from %s", total, self._root)

    def get_by_technique(self, technique_id: str) -> list[SigmaRule]:
        """Return all rules matching a MITRE ATT&CK technique (e.g. 'T1059.001')."""
        return self._by_technique.get(technique_id.upper(), [])

    def get_by_severity(self, severity: str) -> list[SigmaRule]:
        return self._by_severity.get(severity.lower(), [])

    def get_all(self) -> list[SigmaRule]:
        return self._rules

    def count(self) -> int:
        return len(self._rules)

    def covered_techniques(self) -> list[str]:
        return sorted(self._by_technique.keys())


# ---------------------------------------------------------------------------
# Cribl query generation from Sigma rules
# ---------------------------------------------------------------------------

def sigma_rule_to_cribl_query(rule: SigmaRule) -> str:
    """
    Convert a SigmaRule's KQL body into a Cribl Search query.
    Strips comment header lines before conversion.
    """
    # Strip the comment header (lines starting with //)
    body_lines = [
        line for line in rule.kql_body.splitlines()
        if not line.strip().startswith("//")
    ]
    kql_body = "\n".join(body_lines).strip()
    return kql_to_cribl_query(kql_body)
