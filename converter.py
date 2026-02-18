#!/usr/bin/env python3
"""
Sigma to KQL Converter
Converts SigmaHQ detection rules into KQL (Kusto Query Language) queries
for use with Azure Monitor, Microsoft Sentinel, and Microsoft 365 Defender.
"""

import os
import sys
import json
import yaml
import argparse
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

from sigma.collection import SigmaCollection
from sigma.backends.kusto import KustoBackend
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.plugins import InstalledSigmaPlugins

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


PIPELINES = {
    "azure_monitor": "Azure Monitor",
    "microsoft_sentinel": "Microsoft Sentinel (ASIM)",
    "microsoft_xdr": "Microsoft XDR / Defender 365",
}

PIPELINE_MAP = {
    "azure_monitor": "azure_monitor",
    "microsoft_sentinel": "sentinel_asim",
    "microsoft_xdr": "microsoft_xdr",
}

# Categories supported by each KQL pipeline (based on pySigma-backend-kusto mappings)
SUPPORTED_CATEGORIES = {
    "microsoft_xdr": {
        "process_creation",
        "image_load",
        "file_event",
        "registry_add",
        "registry_delete",
        "registry_event",
        "registry_set",
        "network_connection",
    },
    "microsoft_sentinel": {
        "process_creation",
        "file_event",
        "registry_add",
        "registry_delete",
        "registry_event",
        "registry_set",
        "network_connection",
    },
    "azure_monitor": {
        "process_creation",
        "file_event",
        "registry_add",
        "registry_delete",
        "registry_event",
        "registry_set",
        "network_connection",
    },
}

RULE_DIRS = [
    "rules",
    "rules-threat-hunting",
    "rules-emerging-threats",
    "rules-compliance",
]


@dataclass
class ConversionResult:
    rule_path: str
    rule_id: str
    rule_title: str
    rule_level: str
    rule_tags: list
    rule_category: str
    rule_product: str
    pipeline: str
    kql_query: str
    success: bool
    error: Optional[str] = None


@dataclass
class ConversionSummary:
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    skipped: int = 0
    errors: list = field(default_factory=list)


def load_sigma_rule_meta(rule_path: Path) -> dict:
    """Load and parse a sigma rule YAML file for metadata."""
    try:
        with open(rule_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if not isinstance(data, dict):
                return {}
            return data
    except Exception:
        return {}


def get_pipeline(pipeline_id: str):
    """Get processing pipeline by identifier."""
    plugins = InstalledSigmaPlugins.autodiscover()
    resolver = plugins.get_pipeline_resolver()
    return resolver.resolve_pipeline(pipeline_id)


def get_rule_logsource(rule_data: dict) -> tuple[str, str]:
    """Extract category and product from a sigma rule's logsource."""
    logsource = rule_data.get("logsource", {}) if rule_data else {}
    category = logsource.get("category", "")
    product = logsource.get("product", "")
    return category, product


def convert_rule(
    rule_path: Path,
    pipeline_name: str,
    pipeline_id: str,
    backend: KustoBackend,
) -> ConversionResult:
    """Convert a single sigma rule to KQL."""
    rule_data = load_sigma_rule_meta(rule_path)
    rule_id = rule_data.get("id", "unknown")
    rule_title = rule_data.get("title", str(rule_path.name))
    rule_level = rule_data.get("level", "unknown")
    rule_tags = rule_data.get("tags", [])
    rule_category, rule_product = get_rule_logsource(rule_data)

    try:
        collection = SigmaCollection.load_ruleset([rule_path])
        pipeline = get_pipeline(pipeline_id)
        backend_with_pipeline = KustoBackend(processing_pipeline=pipeline)
        queries = backend_with_pipeline.convert(collection)

        if queries:
            kql = "\n\n".join(q for q in queries if q and q.strip())
            if kql.strip():
                return ConversionResult(
                    rule_path=str(rule_path),
                    rule_id=rule_id,
                    rule_title=rule_title,
                    rule_level=rule_level,
                    rule_tags=rule_tags,
                    rule_category=rule_category,
                    rule_product=rule_product,
                    pipeline=pipeline_name,
                    kql_query=kql,
                    success=True,
                )

        return ConversionResult(
            rule_path=str(rule_path),
            rule_id=rule_id,
            rule_title=rule_title,
            rule_level=rule_level,
            rule_tags=rule_tags,
            rule_category=rule_category,
            rule_product=rule_product,
            pipeline=pipeline_name,
            kql_query="",
            success=False,
            error="No query generated",
        )

    except Exception as e:
        return ConversionResult(
            rule_path=str(rule_path),
            rule_id=rule_id,
            rule_title=rule_title,
            rule_level=rule_level,
            rule_tags=rule_tags,
            rule_category=rule_category,
            rule_product=rule_product,
            pipeline=pipeline_name,
            kql_query="",
            success=False,
            error=str(e)[:300],
        )


def write_kql_file(result: ConversionResult, output_dir: Path) -> Path:
    """Write a KQL query to a file preserving the source directory structure."""
    for rules_dir in RULE_DIRS:
        if f"/{rules_dir}/" in result.rule_path:
            relative = result.rule_path.split(f"/{rules_dir}/", 1)[1].replace(".yml", ".kql")
            break
    else:
        relative = Path(result.rule_path).name.replace(".yml", ".kql")

    out_path = output_dir / relative
    out_path.parent.mkdir(parents=True, exist_ok=True)

    header = f"""// Title: {result.rule_title}
// Rule ID: {result.rule_id}
// Severity: {result.rule_level}
// Tags: {", ".join(result.rule_tags) if result.rule_tags else "N/A"}
// Category: {result.rule_category}
// Product: {result.rule_product}
// Pipeline: {result.pipeline}
// Source: {result.rule_path}
//
// Generated by sigma-to-kql converter
// Sigma rules: https://github.com/SigmaHQ/sigma
// pySigma Kusto backend: https://github.com/AttackIQ/pySigma-backend-kusto

"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(header + result.kql_query)

    return out_path


def collect_rule_files(sigma_root: Path) -> list[Path]:
    """Recursively collect all sigma rule YAML files."""
    rule_files = []
    for rules_dir in RULE_DIRS:
        dir_path = sigma_root / rules_dir
        if dir_path.exists():
            rule_files.extend(sorted(dir_path.rglob("*.yml")))
    return rule_files


def filter_supported_rules(
    rule_files: list[Path], pipeline_name: str
) -> tuple[list[Path], int]:
    """
    Filter rule files to only those with supported logsource categories.
    Returns (supported_files, skipped_count).
    """
    supported_cats = SUPPORTED_CATEGORIES.get(pipeline_name, set())
    supported = []
    skipped = 0

    for rule_path in rule_files:
        rule_data = load_sigma_rule_meta(rule_path)
        category, _ = get_rule_logsource(rule_data)
        if category in supported_cats:
            supported.append(rule_path)
        else:
            skipped += 1

    return supported, skipped


def convert_all(
    sigma_root: Path,
    output_root: Path,
    pipelines: Optional[list] = None,
    limit: Optional[int] = None,
    skip_filter: bool = False,
) -> dict:
    """Convert all sigma rules to KQL for all specified pipelines."""
    if pipelines is None:
        pipelines = list(PIPELINES.keys())

    all_rule_files = collect_rule_files(sigma_root)
    total_rules = len(all_rule_files)
    logger.info(f"Found {total_rules} sigma rule files across {len(RULE_DIRS)} rule directories")

    summaries = {p: ConversionSummary() for p in pipelines}
    all_results = {p: [] for p in pipelines}

    for pipeline_name in pipelines:
        pipeline_id = PIPELINE_MAP[pipeline_name]
        summary = summaries[pipeline_name]

        if skip_filter:
            rule_files = all_rule_files
            skipped = 0
        else:
            rule_files, skipped = filter_supported_rules(all_rule_files, pipeline_name)

        if limit:
            rule_files = rule_files[:limit]

        summary.total = len(rule_files) + skipped
        summary.skipped = skipped

        logger.info(
            f"[{PIPELINES[pipeline_name]}] {len(rule_files)} supported rules "
            f"({skipped} skipped - unsupported category)"
        )

        for i, rule_path in enumerate(rule_files, 1):
            if i % 200 == 0 or i == 1:
                logger.info(
                    f"  [{PIPELINES[pipeline_name]}] Processing {i}/{len(rule_files)}..."
                )

            result = convert_rule(rule_path, pipeline_name, pipeline_id, KustoBackend())

            if result.success and result.kql_query:
                summary.succeeded += 1
                out_dir = output_root / pipeline_name
                write_kql_file(result, out_dir)
                all_results[pipeline_name].append(result)
            else:
                summary.failed += 1
                if result.error:
                    summary.errors.append({
                        "rule": result.rule_title,
                        "category": result.rule_category,
                        "error": result.error,
                    })

    return {"summaries": summaries, "results": all_results}


def write_index(output_root: Path, results: dict, summaries: dict):
    """Write a JSON index of all converted rules per pipeline."""
    for pipeline_name, result_list in results.items():
        index = []
        for r in result_list:
            for rules_dir in RULE_DIRS:
                if f"/{rules_dir}/" in r.rule_path:
                    relative = r.rule_path.split(f"/{rules_dir}/", 1)[1].replace(".yml", ".kql")
                    break
            else:
                relative = Path(r.rule_path).name.replace(".yml", ".kql")

            index.append({
                "id": r.rule_id,
                "title": r.rule_title,
                "level": r.rule_level,
                "category": r.rule_category,
                "product": r.rule_product,
                "tags": r.rule_tags,
                "kql_file": relative,
            })

        # Sort by severity then title
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "unknown": 5}
        index.sort(key=lambda x: (severity_order.get(x["level"], 5), x["title"]))

        index_path = output_root / pipeline_name / "index.json"
        with open(index_path, "w", encoding="utf-8") as f:
            json.dump(index, f, indent=2)

        logger.info(f"Wrote index: {index_path} ({len(index)} rules)")


def print_summary(summaries: dict):
    """Print conversion summary table."""
    print("\n" + "=" * 76)
    print("  SIGMA TO KQL CONVERSION SUMMARY")
    print("=" * 76)
    print(f"  {'Pipeline':<32} {'Total':>6} {'Success':>10} {'Failed':>8} {'Skipped':>9}")
    print("-" * 76)
    for pipeline_name, summary in summaries.items():
        label = PIPELINES[pipeline_name]
        pct = (summary.succeeded / (summary.total - summary.skipped) * 100) if (summary.total - summary.skipped) > 0 else 0
        print(
            f"  {label:<32} {summary.total:>6} "
            f"{summary.succeeded:>7} ({pct:.0f}%) "
            f"{summary.failed:>6} "
            f"{summary.skipped:>9}"
        )
    print("=" * 76 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Convert Sigma rules to KQL queries for Microsoft security platforms",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Convert all supported rules for all pipelines
  python3 converter.py

  # Convert only for Microsoft XDR
  python3 converter.py --pipelines microsoft_xdr

  # Use custom sigma rules directory
  python3 converter.py --sigma-root /path/to/sigma

  # Test run with first 50 supported rules
  python3 converter.py --limit 50

Available pipelines:
  azure_monitor         - Azure Monitor / Log Analytics (SecurityEvent table)
  microsoft_sentinel    - Microsoft Sentinel ASIM (imProcessCreate, imRegistry, etc.)
  microsoft_xdr         - Microsoft XDR / Defender 365 (DeviceProcessEvents, etc.)

Supported logsource categories:
  process_creation, image_load (XDR only), file_event,
  registry_add, registry_delete, registry_event, registry_set, network_connection
""",
    )
    parser.add_argument(
        "--sigma-root",
        type=Path,
        default=Path(__file__).parent / "sigma_rules",
        help="Root directory of sigma rules repo (default: ./sigma_rules)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).parent / "kql_output",
        help="Output directory for KQL files (default: ./kql_output)",
    )
    parser.add_argument(
        "--pipelines",
        nargs="+",
        choices=list(PIPELINES.keys()),
        default=list(PIPELINES.keys()),
        help="Pipelines to convert for (default: all)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of supported rules to convert per pipeline (for testing)",
    )
    parser.add_argument(
        "--no-filter",
        action="store_true",
        help="Attempt conversion of all rules regardless of category support",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.sigma_root.exists():
        logger.error(f"Sigma rules directory not found: {args.sigma_root}")
        logger.info("Run: git clone --depth=1 https://github.com/SigmaHQ/sigma.git sigma_rules")
        sys.exit(1)

    args.output_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Sigma root: {args.sigma_root}")
    logger.info(f"Output dir: {args.output_dir}")
    logger.info(f"Pipelines:  {', '.join(args.pipelines)}")

    data = convert_all(
        sigma_root=args.sigma_root,
        output_root=args.output_dir,
        pipelines=args.pipelines,
        limit=args.limit,
        skip_filter=args.no_filter,
    )

    write_index(args.output_dir, data["results"], data["summaries"])
    print_summary(data["summaries"])

    logger.info("Conversion complete.")


if __name__ == "__main__":
    main()
