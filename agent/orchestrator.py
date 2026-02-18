"""
Threat Hunting Agent — main orchestrator.

Ties together all components into a single agent loop:
  1. Collect IOCs from all sources
  2. Build Cribl Search queries from new IOCs
  3. Submit and await search jobs
  4. Record hits in the HitStore
  5. (Human triage happens separately via `python -m agent.triage_ui`)
  6. Submit rehydration jobs for approved hits
  7. Forward rehydrated events to the SIEM

Usage:
    # One-shot hunt cycle (for cron / testing)
    python -m agent.orchestrator --once

    # Continuous loop
    python -m agent.orchestrator

    # Interactive triage only
    python -m agent.orchestrator --triage

    # Add analyst-supplied URL for LLM extraction
    python -m agent.orchestrator --add-url https://example.com/threat-report
"""

import argparse
import logging
import os
import sys
import time
import uuid
from pathlib import Path

import yaml

from .ioc.collector import IOCCollector
from .ioc.normalizer import IOCStore
from .output.forwarder import build_forwarder, enrich_event
from .rehydration.manager import RehydrationManager
from .search.cribl_client import CriblSearchClient, JobStatus
from .search.query_builder import HuntQuery, QueryBuilder
from .search.sigma_mapper import SigmaRuleIndex
from .triage.cli import TriageCLI, print_summary
from .triage.state import HitRecord, HitStatus, HitStore

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def load_config(path: str | Path) -> dict:
    """Load YAML config, expanding ${ENV_VAR} references."""
    with open(path, encoding="utf-8") as f:
        raw = f.read()

    # Expand ${VAR} references
    import re
    def _expand(match):
        var = match.group(1)
        return os.environ.get(var, match.group(0))
    raw = re.sub(r'\$\{([^}]+)\}', _expand, raw)

    return yaml.safe_load(raw)


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class ThreatHuntAgent:
    """
    Top-level agent that orchestrates the full hunt lifecycle.
    """

    def __init__(self, config: dict) -> None:
        self._config = config

        # State stores
        db_path = config.get("state", {}).get("db_path", "agent_state.db")
        self._ioc_store = IOCStore(db_path)
        self._hit_store = HitStore(db_path)

        # IOC collection
        self._collector = IOCCollector(config, self._ioc_store)

        # Cribl Search
        self._cribl = CriblSearchClient.from_config(config)

        # Sigma rule index
        kql_dir = Path(__file__).resolve().parent.parent / "kql_output"
        self._sigma_index = SigmaRuleIndex(kql_dir)

        # MITRE Detection Strategies (optional; may fail gracefully)
        self._mitre = None
        try:
            from .ioc.mitre_det_strategies import MitreDetectionStrategies
            self._mitre = MitreDetectionStrategies(config)
        except Exception as exc:
            logger.warning("MITRE Detection Strategies unavailable: %s", exc)

        # Query builder
        self._query_builder = QueryBuilder(config, self._sigma_index, self._mitre)

        # SIEM forwarder
        self._forwarder = build_forwarder(config)

        # Rehydration manager (fires SIEM forward on completion)
        self._rehydration = RehydrationManager.from_config(
            config,
            self._hit_store,
            on_complete=self._on_rehydration_complete,
        )

        # Triage CLI
        self._triage = TriageCLI(
            self._hit_store,
            on_approve=self._on_hit_approved,
        )

    # ------------------------------------------------------------------
    # Primary cycle
    # ------------------------------------------------------------------

    def collect_and_hunt(self) -> int:
        """
        Run one full collect → build queries → search cycle.
        Returns the number of new hits recorded.
        """
        logger.info("=== Collect & Hunt cycle starting ===")

        # 1. Collect new IOCs
        new_iocs = self._collector.collect()
        if not new_iocs:
            logger.info("No new IOCs — skipping hunt")
            return 0

        logger.info("%d new IOCs collected", len(new_iocs))

        # 2. Build queries
        queries = self._query_builder.build_queries(new_iocs)
        logger.info("%d Cribl queries generated", len(queries))

        # 3. Submit and process each query
        new_hits = 0
        max_jobs = int(self._config.get("schedule", {}).get("max_concurrent_search_jobs", 5))

        for query in queries[:max_jobs * 10]:  # safety cap
            try:
                hits = self._run_single_query(query)
                new_hits += hits
            except Exception as exc:
                logger.error("Query failed (%s): %s", query.description, exc)

        logger.info("=== Cycle complete: %d new hits ===", new_hits)
        return new_hits

    def _run_single_query(self, query: HuntQuery) -> int:
        """Submit a single query, collect results, store hits. Returns hit count."""
        job = self._cribl.submit_search(
            query=query.query,
            time_range=query.time_range,
        )

        job = self._cribl.wait_for_completion(
            job.job_id,
            timeout=float(self._config.get("cribl", {}).get("search_timeout", 300)),
        )

        if job.status != JobStatus.COMPLETED:
            logger.warning("Job %s ended with status %s", job.job_id, job.status)
            return 0

        if job.event_count == 0:
            logger.debug("Job %s: no events matched", job.job_id)
            return 0

        # Fetch up to 5 sample events
        result = self._cribl.get_results(job.job_id, limit=5)
        sample_events = result.events

        hit = HitRecord(
            hit_id=str(uuid.uuid4()),
            ioc_id=query.ioc_id,
            ioc_type=query.ioc_type,
            ioc_value=query.ioc_value,
            cribl_job_id=job.job_id,
            query=query.query,
            event_count=job.event_count,
            sample_events=sample_events,
            matched_rules=query.sigma_rules,
            det_strategies=query.det_strategies,
            description=query.description,
        )
        self._hit_store.add(hit)
        logger.info(
            "Hit recorded: %s (%d events) — %s",
            hit.hit_id[:12], hit.event_count, hit.description,
        )
        return 1

    # ------------------------------------------------------------------
    # Triage & rehydration
    # ------------------------------------------------------------------

    def run_triage(self) -> None:
        """Launch the interactive triage CLI."""
        self._triage.run()

    def process_rehydration(self) -> None:
        """Submit rehydration jobs for all currently approved hits."""
        jobs = self._rehydration.process_approved_hits()
        logger.info("Submitted %d rehydration job(s)", len(jobs))

        # Optionally wait for completion
        for job in jobs:
            self._rehydration.wait_for_completion(job.job_id, hit_id=job.hit_id)

    def _on_hit_approved(self, hit_id: str) -> None:
        """Called by triage CLI when analyst approves a hit."""
        logger.info("Hit %s approved — queuing for rehydration", hit_id[:12])
        hit = self._hit_store.get(hit_id)
        if hit:
            try:
                reh_job = self._rehydration.submit_for_hit(hit)
                logger.info("Rehydration job %s submitted", reh_job.job_id)
            except Exception as exc:
                logger.error("Rehydration submit failed for hit %s: %s", hit_id[:12], exc)

    def _on_rehydration_complete(self, reh_job, hit: HitRecord) -> None:
        """Called by RehydrationManager when rehydration finishes — forward to SIEM."""
        logger.info("Rehydration %s complete — forwarding to SIEM (%s)", reh_job.job_id, self._forwarder.name)

        # For the actual forwarded events we use the sample events; in production
        # the rehydration job delivers events to a Cribl destination, so here we
        # forward the metadata record + samples as a SIEM alert entry.
        events_to_forward = [
            enrich_event(
                raw_event=ev,
                hit_id=hit.hit_id,
                ioc_value=hit.ioc_value,
                ioc_type=hit.ioc_type,
                description=hit.description,
                matched_rules=hit.matched_rules,
                det_strategies=hit.det_strategies,
                analyst_note=hit.analyst_note,
            )
            for ev in (hit.sample_events or [{"note": "no sample — see Cribl rehydration job"}])
        ]

        sent = self._forwarder.send(events_to_forward)
        if sent > 0:
            self._hit_store.update_status(hit.hit_id, HitStatus.FORWARDED, note=hit.analyst_note)
            logger.info("Hit %s forwarded to SIEM (%d events)", hit.hit_id[:12], sent)

    # ------------------------------------------------------------------
    # Continuous loop
    # ------------------------------------------------------------------

    def run_forever(self, interval_minutes: int = 60) -> None:
        """Run collect/hunt/rehydration on a schedule until interrupted."""
        logger.info("Starting continuous threat hunt loop (interval=%dm)", interval_minutes)
        while True:
            try:
                self.collect_and_hunt()
                self.process_rehydration()
            except KeyboardInterrupt:
                logger.info("Agent interrupted by user")
                break
            except Exception as exc:
                logger.error("Unhandled error in agent loop: %s", exc, exc_info=True)

            logger.info("Sleeping %d minutes until next cycle…", interval_minutes)
            try:
                time.sleep(interval_minutes * 60)
            except KeyboardInterrupt:
                logger.info("Agent interrupted during sleep")
                break

    # ------------------------------------------------------------------
    # Manual IOC injection
    # ------------------------------------------------------------------

    def add_url(self, url: str) -> list:
        """LLM-extract IOCs from a URL and add them to the store."""
        from .ioc.llm_extractor import LLMExtractor
        extractor = LLMExtractor(self._config)
        iocs = extractor.extract_from_url(url)
        new, updated = self._ioc_store.add_many(iocs)
        logger.info("URL %s: %d new, %d updated IOCs", url, new, updated)
        return iocs


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Cribl Threat Hunting Agent")
    parser.add_argument("--config", default="agent/config.yaml", help="Path to config.yaml")
    parser.add_argument("--once", action="store_true", help="Run one collect/hunt cycle and exit")
    parser.add_argument("--triage", action="store_true", help="Launch interactive triage CLI")
    parser.add_argument("--summary", action="store_true", help="Print hit summary and exit")
    parser.add_argument("--rehydrate", action="store_true", help="Process approved hits for rehydration")
    parser.add_argument("--add-url", metavar="URL", help="Extract IOCs from a URL via LLM")
    parser.add_argument("--log-level", default="INFO", help="Logging level (DEBUG/INFO/WARNING/ERROR)")
    args = parser.parse_args()

    _setup_logging(args.log_level)

    config_path = Path(args.config)
    if not config_path.exists():
        logger.error("Config file not found: %s", config_path)
        sys.exit(1)

    config = load_config(config_path)
    _setup_logging(config.get("logging", {}).get("level", args.log_level))

    agent = ThreatHuntAgent(config)

    if args.summary:
        print_summary(agent._hit_store)

    elif args.triage:
        agent.run_triage()

    elif args.rehydrate:
        agent.process_rehydration()

    elif args.add_url:
        iocs = agent.add_url(args.add_url)
        print(f"Extracted {len(iocs)} IOCs from {args.add_url}")

    elif args.once:
        hits = agent.collect_and_hunt()
        print(f"Hunt cycle complete: {hits} new hits")
        if hits > 0:
            agent.run_triage()

    else:
        interval = int(config.get("schedule", {}).get("ioc_refresh_minutes", 60))
        agent.run_forever(interval_minutes=interval)


if __name__ == "__main__":
    main()
