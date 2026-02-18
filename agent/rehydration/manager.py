"""
Rehydration Manager — triggers and monitors Cribl rehydration/replay jobs.

When an analyst approves a hit, this module submits a Cribl rehydration job
to move matching archived data from cold storage (S3/GCS/ADLS) to a hot tier
or directly into the SIEM forwarding pipeline.

Cribl rehydration API (approximate — adjust to your Cribl version):
  POST /api/v1/rehydration          → submit
  GET  /api/v1/rehydration/{id}     → poll status
"""

import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional

import requests

from ..triage.state import HitRecord, HitStatus, HitStore

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class RehydrationStatus(str, Enum):
    PENDING    = "pending"
    RUNNING    = "running"
    COMPLETED  = "completed"
    FAILED     = "failed"
    CANCELLED  = "cancelled"
    UNKNOWN    = "unknown"


@dataclass
class RehydrationJob:
    job_id: str
    hit_id: str
    source_dataset: str
    status: RehydrationStatus = RehydrationStatus.PENDING
    progress: float = 0.0
    event_count: int = 0
    error: str = ""


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class RehydrationManager:
    """
    Submit and monitor Cribl rehydration jobs.

    Usage:
        mgr = RehydrationManager.from_config(config, hit_store)
        job = mgr.submit_for_hit(hit)
        job = mgr.wait_for_completion(job.job_id)
    """

    _POLL_INTERVAL = 5    # seconds
    _TIMEOUT = 600        # 10 minutes

    def __init__(
        self,
        cribl_url: str,
        api_key: str,
        hit_store: HitStore,
        default_dataset: str = "archived_logs",
        on_complete: Optional[Callable[[RehydrationJob, HitRecord], None]] = None,
    ) -> None:
        self._base = cribl_url.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        self._hit_store = hit_store
        self._default_dataset = default_dataset
        self._on_complete = on_complete  # called when rehydration finishes successfully

    @classmethod
    def from_config(
        cls,
        config: dict,
        hit_store: HitStore,
        on_complete: Optional[Callable] = None,
    ) -> "RehydrationManager":
        cribl_cfg = config.get("cribl", {})
        return cls(
            cribl_url=cribl_cfg["search_url"],
            api_key=cribl_cfg["api_key"],
            hit_store=hit_store,
            default_dataset=cribl_cfg.get("default_dataset", "archived_logs"),
            on_complete=on_complete,
        )

    # ------------------------------------------------------------------

    def submit_for_hit(
        self,
        hit: HitRecord,
        target_dataset: Optional[str] = None,
        time_range: Optional[dict] = None,
    ) -> RehydrationJob:
        """
        Submit a rehydration job for an approved hit.

        Args:
            hit:            The approved HitRecord
            target_dataset: Where to put the rehydrated data (defaults to config)
            time_range:     {'earliest': ..., 'latest': ...} — defaults to hit's search range

        Returns:
            RehydrationJob with job_id populated.
        """
        payload: dict[str, Any] = {
            "query": hit.query,
            "sourceDataset": self._default_dataset,
            "description": f"Rehydration for hit {hit.hit_id[:8]}: {hit.description}",
        }
        if target_dataset:
            payload["targetDataset"] = target_dataset
        if time_range:
            payload["timeRange"] = time_range

        try:
            resp = self._session.post(
                f"{self._base}/api/v1/rehydration",
                json=payload,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.HTTPError as exc:
            logger.error("Rehydration submit failed (%s): %s", exc.response.status_code, exc.response.text[:500])
            raise
        except Exception as exc:
            logger.error("Rehydration submit failed: %s", exc)
            raise

        reh_job_id = data.get("id") or data.get("jobId") or data.get("job_id", "")
        job = RehydrationJob(
            job_id=reh_job_id,
            hit_id=hit.hit_id,
            source_dataset=self._default_dataset,
        )

        # Update hit store
        self._hit_store.update_status(
            hit.hit_id,
            HitStatus.REHYDRATED,
            note=hit.analyst_note,
            rehydration_job_id=reh_job_id,
        )

        logger.info("Rehydration job %s submitted for hit %s", reh_job_id, hit.hit_id[:12])
        return job

    def get_job_status(self, job_id: str, hit_id: str = "") -> RehydrationJob:
        try:
            resp = self._session.get(
                f"{self._base}/api/v1/rehydration/{job_id}",
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.error("Rehydration status poll failed for %s: %s", job_id, exc)
            return RehydrationJob(
                job_id=job_id, hit_id=hit_id,
                source_dataset="", status=RehydrationStatus.UNKNOWN, error=str(exc),
            )

        status_str = (data.get("status") or "unknown").lower()
        try:
            status = RehydrationStatus(status_str)
        except ValueError:
            status = RehydrationStatus.UNKNOWN

        return RehydrationJob(
            job_id=job_id,
            hit_id=hit_id,
            source_dataset=data.get("sourceDataset", ""),
            status=status,
            progress=float(data.get("progress", 0)),
            event_count=int(data.get("eventCount", 0)),
            error=data.get("error", ""),
        )

    def wait_for_completion(
        self,
        job_id: str,
        hit_id: str = "",
        poll_interval: float = _POLL_INTERVAL,
        timeout: float = _TIMEOUT,
    ) -> RehydrationJob:
        """Block until the rehydration job finishes, then fire on_complete callback."""
        deadline = time.monotonic() + timeout

        while True:
            job = self.get_job_status(job_id, hit_id)
            if job.status in (
                RehydrationStatus.COMPLETED,
                RehydrationStatus.FAILED,
                RehydrationStatus.CANCELLED,
            ):
                logger.info(
                    "Rehydration job %s finished: status=%s events=%d",
                    job_id, job.status.value, job.event_count,
                )
                if job.status == RehydrationStatus.COMPLETED and self._on_complete:
                    hit = self._hit_store.get(hit_id)
                    if hit:
                        self._on_complete(job, hit)
                return job

            if time.monotonic() > deadline:
                logger.warning("Timeout waiting for rehydration job %s", job_id)
                job.status = RehydrationStatus.CANCELLED
                return job

            time.sleep(poll_interval)

    def process_approved_hits(self, timeout_per_job: float = _TIMEOUT) -> list[RehydrationJob]:
        """
        Submit rehydration jobs for all hits currently in APPROVED state.
        Returns the list of submitted jobs.
        """
        approved = self._hit_store.get_approved()
        if not approved:
            logger.info("No approved hits pending rehydration")
            return []

        jobs: list[RehydrationJob] = []
        for hit in approved:
            try:
                job = self.submit_for_hit(hit)
                jobs.append(job)
            except Exception as exc:
                logger.error("Failed to submit rehydration for hit %s: %s", hit.hit_id[:12], exc)

        logger.info("Submitted %d rehydration job(s)", len(jobs))
        return jobs
