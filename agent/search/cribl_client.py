"""
Cribl Search REST API client.

Wraps the Cribl Search job lifecycle:
  POST  /api/v1/search/jobs            → submit a search job
  GET   /api/v1/search/jobs/{id}       → poll status
  GET   /api/v1/search/jobs/{id}/results → fetch results
  DELETE /api/v1/search/jobs/{id}      → cancel a job

Authentication: Bearer token (CRIBL_API_KEY).
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

import requests

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


@dataclass
class SearchJob:
    job_id: str
    query: str
    status: JobStatus = JobStatus.QUEUED
    progress: float = 0.0       # 0–100
    event_count: int = 0
    error: str = ""
    dataset: str = ""
    time_range: dict = field(default_factory=dict)


@dataclass
class SearchResult:
    job_id: str
    events: list[dict]
    total: int
    truncated: bool = False


# ---------------------------------------------------------------------------
# Cribl Search client
# ---------------------------------------------------------------------------

class CriblSearchClient:
    """
    REST API wrapper for Cribl Search.

    Usage:
        client = CriblSearchClient.from_config(config)
        job    = client.submit_search(query="...", time_range={...})
        job    = client.wait_for_completion(job.job_id)
        result = client.get_results(job.job_id)
    """

    _DEFAULT_POLL_INTERVAL = 3   # seconds
    _DEFAULT_TIMEOUT = 300       # seconds to wait for a job

    def __init__(self, search_url: str, api_key: str) -> None:
        self._base = search_url.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    @classmethod
    def from_config(cls, config: dict) -> "CriblSearchClient":
        cribl_cfg = config.get("cribl", {})
        return cls(
            search_url=cribl_cfg["search_url"],
            api_key=cribl_cfg["api_key"],
        )

    # ------------------------------------------------------------------
    # Job lifecycle
    # ------------------------------------------------------------------

    def submit_search(
        self,
        query: str,
        dataset: Optional[str] = None,
        time_range: Optional[dict] = None,
        earliest: Optional[str] = None,
        latest: Optional[str] = None,
    ) -> SearchJob:
        """
        Submit a search job to Cribl Search.

        Args:
            query:      Cribl SPL query string
            dataset:    Target dataset / data set name
            time_range: Dict with 'earliest' and 'latest' (ISO8601 or relative like '-90d')
            earliest:   Shortcut for time_range['earliest']
            latest:     Shortcut for time_range['latest']

        Returns:
            SearchJob with job_id populated.
        """
        # Build time range
        tr: dict[str, str] = {}
        if time_range:
            tr = time_range
        else:
            if earliest:
                tr["earliest"] = earliest
            if latest:
                tr["latest"] = latest

        payload: dict[str, Any] = {"query": query}
        if dataset:
            payload["dataset"] = dataset
        if tr:
            payload["timeRange"] = tr

        try:
            resp = self._session.post(
                f"{self._base}/api/v1/search/jobs",
                json=payload,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.HTTPError as exc:
            logger.error("Cribl Search submit failed (%s): %s", exc.response.status_code, exc.response.text[:500])
            raise
        except Exception as exc:
            logger.error("Cribl Search submit failed: %s", exc)
            raise

        job_id = data.get("id") or data.get("jobId") or data.get("job_id", "")
        job = SearchJob(
            job_id=job_id,
            query=query,
            status=JobStatus(data.get("status", "queued").lower()),
            dataset=dataset or "",
            time_range=tr,
        )
        logger.info("Submitted Cribl Search job %s: %s", job_id, query[:80])
        return job

    def get_job_status(self, job_id: str) -> SearchJob:
        """Poll the status of a submitted search job."""
        try:
            resp = self._session.get(
                f"{self._base}/api/v1/search/jobs/{job_id}",
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.error("Cribl Search status poll failed for %s: %s", job_id, exc)
            return SearchJob(job_id=job_id, query="", status=JobStatus.UNKNOWN, error=str(exc))

        status_str = (data.get("status") or "unknown").lower()
        try:
            status = JobStatus(status_str)
        except ValueError:
            status = JobStatus.UNKNOWN

        return SearchJob(
            job_id=job_id,
            query=data.get("query", ""),
            status=status,
            progress=float(data.get("progress", 0)),
            event_count=int(data.get("eventCount", data.get("event_count", 0))),
            error=data.get("error", data.get("errorMessage", "")),
        )

    def wait_for_completion(
        self,
        job_id: str,
        poll_interval: float = _DEFAULT_POLL_INTERVAL,
        timeout: float = _DEFAULT_TIMEOUT,
        on_progress: Optional[Callable[[SearchJob], None]] = None,
    ) -> SearchJob:
        """
        Block until the job reaches a terminal state (completed/failed/cancelled).

        Args:
            on_progress: optional callback called each poll cycle with the current SearchJob
        """
        deadline = time.monotonic() + timeout
        while True:
            job = self.get_job_status(job_id)
            if on_progress:
                on_progress(job)

            if job.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
                logger.info(
                    "Job %s finished with status=%s events=%d",
                    job_id, job.status.value, job.event_count,
                )
                return job

            if time.monotonic() > deadline:
                logger.warning("Timeout waiting for job %s; cancelling", job_id)
                self.cancel_job(job_id)
                job.status = JobStatus.CANCELLED
                return job

            time.sleep(poll_interval)

    def get_results(
        self,
        job_id: str,
        limit: int = 1000,
        offset: int = 0,
    ) -> SearchResult:
        """
        Retrieve results from a completed search job.

        Returns a SearchResult with the list of event dicts.
        """
        params: dict[str, Any] = {"count": limit, "offset": offset}
        try:
            resp = self._session.get(
                f"{self._base}/api/v1/search/jobs/{job_id}/results",
                params=params,
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.error("Cribl Search results fetch failed for %s: %s", job_id, exc)
            return SearchResult(job_id=job_id, events=[], total=0)

        events = data.get("events", data.get("results", []))
        total = data.get("total", len(events))
        truncated = total > (offset + limit)

        return SearchResult(
            job_id=job_id,
            events=events,
            total=total,
            truncated=truncated,
        )

    def get_all_results(self, job_id: str, page_size: int = 1000) -> list[dict]:
        """Fetch all result pages from a completed job."""
        all_events: list[dict] = []
        offset = 0
        while True:
            result = self.get_results(job_id, limit=page_size, offset=offset)
            all_events.extend(result.events)
            if not result.truncated:
                break
            offset += page_size
        return all_events

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a running search job. Returns True on success."""
        try:
            resp = self._session.delete(
                f"{self._base}/api/v1/search/jobs/{job_id}",
                timeout=15,
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.warning("Could not cancel job %s: %s", job_id, exc)
            return False

    # ------------------------------------------------------------------
    # Convenience method: submit + wait + return results
    # ------------------------------------------------------------------

    def run_search(
        self,
        query: str,
        dataset: Optional[str] = None,
        time_range: Optional[dict] = None,
        earliest: Optional[str] = None,
        latest: Optional[str] = None,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> SearchResult:
        """
        One-shot: submit a query, wait for completion, return results.
        Raises on job failure.
        """
        job = self.submit_search(
            query=query, dataset=dataset, time_range=time_range,
            earliest=earliest, latest=latest,
        )
        job = self.wait_for_completion(job.job_id, timeout=timeout)

        if job.status == JobStatus.FAILED:
            raise RuntimeError(f"Cribl Search job {job.job_id} failed: {job.error}")

        return self.get_all_results(job.job_id)
