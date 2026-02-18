"""
Triage state — SQLite persistence for hunt hits and analyst decisions.

A "HitRecord" represents a set of Cribl Search results tied to a specific
HuntQuery. Analysts review HitRecords and mark them:
  pending    → initial state, awaiting review
  approved   → analyst approved; rehydration should be triggered
  rejected   → analyst dismissed; no rehydration needed
  snoozed    → defer review (e.g. known-good, check again later)
  rehydrated → rehydration job submitted
  forwarded  → events sent to SIEM
"""

import json
import logging
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class HitStatus(str, Enum):
    PENDING    = "pending"
    APPROVED   = "approved"
    REJECTED   = "rejected"
    SNOOZED    = "snoozed"
    REHYDRATED = "rehydrated"
    FORWARDED  = "forwarded"


@dataclass
class HitRecord:
    hit_id: str
    ioc_id: str
    ioc_type: str
    ioc_value: str
    cribl_job_id: str
    query: str
    event_count: int
    sample_events: list[dict]            # up to 5 representative events
    matched_rules: list[str]
    det_strategies: list[str]
    description: str
    status: HitStatus = HitStatus.PENDING
    analyst_note: str = ""
    rehydration_job_id: str = ""
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now
        if not self.hit_id:
            self.hit_id = str(uuid.uuid4())

    def to_db_dict(self) -> dict:
        d = asdict(self)
        d["sample_events"] = json.dumps(d["sample_events"])
        d["matched_rules"] = json.dumps(d["matched_rules"])
        d["det_strategies"] = json.dumps(d["det_strategies"])
        d["status"] = d["status"] if isinstance(d["status"], str) else d["status"].value
        return d

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "HitRecord":
        d = dict(row)
        d["sample_events"] = json.loads(d.get("sample_events") or "[]")
        d["matched_rules"] = json.loads(d.get("matched_rules") or "[]")
        d["det_strategies"] = json.loads(d.get("det_strategies") or "[]")
        d["status"] = HitStatus(d.get("status", "pending"))
        return cls(**d)


# ---------------------------------------------------------------------------
# SQLite schema
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS hits (
    hit_id              TEXT PRIMARY KEY,
    ioc_id              TEXT NOT NULL,
    ioc_type            TEXT NOT NULL,
    ioc_value           TEXT NOT NULL,
    cribl_job_id        TEXT NOT NULL,
    query               TEXT NOT NULL,
    event_count         INTEGER NOT NULL DEFAULT 0,
    sample_events       TEXT NOT NULL DEFAULT '[]',
    matched_rules       TEXT NOT NULL DEFAULT '[]',
    det_strategies      TEXT NOT NULL DEFAULT '[]',
    description         TEXT NOT NULL DEFAULT '',
    status              TEXT NOT NULL DEFAULT 'pending',
    analyst_note        TEXT NOT NULL DEFAULT '',
    rehydration_job_id  TEXT NOT NULL DEFAULT '',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hits_status  ON hits(status);
CREATE INDEX IF NOT EXISTS idx_hits_ioc     ON hits(ioc_id);
CREATE INDEX IF NOT EXISTS idx_hits_created ON hits(created_at);
"""


class HitStore:
    """
    SQLite-backed store for hunt hits and analyst triage decisions.

    Usage:
        store = HitStore("agent_state.db")
        store.add(hit_record)
        pending = store.get_by_status(HitStatus.PENDING)
        store.update_status(hit_id, HitStatus.APPROVED, note="Confirmed C2")
    """

    def __init__(self, db_path: str | Path = "agent_state.db") -> None:
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_DDL)
        self._conn.commit()

    def add(self, hit: HitRecord) -> None:
        d = hit.to_db_dict()
        cols = ", ".join(d.keys())
        placeholders = ", ".join("?" * len(d))
        self._conn.execute(
            f"INSERT OR REPLACE INTO hits ({cols}) VALUES ({placeholders})",
            list(d.values()),
        )
        self._conn.commit()
        logger.debug("Hit recorded: %s (ioc=%s, events=%d)", hit.hit_id, hit.ioc_value, hit.event_count)

    def get(self, hit_id: str) -> Optional[HitRecord]:
        row = self._conn.execute(
            "SELECT * FROM hits WHERE hit_id = ?", (hit_id,)
        ).fetchone()
        return HitRecord.from_row(row) if row else None

    def get_by_status(self, status: HitStatus) -> list[HitRecord]:
        rows = self._conn.execute(
            "SELECT * FROM hits WHERE status = ? ORDER BY created_at DESC",
            (status.value,),
        ).fetchall()
        return [HitRecord.from_row(r) for r in rows]

    def get_pending(self) -> list[HitRecord]:
        return self.get_by_status(HitStatus.PENDING)

    def get_approved(self) -> list[HitRecord]:
        return self.get_by_status(HitStatus.APPROVED)

    def update_status(
        self,
        hit_id: str,
        new_status: HitStatus,
        note: str = "",
        rehydration_job_id: str = "",
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """UPDATE hits SET status = ?, analyst_note = ?,
               rehydration_job_id = ?, updated_at = ?
               WHERE hit_id = ?""",
            (new_status.value, note, rehydration_job_id, now, hit_id),
        )
        self._conn.commit()
        logger.info("Hit %s → %s", hit_id, new_status.value)

    def count_by_status(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT status, COUNT(*) as cnt FROM hits GROUP BY status"
        ).fetchall()
        return {row["status"]: row["cnt"] for row in rows}

    def get_all(self) -> list[HitRecord]:
        rows = self._conn.execute(
            "SELECT * FROM hits ORDER BY created_at DESC"
        ).fetchall()
        return [HitRecord.from_row(r) for r in rows]

    def close(self) -> None:
        self._conn.close()
