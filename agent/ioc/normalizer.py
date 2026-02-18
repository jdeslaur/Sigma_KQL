"""
IOC Normalizer — deduplication, scoring, and SQLite persistence.

All IOCs from every source pass through here before being used for hunting.
Internal schema is STIX2-inspired but simplified for operability.
"""

import json
import logging
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# IOC data model
# ---------------------------------------------------------------------------

VALID_IOC_TYPES = {
    "ttp",        # MITRE ATT&CK technique / behavioural pattern
    "cve",        # CVE identifier
    "cmdline",    # Command-line pattern
    "file_path",  # File path or name pattern
    "registry",   # Windows registry key/value
    "ip",         # IP address
    "domain",     # Domain name
    "url",        # URL
    "hash_md5",
    "hash_sha1",
    "hash_sha256",
    "ja3",        # TLS fingerprint
    "email",
}

VALID_SOURCES = {"osint", "llm", "commercial", "manual", "mitre_det"}


@dataclass
class IOC:
    ioc_type: str                          # one of VALID_IOC_TYPES
    value: str                             # the raw indicator value
    source: str                            # one of VALID_SOURCES
    confidence: float = 0.5               # 0.0–1.0
    mitre_techniques: list[str] = field(default_factory=list)   # e.g. ["T1059.001"]
    det_strategies: list[str] = field(default_factory=list)     # e.g. ["DET0001"]
    context: str = ""                      # free-text description / origin
    tags: list[str] = field(default_factory=list)
    first_seen: str = ""                   # ISO8601
    last_seen: str = ""                    # ISO8601
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        if not self.first_seen:
            self.first_seen = now
        if not self.last_seen:
            self.last_seen = now
        self._validate()

    def _validate(self) -> None:
        if self.ioc_type not in VALID_IOC_TYPES:
            raise ValueError(f"Invalid ioc_type: {self.ioc_type!r}. Must be one of {VALID_IOC_TYPES}")
        if self.source not in VALID_SOURCES:
            raise ValueError(f"Invalid source: {self.source!r}. Must be one of {VALID_SOURCES}")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {self.confidence}")
        if not self.value:
            raise ValueError("IOC value must not be empty")

    def dedup_key(self) -> str:
        """Unique key used for deduplication — type + normalised value."""
        return f"{self.ioc_type}:{self.value.strip().lower()}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["mitre_techniques"] = json.dumps(d["mitre_techniques"])
        d["det_strategies"] = json.dumps(d["det_strategies"])
        d["tags"] = json.dumps(d["tags"])
        return d

    @classmethod
    def from_row(cls, row: dict) -> "IOC":
        row = dict(row)
        row["mitre_techniques"] = json.loads(row.get("mitre_techniques") or "[]")
        row["det_strategies"] = json.loads(row.get("det_strategies") or "[]")
        row["tags"] = json.loads(row.get("tags") or "[]")
        return cls(**row)


# ---------------------------------------------------------------------------
# SQLite-backed IOC store
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS iocs (
    id              TEXT PRIMARY KEY,
    ioc_type        TEXT NOT NULL,
    value           TEXT NOT NULL,
    source          TEXT NOT NULL,
    confidence      REAL NOT NULL DEFAULT 0.5,
    mitre_techniques TEXT NOT NULL DEFAULT '[]',
    det_strategies  TEXT NOT NULL DEFAULT '[]',
    context         TEXT NOT NULL DEFAULT '',
    tags            TEXT NOT NULL DEFAULT '[]',
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    dedup_key       TEXT NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_iocs_type  ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_dedup ON iocs(dedup_key);
CREATE INDEX IF NOT EXISTS idx_iocs_last  ON iocs(last_seen);
"""


class IOCStore:
    """
    Thread-safe SQLite-backed IOC store with deduplication and confidence merging.

    Usage:
        store = IOCStore("agent_state.db")
        added = store.add(ioc)  # True if new, False if already known
        iocs  = store.get_recent(hours=24)
    """

    def __init__(self, db_path: str | Path = "agent_state.db") -> None:
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(_DDL)
        self._conn.commit()

    def add(self, ioc: IOC) -> bool:
        """
        Insert an IOC. If a duplicate (same dedup_key) exists:
        - update last_seen and raise confidence if new value is higher
        - merge mitre_techniques and tags lists
        Returns True if the IOC was newly inserted, False if it already existed.
        """
        key = ioc.dedup_key()
        now = datetime.now(timezone.utc).isoformat()

        existing = self._conn.execute(
            "SELECT * FROM iocs WHERE dedup_key = ?", (key,)
        ).fetchone()

        if existing is None:
            d = ioc.to_dict()
            d["dedup_key"] = key
            cols = ", ".join(d.keys())
            placeholders = ", ".join("?" * len(d))
            self._conn.execute(
                f"INSERT INTO iocs ({cols}) VALUES ({placeholders})",
                list(d.values()),
            )
            self._conn.commit()
            logger.debug("New IOC added: %s", key)
            return True

        # Merge existing record
        existing_techniques = json.loads(existing["mitre_techniques"] or "[]")
        existing_tags = json.loads(existing["tags"] or "[]")
        existing_strategies = json.loads(existing["det_strategies"] or "[]")

        merged_techniques = list(set(existing_techniques + ioc.mitre_techniques))
        merged_tags = list(set(existing_tags + ioc.tags))
        merged_strategies = list(set(existing_strategies + ioc.det_strategies))
        new_confidence = max(existing["confidence"], ioc.confidence)

        self._conn.execute(
            """UPDATE iocs SET
               last_seen = ?,
               confidence = ?,
               mitre_techniques = ?,
               det_strategies = ?,
               tags = ?
               WHERE dedup_key = ?""",
            (now, new_confidence, json.dumps(merged_techniques),
             json.dumps(merged_strategies), json.dumps(merged_tags), key),
        )
        self._conn.commit()
        logger.debug("Existing IOC updated: %s", key)
        return False

    def add_many(self, iocs: list[IOC]) -> tuple[int, int]:
        """Returns (new_count, updated_count)."""
        new_count = updated_count = 0
        for ioc in iocs:
            if self.add(ioc):
                new_count += 1
            else:
                updated_count += 1
        return new_count, updated_count

    def get_by_type(self, ioc_type: str) -> list[IOC]:
        rows = self._conn.execute(
            "SELECT * FROM iocs WHERE ioc_type = ? ORDER BY last_seen DESC", (ioc_type,)
        ).fetchall()
        return [IOC.from_row(r) for r in rows]

    def get_by_technique(self, technique_id: str) -> list[IOC]:
        """Return IOCs whose mitre_techniques list contains the given technique."""
        rows = self._conn.execute(
            "SELECT * FROM iocs WHERE mitre_techniques LIKE ?",
            (f'%"{technique_id}"%',),
        ).fetchall()
        return [IOC.from_row(r) for r in rows]

    def get_recent(self, hours: int = 24) -> list[IOC]:
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        rows = self._conn.execute(
            "SELECT * FROM iocs WHERE last_seen >= ? ORDER BY confidence DESC",
            (cutoff,),
        ).fetchall()
        return [IOC.from_row(r) for r in rows]

    def get_all(self) -> list[IOC]:
        rows = self._conn.execute(
            "SELECT * FROM iocs ORDER BY last_seen DESC"
        ).fetchall()
        return [IOC.from_row(r) for r in rows]

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]

    def close(self) -> None:
        self._conn.close()


# ---------------------------------------------------------------------------
# Convenience factory helpers
# ---------------------------------------------------------------------------

def make_ttp_ioc(
    technique_id: str,
    description: str,
    source: str = "mitre_det",
    confidence: float = 0.9,
    det_strategies: Optional[list[str]] = None,
) -> IOC:
    """Create a TTP-typed IOC from a MITRE technique ID."""
    return IOC(
        ioc_type="ttp",
        value=technique_id,
        source=source,
        confidence=confidence,
        mitre_techniques=[technique_id],
        det_strategies=det_strategies or [],
        context=description,
    )


def make_cve_ioc(
    cve_id: str,
    description: str,
    source: str = "llm",
    confidence: float = 0.85,
    mitre_techniques: Optional[list[str]] = None,
) -> IOC:
    """Create a CVE-typed IOC."""
    return IOC(
        ioc_type="cve",
        value=cve_id,
        source=source,
        confidence=confidence,
        mitre_techniques=mitre_techniques or [],
        context=description,
    )
