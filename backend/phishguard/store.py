"""Scan history in SQLite, plus the aggregate queries the admin dashboard needs.

WHY SQLite: it ships with Python, needs no server, and one file is plenty
for a single-machine demo.

WHY one long-lived connection behind a lock: the first version opened a
connection per call. In WAL mode, closing the last connection checkpoints
and deletes the WAL file, so every scan paid ~7 ms for that (measured with
the benchmark). One connection shared by FastAPI's worker threads, with a
lock so only one thread uses it at a time, brings a write well under 1 ms.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT    NOT NULL,             -- ISO-8601 UTC
    url         TEXT    NOT NULL,
    domain      TEXT    NOT NULL,             -- registrable domain
    mode        TEXT    NOT NULL,             -- fast | full
    score       INTEGER NOT NULL,             -- 0..100
    verdict     TEXT    NOT NULL,             -- safe | suspicious | phishing
    client      TEXT    NOT NULL,             -- web | extension | api
    cached      INTEGER NOT NULL,
    latency_ms  REAL    NOT NULL,
    result_json TEXT    NOT NULL              -- full response, for the detail view
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_scans_domain  ON scans(domain);
"""


class ScanStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: the connection is shared across threads,
        # which is safe because every use goes through self._lock.
        self._db = sqlite3.connect(self.path, timeout=5, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")  # readers do not block the writer
        # synchronous=NORMAL: in WAL mode this is still safe against app
        # crashes and corruption; a power cut can lose only the last few
        # history rows, which is acceptable for this data.
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript(SCHEMA)
        self._lock = threading.Lock()

    @contextmanager
    def _conn(self):
        with self._lock:
            try:
                yield self._db
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def record(self, result: dict, client: str) -> int:
        with self._conn() as db:
            cur = db.execute(
                "INSERT INTO scans (created_at, url, domain, mode, score, verdict, client, cached, "
                "latency_ms, result_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (result["scanned_at"], result["normalized_url"], result["domain"], result["mode"],
                 result["score"], result["verdict"], client, int(result["cached"]),
                 result["latency_ms"], json.dumps(result)))
            return int(cur.lastrowid)

    def history(self, limit: int = 50, verdict: str | None = None, query: str | None = None) -> list[dict]:
        sql = ("SELECT id, created_at, url, domain, mode, score, verdict, client, cached, latency_ms "
               "FROM scans WHERE 1=1")
        args: list = []
        if verdict:
            sql += " AND verdict = ?"
            args.append(verdict)
        if query:
            sql += " AND url LIKE ?"  # parameterised: user text never becomes SQL
            args.append(f"%{query}%")
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._conn() as db:
            return [dict(r) for r in db.execute(sql, args)]

    def get(self, scan_id: int) -> dict | None:
        with self._conn() as db:
            row = db.execute("SELECT result_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return json.loads(row["result_json"]) if row else None

    def top_flagged_domains(self, limit: int = 10) -> list[dict]:
        with self._conn() as db:
            rows = db.execute(
                "SELECT domain, COUNT(*) AS scans, MAX(score) AS max_score, "
                "ROUND(AVG(score), 1) AS avg_score, MAX(created_at) AS last_seen "
                "FROM scans WHERE verdict != 'safe' GROUP BY domain "
                "ORDER BY scans DESC, max_score DESC LIMIT ?", (limit,))
            return [dict(r) for r in rows]

    def stats(self, days: int = 14) -> dict:
        with self._conn() as db:
            total = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            by_verdict = {r[0]: r[1] for r in db.execute("SELECT verdict, COUNT(*) FROM scans GROUP BY verdict")}
            by_client = {r[0]: r[1] for r in db.execute("SELECT client, COUNT(*) FROM scans GROUP BY client")}
            latency = {}
            for mode in ("fast", "full"):
                # Latency of real (uncached) work, so cache hits do not flatter it.
                values = [r[0] for r in db.execute(
                    "SELECT latency_ms FROM scans WHERE mode = ? AND cached = 0 ORDER BY latency_ms", (mode,))]
                latency[mode] = {
                    "count": len(values),
                    "p50": values[len(values) // 2] if values else None,
                    "p95": values[min(len(values) - 1, int(len(values) * 0.95))] if values else None,
                }
            cached = db.execute("SELECT COUNT(*) FROM scans WHERE cached = 1").fetchone()[0]
            per_day = [dict(r) for r in db.execute(
                "SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS total, "
                "SUM(verdict = 'safe') AS safe, SUM(verdict = 'suspicious') AS suspicious, "
                "SUM(verdict = 'phishing') AS phishing FROM scans "
                "WHERE created_at >= date('now', ?) GROUP BY day ORDER BY day", (f"-{days - 1} days",))]
        flagged = by_verdict.get("suspicious", 0) + by_verdict.get("phishing", 0)
        return {
            "total_scans": total,
            "by_verdict": {v: by_verdict.get(v, 0) for v in ("safe", "suspicious", "phishing")},
            "by_client": by_client,
            "flagged_rate": round(flagged / total, 4) if total else 0.0,
            "cache_hit_rate": round(cached / total, 4) if total else 0.0,
            "latency_ms": latency,
            "per_day": per_day,
        }
