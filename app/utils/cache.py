"""SQLite IOC 缓存：避免重复查询威胁情报 API，规避免费额度限流。"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from app.config import CACHE_DB
from app.utils.logger import get_logger

log = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS intel_cache (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL
);
"""

# 报告索引：report_id -> 摘要信息，供 /reports 列表与看板统计使用
_REPORT_SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    report_id    TEXT PRIMARY KEY,
    filename     TEXT,
    verdict      TEXT,
    score        INTEGER,
    created_at   TEXT,
    ioc_count    INTEGER,
    report_path  TEXT
);
"""


class Cache:
    """线程安全的 SQLite 键值缓存（带 TTL），同时承担报告索引职责。"""

    def __init__(self, db_path: Path = CACHE_DB):
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.executescript(_REPORT_SCHEMA)
            self._conn.commit()

    def get(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM intel_cache WHERE key = ? AND expires_at > ?",
                (key, time.time()),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def set(self, key: str, value: dict[str, Any], ttl_hours: int = 24) -> None:
        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO intel_cache (key, value, created_at, expires_at) "
                "VALUES (?, ?, ?, ?)",
                (key, json.dumps(value, ensure_ascii=False), now, now + ttl_hours * 3600),
            )
            self._conn.commit()

    def purge_expired(self) -> int:
        with self._lock:
            cur = self._conn.execute("DELETE FROM intel_cache WHERE expires_at <= ?", (time.time(),))
            self._conn.commit()
            return cur.rowcount

    # ---- 报告索引 ----
    def index_report(self, report_id: str, filename: str, verdict: str, score: int,
                     created_at: str, ioc_count: int, report_path: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO reports VALUES (?, ?, ?, ?, ?, ?, ?)",
                (report_id, filename, verdict, score, created_at, ioc_count, report_path),
            )
            self._conn.commit()

    def list_reports(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT report_id, filename, verdict, score, created_at, ioc_count "
                "FROM reports ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [
            {
                "report_id": r[0], "filename": r[1], "verdict": r[2],
                "score": r[3], "created_at": r[4], "ioc_count": r[5],
            }
            for r in rows
        ]

    def get_report_meta(self, report_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT report_id, filename, verdict, score, created_at, ioc_count, report_path "
                "FROM reports WHERE report_id = ?",
                (report_id,),
            ).fetchone()
        if not row:
            return None
        return {
            "report_id": row[0], "filename": row[1], "verdict": row[2],
            "score": row[3], "created_at": row[4], "ioc_count": row[5],
            "report_path": row[6],
        }

    def stats(self) -> dict[str, Any]:
        with self._lock:
            total, = self._conn.execute("SELECT COUNT(*) FROM reports").fetchone()
            mal, = self._conn.execute(
                "SELECT COUNT(*) FROM reports WHERE verdict = 'MALICIOUS'").fetchone()
            susp, = self._conn.execute(
                "SELECT COUNT(*) FROM reports WHERE verdict = 'SUSPICIOUS'").fetchone()
            ben, = self._conn.execute(
                "SELECT COUNT(*) FROM reports WHERE verdict = 'BENIGN'").fetchone()
        return {"total": total, "malicious": mal, "suspicious": susp, "benign": ben}

    # ---- 清理（供 app/utils/maintenance.py 调用） ----
    def count_intel(self) -> int:
        """情报缓存当前条数（含已过期未清理的）。"""
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM intel_cache").fetchone()
        return row[0]

    def clear_reports(self) -> int:
        """清空报告索引，返回删除行数。"""
        with self._lock:
            cur = self._conn.execute("DELETE FROM reports")
            self._conn.commit()
            return cur.rowcount

    def clear_intel_cache(self) -> int:
        """清空情报查询缓存，返回删除行数（下次分析会重新查询情报源）。"""
        with self._lock:
            cur = self._conn.execute("DELETE FROM intel_cache")
            self._conn.commit()
            return cur.rowcount


cache = Cache()
