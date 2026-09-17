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


# 邮箱同步游标：每个文件夹记录 UIDVALIDITY 与已取最大 UID，实现增量取信。
# UIDVALIDITY 由服务端维护，它一旦变化说明邮箱被重建，此前记录的 UID 全部失效，
# 必须从头重扫——这是 IMAP 增量同步的硬要求，漏了会静默丢信。
_MAILBOX_SCHEMA = """
CREATE TABLE IF NOT EXISTS mailbox_sync (
    folder       TEXT PRIMARY KEY,
    uidvalidity  INTEGER NOT NULL,
    last_uid     INTEGER NOT NULL,
    last_sync    TEXT
);
"""


# 发件人往来历史（信任上下文的依据）。只存"谁、多少封、时间跨度、是否回过、用过哪些链接域"，
# **不存正文**。判据与降权策略在 app/scoring/trust.py，这里只负责存取。
_SENDER_SCHEMA = """
CREATE TABLE IF NOT EXISTS sender_history (
    addr         TEXT PRIMARY KEY,
    domain       TEXT,
    count        INTEGER NOT NULL DEFAULT 0,
    first_seen   TEXT,
    last_seen    TEXT,
    replied      INTEGER NOT NULL DEFAULT 0,
    link_domains TEXT
);
CREATE INDEX IF NOT EXISTS idx_sender_domain ON sender_history(domain);
"""


# 往来历史的"已计入"台账：path -> 计入时间。增量重建靠它判断"哪些邮件还没计入"——
# 逐封 upsert 会累加计数，所以必须保证**每封只计一次**（重复计入 = 把信任门槛吹大）。
_TRUST_FILES_SCHEMA = """
CREATE TABLE IF NOT EXISTS trust_files (
    path       TEXT PRIMARY KEY,
    counted_at TEXT NOT NULL
);
"""


# 桌面通知的去重状态：key（发件人）-> 上次提醒时间。存 cache.db 是为了跨进程/重启仍生效——
# 否则 watch 重启后会把刚提醒过的发件人再提醒一遍。
_NOTIFY_SCHEMA = """
CREATE TABLE IF NOT EXISTS notify_state (
    key       TEXT PRIMARY KEY,
    last_at   TEXT NOT NULL
);
"""


# 往来历史重建的"输入指纹"：文件集（数量/最大 mtime/总大小/路径摘要）没变就不必重扫。
# 重建一次要读每封邮件（597 封实测 2.5~3.4s），而绝大多数调用是"没有任何新邮件"的重复调用。
_TRUST_STATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS trust_state (
    root         TEXT PRIMARY KEY,
    fingerprint  TEXT NOT NULL,
    stats        TEXT,
    updated_at   TEXT
);
"""


# 人工判定（L1 显式反馈）：按"发件地址"或"可注册域"记录人工确认的正常/钓鱼。
# 必须留痕、可撤销、可到期——人工反馈是**可被投毒**的通道（攻击者只要诱你点一次"正常"
# 就拿到该发件人的信任），所以字段里保留 source/note/created_at/expires_at。
_HUMAN_SCHEMA = """
CREATE TABLE IF NOT EXISTS human_verdict (
    scope       TEXT NOT NULL,
    key         TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT,
    source      TEXT,
    note        TEXT,
    PRIMARY KEY (scope, key)
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
            self._conn.executescript(_MAILBOX_SCHEMA)
            self._conn.executescript(_SENDER_SCHEMA)
            self._conn.executescript(_TRUST_STATE_SCHEMA)
            self._conn.executescript(_NOTIFY_SCHEMA)
            self._conn.executescript(_TRUST_FILES_SCHEMA)
            self._conn.executescript(_HUMAN_SCHEMA)
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

    # ---- 人工判定（L1 显式反馈） ----
    def set_human_verdict(self, scope: str, key: str, verdict: str,
                          days: int | None = None, source: str = "gui",
                          note: str = "") -> None:
        """写入人工判定。scope ∈ {addr, domain}；verdict ∈ {benign, phishing}。

        ``days=None`` 表示不过期（默认），``days=N`` 则 N 天后自动失效——信任类判定
        建议设到期，避免一条人工判断永久放行一个发件人。
        """
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        expires = (now + timedelta(days=days)).isoformat() if days else None
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO human_verdict "
                "(scope, key, verdict, created_at, expires_at, source, note) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scope, key.lower(), verdict, now.isoformat(), expires, source, note),
            )
            self._conn.commit()

    def get_human_verdict(self, addr: str, domain: str = "") -> dict[str, Any] | None:
        """查该发件人的有效人工判定（地址级优先于域级；已过期的视同不存在）。"""
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat()
        candidates = [("addr", (addr or "").lower()), ("domain", (domain or "").lower())]
        with self._lock:
            for scope, key in candidates:
                if not key:
                    continue
                row = self._conn.execute(
                    "SELECT scope, key, verdict, created_at, expires_at, source, note "
                    "FROM human_verdict WHERE scope = ? AND key = ?", (scope, key)).fetchone()
                if not row:
                    continue
                if row[4] and row[4] <= now:      # 已过期：删掉并继续看下一个作用域
                    self._conn.execute("DELETE FROM human_verdict WHERE scope = ? AND key = ?",
                                       (scope, key))
                    self._conn.commit()
                    continue
                return {"scope": row[0], "key": row[1], "verdict": row[2], "created_at": row[3],
                        "expires_at": row[4], "source": row[5], "note": row[6]}
        return None

    def list_human_verdicts(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT scope, key, verdict, created_at, expires_at, source, note "
                "FROM human_verdict ORDER BY created_at DESC").fetchall()
        return [{"scope": r[0], "key": r[1], "verdict": r[2], "created_at": r[3],
                 "expires_at": r[4], "source": r[5], "note": r[6]} for r in rows]

    def delete_human_verdict(self, scope: str, key: str) -> int:
        with self._lock:
            cur = self._conn.execute("DELETE FROM human_verdict WHERE scope = ? AND key = ?",
                                     (scope, key.lower()))
            self._conn.commit()
            return cur.rowcount

    # ---- 发件人往来历史（信任上下文） ----
    def upsert_sender(self, addr: str, domain: str, seen_at: str,
                      replied: bool = False, link_domains: tuple[str, ...] = ()) -> None:
        """累加一条发件人来往记录（按地址为主键，域用于"域级已建立"判定）。"""
        import json

        with self._lock:
            row = self._conn.execute(
                "SELECT count, first_seen, last_seen, replied, link_domains "
                "FROM sender_history WHERE addr = ?", (addr,)).fetchone()
            links: set[str] = set()
            if row:
                count, first_seen, last_seen, old_replied, old_links = row
                try:
                    links = set(json.loads(old_links or "[]"))
                except Exception:  # noqa: BLE001
                    links = set()
                count += 1
                replied = bool(replied or old_replied)
                first_seen = min(first_seen, seen_at) if first_seen else seen_at
                last_seen = max(last_seen, seen_at) if last_seen else seen_at
            else:
                count, first_seen, last_seen = 1, seen_at, seen_at
            links |= {d for d in link_domains if d}
            self._conn.execute(
                "INSERT OR REPLACE INTO sender_history "
                "(addr, domain, count, first_seen, last_seen, replied, link_domains) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (addr, domain, count, first_seen, last_seen, int(replied),
                 json.dumps(sorted(links), ensure_ascii=False)),
            )
            self._conn.commit()

    def mark_replied(self, addr: str) -> None:
        """标记"你给它写过信"（已发送收件人），并按需建档。"""
        with self._lock:
            self._conn.execute(
                "INSERT INTO sender_history (addr, domain, count, replied) VALUES (?, '', 0, 1) "
                "ON CONFLICT(addr) DO UPDATE SET replied = 1",
                (addr,),
            )
            self._conn.commit()

    def get_sender(self, addr: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT addr, domain, count, first_seen, last_seen, replied, link_domains "
                "FROM sender_history WHERE addr = ?", (addr,)).fetchone()
        if not row:
            return None
        import json

        try:
            links = tuple(json.loads(row[6] or "[]"))
        except Exception:  # noqa: BLE001
            links = ()
        return {"addr": row[0], "domain": row[1], "count": row[2], "first_seen": row[3],
                "last_seen": row[4], "replied": bool(row[5]), "link_domains": links}

    def get_domain_history(self, domain: str) -> dict[str, int]:
        """某可注册域的聚合历史（封数 + 时间跨度天数）。"""
        if not domain:
            return {"count": 0, "span_days": 0}
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(count), 0), MIN(first_seen), MAX(last_seen) "
                "FROM sender_history WHERE domain = ?", (domain,)).fetchone()
        count, first_seen, last_seen = row or (0, None, None)
        span = 0
        if first_seen and last_seen:
            try:
                from datetime import datetime

                span = (datetime.fromisoformat(last_seen) - datetime.fromisoformat(first_seen)).days
            except Exception:  # noqa: BLE001
                span = 0
        return {"count": int(count), "span_days": max(span, 0)}

    def list_senders(self, limit: int = 500) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT addr, domain, count, first_seen, last_seen, replied "
                "FROM sender_history ORDER BY count DESC, last_seen DESC LIMIT ?",
                (limit,)).fetchall()
        return [{"addr": r[0], "domain": r[1], "count": r[2], "first_seen": r[3],
                 "last_seen": r[4], "replied": bool(r[5])} for r in rows]

    def clear_senders(self) -> int:
        with self._lock:
            cur = self._conn.execute("DELETE FROM sender_history")
            self._conn.commit()
            return cur.rowcount

    # ---- 往来历史增量台账 ----
    def known_trust_files(self) -> set[str]:
        with self._lock:
            rows = self._conn.execute("SELECT path FROM trust_files").fetchall()
        return {r[0] for r in rows}

    def mark_trust_files(self, paths: list[str]) -> None:
        from datetime import datetime, timezone

        if not paths:
            return
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.executemany(
                "INSERT OR REPLACE INTO trust_files (path, counted_at) VALUES (?, ?)",
                [(p, now) for p in paths])
            self._conn.commit()

    def clear_trust_files(self) -> int:
        with self._lock:
            cur = self._conn.execute("DELETE FROM trust_files")
            self._conn.commit()
            return cur.rowcount

    # ---- 桌面通知去重状态 ----
    def get_notify_state(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT last_at FROM notify_state WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_notify_state(self, key: str, last_at: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO notify_state (key, last_at) VALUES (?, ?)", (key, last_at))
            self._conn.commit()

    def clear_notify_state(self) -> int:
        with self._lock:
            cur = self._conn.execute("DELETE FROM notify_state")
            self._conn.commit()
            return cur.rowcount

    # ---- 往来历史重建的输入指纹 ----
    def get_trust_state(self, root: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT fingerprint, stats, updated_at FROM trust_state WHERE root = ?",
                (root,),
            ).fetchone()
        if not row:
            return None
        return {"fingerprint": row[0], "stats": json.loads(row[1] or "{}"), "updated_at": row[2]}

    def set_trust_state(self, root: str, fingerprint: str, stats: dict[str, Any]) -> None:
        from datetime import datetime, timezone

        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO trust_state (root, fingerprint, stats, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (root, fingerprint, json.dumps(stats, ensure_ascii=False),
                 datetime.now(timezone.utc).isoformat()),
            )
            self._conn.commit()

    # ---- 邮箱同步游标（IMAP 增量取信） ----
    def get_mailbox_cursor(self, folder: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT uidvalidity, last_uid, last_sync FROM mailbox_sync WHERE folder = ?",
                (folder,),
            ).fetchone()
        if not row:
            return None
        return {"uidvalidity": row[0], "last_uid": row[1], "last_sync": row[2]}

    def set_mailbox_cursor(self, folder: str, uidvalidity: int, last_uid: int) -> None:
        from datetime import datetime, timezone

        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO mailbox_sync (folder, uidvalidity, last_uid, last_sync) "
                "VALUES (?, ?, ?, ?)",
                (folder, uidvalidity, last_uid, datetime.now(timezone.utc).isoformat()),
            )
            self._conn.commit()

    def reset_mailbox_cursor(self, folder: str = "") -> int:
        """重置同步游标（文件夹为空则清空全部），返回删除行数。"""
        with self._lock:
            if folder:
                cur = self._conn.execute("DELETE FROM mailbox_sync WHERE folder = ?", (folder,))
            else:
                cur = self._conn.execute("DELETE FROM mailbox_sync")
            self._conn.commit()
            return cur.rowcount

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
