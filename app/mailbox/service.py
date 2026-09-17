"""后台监控服务：把轮询分析跑在守护线程里，并向 GUI 暴露状态与最近告警。

**与 CLI `--watch` 的关系**：主循环是同一个 `run_watch`（同一套游标语义、断线自愈、
"分析成功才推进游标"），差别只在宿主——这里是 Streamlit 进程内的守护线程，CLI 是独立进程。
推送给 GUI 的两样东西都从 `on_round` 回调来，不另写一套逻辑：

  - ``status()``：是否在跑、轮次、最后检查时间、累计新邮件/告警/推送；
  - ``alerts()``：最近 N 封 MALICIOUS/SUSPICIOUS（**无论是否开启桌面通知都记录**，
    GUI 的「最近告警」视图靠它）。

**边界说明（写进 GUI）**：线程随 Streamlit 进程存活——页面关掉/服务重启就停了。要长期常驻请用
CLI（`--watch --notify`）并交给系统服务管理（Windows 任务计划/NSSM、systemd、容器 sidecar）。
"""
from __future__ import annotations

import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from app.utils.logger import get_logger

log = get_logger(__name__)

ALERT_VERDICTS = ("MALICIOUS", "SUSPICIOUS")
MAX_LOG = 300
MAX_ALERTS = 100


class Monitor:
    """轮询监控的宿主（GUI 用）。**线程安全**：状态用锁保护，回调只追加不修改历史。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._log: deque[str] = deque(maxlen=MAX_LOG)
        self._alerts: deque[dict[str, Any]] = deque(maxlen=MAX_ALERTS)
        self._rounds = 0
        self._new_mails = 0
        self._pushed = 0
        self._last_round_at = ""
        self._last_error = ""
        self._started_at = ""
        self._config: dict[str, Any] = {}

    # ---- 供 GUI 读 ----
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self.running(),
                "rounds": self._rounds,
                "new_mails": self._new_mails,
                "pushed": self._pushed,
                "last_round_at": self._last_round_at,
                "last_error": self._last_error,
                "started_at": self._started_at,
                "config": dict(self._config),
                "log": list(self._log),
                "alerts": list(self._alerts),
            }

    def alerts(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._alerts)

    # ---- 写状态（回调/单轮检查共用） ----
    def _record(self, info: dict[str, Any], notifier: Any = None,
                out_root: Path | None = None) -> dict[str, Any]:
        reports = info.get("reports") or []
        pushed: list[dict[str, Any]] = []
        if notifier is not None and reports:
            pushed = notifier.notify_reports(reports)
        pushed_keys = {p["key"] for p in pushed}
        with self._lock:
            self._rounds = int(info.get("round") or self._rounds + 1)
            self._new_mails += int(info.get("files") or 0)
            self._pushed += len(pushed)
            self._last_round_at = datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S")
            self._last_error = str(info.get("error") or "")
            stamp = self._last_round_at
            if not reports:
                self._log.append(f"[{stamp}] 无新邮件")
            else:
                counts: dict[str, int] = {}
                for r in reports:
                    counts[r.get("verdict", "?")] = counts.get(r.get("verdict", "?"), 0) + 1
                summary = " | ".join(f"{k} {v}" for k, v in sorted(counts.items()))
                self._log.append(f"[{stamp}] 新邮件 {len(reports)} 封 -> {summary}")
                for r in reports:
                    if r.get("verdict") in ALERT_VERDICTS:
                        self._alerts.append({
                            "时间": stamp,
                            "判定": r.get("verdict"),
                            "分数": r.get("score"),
                            "主题": str(r.get("subject") or "")[:60],
                            "发件人": str(r.get("from") or "")[:60],
                            "已推送": notifier.sender_key(r) in pushed_keys if notifier else False,
                            "报告": r.get("report_id", ""),
                        })
                        self._log.append(f"      [{r.get('verdict')} {r.get('score')}] "
                                         f"{str(r.get('subject') or '')[:50]}")
            if info.get("error"):
                self._log.append(f"      警告：{info['error']}（重连中）")
        return {"pushed": pushed}

    # ---- 单轮检查（GUI 的「立即检查一次」，同步执行，便于立刻看到结果） ----
    def check_once(self, folders: list[str], offline: bool = True,
                   notify: bool = False, window_hours: int = 12,
                   out_root: Path | None = None,
                   connect: Callable[[], Any] | None = None) -> dict[str, Any]:
        from app.config import DATA_DIR, settings
        from app.mailbox.imap_client import _client
        from app.mailbox.watch import analyze_and_advance, watch_once

        out_root = out_root or (DATA_DIR / "mailbox")
        notifier = None
        if notify:
            from app.response.notify import Notifier

            notifier = Notifier(enabled=True, window_hours=window_hours)
        conn = (connect or _client)()
        try:
            files, pending = watch_once(conn, folders, out_root, settings.mailbox_max_bytes)
            if files:
                # 先增量更新往来历史再分析：信任上下文是**评分输入**，必须包含刚取到的这些邮件
                # 之外的历史（新邮件自身不参与自己的判定，与 run_watch 的口径一致）
                from app.mailbox.reputation import rebuild as rebuild_history

                rebuild_history(out_root, incremental=True)
            results = analyze_and_advance(files, pending, offline) if files else []
        finally:
            try:
                conn.logout()
            except Exception:  # noqa: BLE001
                pass
        info = {"round": self._rounds + 1, "files": len(files), "reports": results, "error": ""}
        return self._record(info, notifier=notifier, out_root=out_root)

    # ---- 后台线程 ----
    def start(self, folders: list[str], interval: int, offline: bool = True,
              notify: bool = False, window_hours: int = 12,
              out_root: Path | None = None,
              connect: Callable[[], Any] | None = None,
              sleep: Callable[[float], None] = time.sleep) -> None:
        if self.running():
            return
        from app.config import DATA_DIR
        from app.mailbox.watch import run_watch
        from app.response.notify import Notifier

        out_root = out_root or (DATA_DIR / "mailbox")
        notifier = Notifier(enabled=True, window_hours=window_hours) if notify else None
        self._stop = threading.Event()
        with self._lock:
            self._started_at = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
            self._config = {"folders": list(folders), "interval": interval,
                            "offline": offline, "notify": notify, "window_hours": window_hours}

        def _worker() -> None:
            try:
                run_watch(folders, interval, offline=offline, out_root=out_root,
                          connect=connect, sleep=sleep, quiet=True,
                          on_round=lambda info: self._record(info, notifier=notifier),
                          should_stop=self._stop.is_set)
            except Exception as exc:  # noqa: BLE001 - 线程内异常不能让页面崩
                log.warning("监控线程退出：%s: %s", type(exc).__name__, exc)
                with self._lock:
                    self._last_error = f"{type(exc).__name__}: {exc}"
                    self._log.append(f"监控线程退出：{type(exc).__name__}: {exc}")

        self._thread = threading.Thread(target=_worker, name="mailbox-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._thread = None


_monitor = Monitor()


def monitor() -> Monitor:
    """进程级单例（Streamlit 每次 rerun 都重新执行页面脚本，必须把状态挂在这里）。"""
    return _monitor
