"""通知出口：把"值得人看一眼的邮件"推出去（当前实现：桌面通知）。

**为什么必须有这一层**（README_dev 待办原话）：轮询分析已经跑起来了，但只在终端打印——
没人盯着终端就等于没做。这里做两件事：

1. **跨平台桌面通知，零 Python 依赖**：
   - Windows：优先 `winotify`（若已安装），否则用 PowerShell 的 WinRT Toast（系统自带，无需装包）；
   - macOS：`osascript -e 'display notification …'`；
   - Linux：`notify-send`。
   三者都是"尽力而为"：发不出去只记日志、绝不阻断分析主流程（通知失败不该让分析失败）。
   测试用可注入的 `runner`，不真的弹窗。

2. **降噪**（不做的话营销邮件会把人吵到关掉通知）：
   - 只推 `MALICIOUS` / `SUSPICIOUS`（SPAM/BENIGN 不推——前者是归档档，后者本就无需处置）；
   - **按发件人聚合**，同一发件人 `window_hours`（默认 12h）内只提醒一次；
   - 单轮**最多推 N 条**（默认 3），超出只推一条汇总（"另有 N 封见看板"），避免一次断线重连
     后几百封邮件把桌面刷屏。

后续如果要接微信（Server酱/Bark）或 TheHive 工单，加一个后端即可——入口、去重、限流都不用重写。
"""
from __future__ import annotations

import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from app.utils.logger import get_logger

log = get_logger(__name__)

NOTIFY_VERDICTS = ("MALICIOUS", "SUSPICIOUS")
DEFAULT_WINDOW_HOURS = 12
DEFAULT_MAX_PER_ROUND = 3
_ADDR_RE = re.compile(r"[\w.+-]+@([\w.-]+)")

_PS_TOAST = (
    "$ErrorActionPreference='Stop';"
    "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
    "ContentType=WindowsRuntime]|Out-Null;"
    "$t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
    "[Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
    "$n=$t.GetElementsByTagName('text');"
    "$n.Item(0).AppendChild($t.CreateTextNode($env:PA_TOAST_TITLE))|Out-Null;"
    "$n.Item(1).AppendChild($t.CreateTextNode($env:PA_TOAST_BODY))|Out-Null;"
    "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("
    "'Phishing Analyzer').Show([Windows.UI.Notifications.ToastNotification]::new($t))"
)


def _ran_ok(res: Any) -> bool:
    """子进程类后端是否成功。**必须查退出码**：subprocess.run 默认不因非零退出而抛异常，
    只看"没抛异常"会把失败当成功（实测：PowerShell 报错时函数照样返回 True）。"""
    code = getattr(res, "returncode", 0)
    if code:
        log.warning("桌面通知命令退出码 %s: %s", code,
                    (getattr(res, "stderr", b"") or b"")[:200])
        return False
    return True


def desktop_notify(title: str, message: str,
                   runner: Callable[..., Any] = subprocess.run) -> bool:
    """尽力弹一条桌面通知；返回是否成功（失败只记日志，不影响调用方）。"""
    try:
        if sys.platform == "win32":
            try:
                from winotify import Notification  # type: ignore[import-not-found]

                Notification(app_id="Phishing Analyzer", title=title, msg=message).show()
                return True
            except Exception:  # noqa: BLE001 - 没装 winotify 就走 PowerShell
                import os

                env = dict(os.environ, PA_TOAST_TITLE=title, PA_TOAST_BODY=message)
                return _ran_ok(runner(["powershell", "-NoProfile", "-NonInteractive",
                                       "-Command", _PS_TOAST],
                                      env=env, capture_output=True, timeout=20))
        if sys.platform == "darwin":
            script = f'display notification {message!r} with title {title!r}'
            return _ran_ok(runner(["osascript", "-e", script], capture_output=True, timeout=20))
        return _ran_ok(runner(["notify-send", title, message], capture_output=True, timeout=20))
    except Exception as exc:  # noqa: BLE001 - 通知是"尽力而为"，绝不阻断分析
        log.warning("桌面通知发送失败（不影响分析）: %s", exc)
        return False


class Notifier:
    """按发件人去重、限量推送的桌面通知器（去重状态存在 cache.db）。"""

    def __init__(self, enabled: bool = True, window_hours: int = DEFAULT_WINDOW_HOURS,
                 max_per_round: int = DEFAULT_MAX_PER_ROUND,
                 send: Callable[[str, str], bool] = desktop_notify):
        self.enabled = enabled
        self.window_hours = max(0, int(window_hours))
        self.max_per_round = max(1, int(max_per_round))
        self._send = send

    # ---- 去重状态（cache.db；通知器重启后仍记得"刚提醒过谁"） ----
    def _recently_notified(self, key: str) -> bool:
        from app.utils.cache import cache

        row = cache.get_notify_state(key)
        if not row or self.window_hours <= 0:
            return False
        try:
            last = datetime.fromisoformat(row)
        except ValueError:
            return False
        return datetime.now(timezone.utc) - last < timedelta(hours=self.window_hours)

    def _mark(self, key: str) -> None:
        from app.utils.cache import cache

        cache.set_notify_state(key, datetime.now(timezone.utc).isoformat())

    @staticmethod
    def sender_key(report: dict[str, Any]) -> str:
        """聚合键：优先发件地址，取不到则用可注册域，再不行用文件名。"""
        raw = str(report.get("from") or "")
        m = _ADDR_RE.search(raw)
        if m:
            return ("addr:" + m.group(0)).lower()
        return "file:" + str(report.get("filename") or report.get("report_id") or "?")

    def notify_reports(self, reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """把值得提醒的报告推出去，返回**实际推送**的条目（供 GUI/日志展示）。"""
        if not self.enabled:
            return []
        pushed: list[dict[str, Any]] = []
        skipped_window = 0
        candidates = []
        for r in reports:
            if r.get("verdict") not in NOTIFY_VERDICTS:
                continue
            key = self.sender_key(r)
            if self._recently_notified(key):
                skipped_window += 1
                continue
            candidates.append((key, r))
        for key, r in candidates[: self.max_per_round]:
            title = f"{r.get('verdict')} {r.get('score')}｜钓鱼邮件分析"
            body = (f"发件人: {str(r.get('from') or '?')[:60]}\n"
                    f"主题: {str(r.get('subject') or '?')[:60]}")
            self._send(title, body)
            self._mark(key)
            pushed.append({"key": key, "verdict": r.get("verdict"), "score": r.get("score"),
                           "subject": r.get("subject"), "from": r.get("from"),
                           "report_id": r.get("report_id")})
        extra = len(candidates) - len(pushed)
        if extra > 0:
            # 超限只发一条汇总：既完成了"提醒"，又不会把桌面刷屏
            self._send("另有邮件需要关注", f"本轮还有 {extra} 封 MALICIOUS/SUSPICIOUS，详见看板")
            for key, _r in candidates[self.max_per_round:]:
                self._mark(key)      # 汇总也算提醒过，避免下一轮又刷一遍
        if skipped_window:
            log.debug("通知去重窗口内跳过 %d 封", skipped_window)
        return pushed
