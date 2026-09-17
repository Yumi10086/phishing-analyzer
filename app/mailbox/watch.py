"""轮询式实时分析：每隔 N 秒取一次新邮件并自动分析。

为什么用轮询而不是 IMAP IDLE：现有增量取信（UID 游标 + UIDVALIDITY 失效重扫 + 大小门控 +
自寄过滤）已经过真实邮箱实测，轮询直接复用、零协议风险；IDLE 需要自己实现 raw 收发
（imaplib 无原生支持）、29 分钟超时重连与保活，属另一轮工程。延迟 = ``--interval``（默认 60s）。

**关键保证：分析成功才推进游标。** 取信与写游标被刻意拆开——若先写游标再分析，一旦分析
失败（进程崩、磁盘满、在线情报超时），这些邮件就永久跳过了（游标已过、不会重取）。

用法：
  python -m app.mailbox.fetch --watch --interval 60 --folder INBOX --folder Junk
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable

from app.config import DATA_DIR, settings
from app.utils.logger import get_logger

log = get_logger(__name__)

# 单轮最多下载多少封（防止积压时一次性拉爆；剩下的下一轮继续）
ROUND_LIMIT = 200


def watch_once(conn: Any, folders_raw: list[str], out_root: Path,
               max_bytes: int, limit: int = ROUND_LIMIT) -> tuple[list[Path], dict[str, dict[str, int]]]:
    """取一轮新邮件（**不写游标**）。

    返回 ``(新落盘文件, {folder_raw: {uidvalidity, last_uid}})``；游标由调用方在分析成功
    之后写入（见模块说明）。已处理过的邮件由 UID 游标天然排除，不会重复取。
    """
    from app.mailbox.fetch import _sync_cursor
    from app.mailbox.imap_client import fetch_folder, folder_status, save_mail
    from app.utils.cache import cache

    new_files: list[Path] = []
    pending: dict[str, dict[str, int]] = {}
    for raw_name in folders_raw:
        status = folder_status(conn, raw_name)
        cursor = cache.get_mailbox_cursor(raw_name)
        since_uid = _sync_cursor(raw_name, status, cursor)
        out_dir = out_root / raw_name.replace("/", "_")
        written = 0
        max_uid = since_uid
        # 文件名序号接着已有文件排，避免覆盖（save_mail 的 index 只用于命名唯一）
        index = len(list(out_dir.glob("*.eml"))) if out_dir.is_dir() else 0
        for mail in fetch_folder(conn, raw_name, since_uid=since_uid, limit=limit,
                                 max_bytes=max_bytes):
            if mail.raw is None:            # 超限/取空：跳过但推进游标，否则每轮都重试同一封
                max_uid = max(max_uid, int(mail.uid))
                log.info("[%s] 跳过 UID %s（%s）", raw_name, mail.uid, mail.skipped_reason)
                continue
            # 同一 UID 已落盘过就直接复用（文件名里带 UID）：分析失败重试时不会重复写盘，
            # 也不会因为序号基数变化堆出同内容不同名的副本（实测踩过：一轮重试多出 200 份）
            existing = next(out_dir.glob("*_uid{}_*".format(mail.uid)), None) if out_dir.is_dir()                 else None
            if existing is not None:
                new_files.append(existing)
            else:
                new_files.append(save_mail(mail, out_dir, index=index + written))
                written += 1
            max_uid = max(max_uid, int(mail.uid))
        if status.get("uidvalidity"):
            pending[raw_name] = {"uidvalidity": int(status["uidvalidity"]), "last_uid": max_uid}
    return new_files, pending


def analyze_and_advance(files: list[Path], pending: dict[str, dict[str, int]],
                        offline: bool) -> list[dict[str, Any]]:
    """分析本轮新邮件；**全部分析成功后**才推进游标。

    失败时既不推进游标也不向上抛：下一轮会重新取到同一批再试（幂等，代价是重复下载）。
    相比"永久漏掉一封钓鱼邮件"，重复下载这个代价可以接受。
    """
    from app.mailbox.fetch import analyze_new_files
    from app.utils.cache import cache

    if not files:
        for raw_name, cur in pending.items():
            cache.set_mailbox_cursor(raw_name, cur["uidvalidity"], cur["last_uid"])
        return []
    results, _skipped = analyze_new_files(files, offline, quiet=True)
    if len(results) < len(files):
        log.warning("本轮有 %d 封分析失败，游标不推进（下轮重试）", len(files) - len(results))
        return results
    for raw_name, cur in pending.items():
        cache.set_mailbox_cursor(raw_name, cur["uidvalidity"], cur["last_uid"])
    return results


def run_watch(folders_raw: list[str], interval: int, offline: bool, out_root: Path | None = None,
              max_bytes: int | None = None, trust_rebuild: bool = True,
              connect: Callable[[], Any] | None = None, sleep: Callable[[float], None] = time.sleep,
              max_rounds: int = 0, bell: bool = False, quiet: bool = False,
              on_round: Callable[[dict[str, Any]], None] | None = None,
              should_stop: Callable[[], bool] | None = None) -> int:
    """轮询主循环。``connect``/``sleep``/``max_rounds`` 可注入，便于离线单测。

    ``on_round(info)`` 每轮结束时回调一次（info: 轮次/新邮件数/报告列表/是否出错），
    **通知出口与 GUI 都挂在这里**——不要在循环里再写第二套推送逻辑。
    ``should_stop()`` 返回真则退出循环（GUI 的停止按钮用）。
    ``quiet=True`` 不打印（GUI 后台线程里打印会污染页面）。
    """
    from app.mailbox.imap_client import _client, list_folders
    from app.mailbox.reputation import rebuild as rebuild_history

    out_root = out_root or (DATA_DIR / "mailbox")
    max_bytes = max_bytes or settings.mailbox_max_bytes
    connect = connect or _client

    def _say(line: str) -> None:
        if not quiet:
            print(line, flush=True)

    _say("实时分析已启动：文件夹 {}，间隔 {}s，模式 {}，Ctrl+C 退出".format(
        ", ".join(folders_raw), interval, "离线" if offline else "在线情报"))
    if trust_rebuild:
        stats = rebuild_history(out_root, incremental=True)
        _say("[信任上下文] 往来历史{}: 本地 {} 封，入站发件人 {} 条".format(
            "（输入未变，复用上次结果）" if stats.get("skipped")
            else "（增量：新计入 {} 封）".format(stats.get("processed", 0)),
            stats["files"], stats["inbound"]))

    conn: Any = None
    folders = list(folders_raw)
    rounds = 0
    while True:
        if should_stop is not None and should_stop():
            return 0
        rounds += 1
        info: dict[str, Any] = {"round": rounds, "files": 0, "reports": [], "error": ""}
        try:
            if conn is None:
                conn = connect()
                available = {f.raw for f in list_folders(conn)}
                missing = [f for f in folders_raw if f not in available]
                if missing:
                    print("警告：邮箱里没有这些文件夹，已跳过: {}".format(", ".join(missing)))
                folders = [f for f in folders_raw if f in available] or list(folders_raw)
            files, pending = watch_once(conn, folders, out_root, max_bytes)
            stamp = time.strftime("%H:%M:%S")
            info["files"] = len(files)
            if not files:
                _say("[{}] 无新邮件".format(stamp))
            else:
                results = analyze_and_advance(files, pending, offline)
                info["reports"] = results
                counts: dict[str, int] = {}
                for r in results:
                    counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
                summary = " | ".join("{} {}".format(k, v) for k, v in sorted(counts.items()))
                _say("[{}] 新邮件 {} 封 -> {}".format(stamp, len(files), summary or "（未产出报告）"))
                for r in results:
                    if r["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
                        _say("      [{} {:3d}] {}".format(r["verdict"], r["score"],
                                                          str(r.get("subject", ""))[:56]))
                        if bell:
                            print(chr(7), end="", flush=True)
            # 只有**本轮真的落了新邮件**才重建往来历史：空轮次的输入与上一轮完全相同，
            # 重建（597 封实测 2.5~3.4s）纯属白扫——按 60s 间隔算一天能白烧一个多小时，
            # 且随邮箱增长线性变差。语义上可证等价：没有新文件，历史必然一模一样。
            if trust_rebuild and files:
                rebuild_history(out_root, incremental=True)
        except KeyboardInterrupt:
            raise
        except Exception as exc:  # noqa: BLE001 — 长驻进程必须自愈：断线/超时/授权码失效
            info["error"] = f"{type(exc).__name__}: {exc}"
            log.warning("本轮失败（将重连后重试）：%s: %s", type(exc).__name__, exc)
            _say("警告：{}: {}（重连中）".format(type(exc).__name__, exc))
            try:
                if conn is not None:
                    conn.logout()
            except Exception:  # noqa: BLE001
                pass
            conn = None
        finally:
            if on_round is not None:
                try:
                    on_round(info)
                except Exception as exc:  # noqa: BLE001 - 回调（推送/UI）失败不影响监控
                    log.warning("on_round 回调失败（已忽略）: %s", exc)
        if max_rounds and rounds >= max_rounds:
            return 0
        sleep(interval)
