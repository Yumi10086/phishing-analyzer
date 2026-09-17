"""邮箱取信 CLI：IMAP 只读拉取 -> 落 .eml -> 复用分析流水线。

独立成模块（而非塞进 ``app/cli.py``）是为了让 cli 保持"薄入口"，同时让取信逻辑
（连接、文件夹选择、增量游标、批量分析、汇总打印）能被单独测试与复用。

用法：
  python -m app.mailbox.fetch --list                    # 只看文件夹与邮件数
  python -m app.mailbox.fetch --folder INBOX --limit 50 # 取收件箱最近 50 封并分析
  python -m app.mailbox.fetch --folder Junk --since-date 01-Sep-2026
  python -m app.mailbox.fetch --folder INBOX --full     # 忽略游标，从头重扫
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.config import DATA_DIR, settings
from app.mailbox.imap_client import (
    DEFAULT_FOLDERS,
    DEFAULT_MAX_BYTES,
    FetchedMail,
    fetch_folder,
    folder_status,
    list_folders,
    save_mail,
)
from app.utils.cache import cache
from app.utils.logger import get_logger

log = get_logger(__name__)

DEFAULT_OUT_ROOT = DATA_DIR / "mailbox"


def cmd_list() -> int:
    from app.mailbox.imap_client import _client

    conn = _client()
    try:
        print(f"邮箱: {settings.mailbox_imap_user} @ {settings.mailbox_imap_host}:{settings.mailbox_imap_port}")
        for f in list_folders(conn):
            if not f.selectable:
                print(f"  [--] {f.name}  (不可选，仅分组)")
                continue
            st = folder_status(conn, f.raw)
            cursor = cache.get_mailbox_cursor(f.raw)
            seen = f"已同步至 UID {cursor['last_uid']}" if cursor else "未同步"
            print(f"  [OK] {f.name:20s} 共 {st.get('messages', '?'):>6} 封 | {seen}")
    finally:
        try:
            conn.logout()
        except Exception:  # noqa: BLE001
            pass
    return 0


def _sync_cursor(folder_raw: str, st: dict[str, int], cursor: dict | None) -> int:
    """决定起始 UID：UIDVALIDITY 变化则从头重扫（旧游标失效）。"""
    if not cursor:
        return 0
    if st.get("uidvalidity") and st["uidvalidity"] != cursor["uidvalidity"]:
        log.warning("文件夹 %s 的 UIDVALIDITY 变化（%s -> %s），游标作废，从头重扫",
                    folder_raw, cursor["uidvalidity"], st["uidvalidity"])
        return 0
    return int(cursor["last_uid"])


def resolve_since_uid(folder_raw: str, st: dict, cursor: dict | None, *,
                      use_cursor: bool) -> int:
    """取信起始 UID 的统一口径（GUI 与 CLI 都走这里，避免两套行为漂移）。

    ``use_cursor=False``（按日期区间 / 全量重扫 / 最新 N 封抽样）恒从 0 开始：这些模式
    要的是**明确的窗口/样本**，被同步游标截断就取不到——此前 CLI 的"按日期"仍套游标，
    而 GUI 已忽略游标，两边行为不一致（按日期回扫历史时 CLI 一封都取不到）。
    """
    if not use_cursor:
        return 0
    return _sync_cursor(folder_raw, st, cursor)


def advance_cursor(folder_raw: str, st: dict, cursor: dict | None, max_uid: int) -> None:
    """推进同步游标，**只前进不回退**。

    按日期回扫历史窗口时 max_uid 通常小于当前游标（窗口在游标之前），若照写就回退，
    下次"增量"会把已经分析过的邮件再下一遍。另外一封都没取到时（max_uid=0）不写，
    避免把游标清零。UIDVALIDITY 变化时旧游标本就作废，从 0 起算。
    """
    uidvalidity = st.get("uidvalidity")
    if not uidvalidity or max_uid <= 0:
        return
    prev = 0
    if cursor and cursor.get("uidvalidity") == uidvalidity:
        prev = int(cursor.get("last_uid") or 0)
    if max_uid > prev:
        cache.set_mailbox_cursor(folder_raw, uidvalidity, max_uid)


def cmd_fetch(args: argparse.Namespace) -> int:
    from app.mailbox.imap_client import _client, search_uids

    folders = args.folder or list(DEFAULT_FOLDERS)
    out_root = Path(args.out) if args.out else DEFAULT_OUT_ROOT
    conn = _client()
    total_written = total_skipped = 0
    fetched_dirs: list[Path] = []
    # **本次真正落盘的邮件**：只分析这些。此前是把目录下全部 .eml 重扫一遍——取 1 封也要
    # 分析几百封（实测单封 134ms、627 封串行 84s／8 进程 30s），且随邮箱线性变差。
    fetched_files: list[Path] = []
    # 明确给了日期窗口就是"按区间回扫"，不套同步游标（见 resolve_since_uid）
    from app.mailbox.imap_client import parse_date_arg

    try:
        args.since_date = parse_date_arg(getattr(args, "since_date", ""))
        args.until_date = parse_date_arg(getattr(args, "until_date", ""))
    except ValueError as exc:
        print(f"日期参数错误：{exc}")
        return 2
    date_window = bool(args.since_date or args.until_date)
    use_cursor = not (args.full or args.recent or date_window)
    try:
        available = {f.raw: f for f in list_folders(conn)}
        for folder in folders:
            raw_name = folder if folder in available else None
            if raw_name is None:
                # 允许用解码后的可读名指定（如「其他文件夹」）
                raw_name = next((f.raw for f in available.values() if f.name == folder), None)
            if raw_name is None:
                matches = [f for f in available.values() if folder.lower() in f.name.lower()]
                if len(matches) == 1:
                    raw_name = matches[0].raw
                else:
                    print(f"跳过：邮箱里没有文件夹 {folder!r}（用 --list 查看可用名）")
                    continue

            st = folder_status(conn, raw_name)
            cursor = None if (args.full or args.recent) else cache.get_mailbox_cursor(raw_name)
            since_uid = resolve_since_uid(raw_name, st, cursor, use_cursor=use_cursor)
            out_dir = out_root / raw_name.replace("/", "_")
            written = skipped = 0
            max_uid = since_uid

            for mail in fetch_folder(conn, raw_name, since_uid=since_uid,
                                     since_date=args.since_date, until_date=args.until_date,
                                     limit=args.limit,
                                     recent=args.recent,
                                     max_bytes=args.max_bytes, with_body=not args.headers_only):
                max_uid = max(max_uid, int(mail.uid))
                if mail.raw is None:
                    skipped += 1
                    print(f"  [跳过 UID {mail.uid}] {mail.skipped_reason} | {mail.subject[:60]}"
                          f" | {mail.size / 1048576:.1f}MB")
                    continue
                path = save_mail(mail, out_dir, index=written)
                written += 1
                fetched_files.append(path)      # 供"只分析本次新取到的"用（见下方 _analyze）
                if written % 25 == 0:
                    print(f"  ... {raw_name}: 已取 {written} 封")

            # --recent 是"只看最近几封"的抽样，推进游标会永久跳过中间那段，故不动它
            if not args.recent:
                advance_cursor(raw_name, st, cursor, max_uid)
            print(f"[{available[raw_name].name}] 取到 {written} 封，跳过 {skipped} 封 -> {out_dir}")
            total_written += written
            total_skipped += skipped
            if written:
                fetched_dirs.append(out_dir)
    finally:
        try:
            conn.logout()
        except Exception:  # noqa: BLE001
            pass

    print(f"\n合计取到 {total_written} 封（跳过 {total_skipped} 封）")
    if not total_written:
        print("本次没有新邮件，跳过分析（要重算历史结论请用 --analyze-only）")
        return 0
    if not args.no_analyze:
        return _analyze(fetched_files, root=out_root, offline=not args.online)
    return 0


def _enable_mailbox_profile() -> None:
    """把分析档位切到 mailbox（须在起分析子进程之前调用，spawn 会继承环境变量）。

    邮箱直读时服务商不给存储副本写 Authentication-Results，"缺认证头"是渠道形态而非
    风险证据（实测 54 封正常邮件里 33 封命中，是误报第一大来源）。
    """
    import os

    os.environ["ANALYSIS_PROFILE"] = "mailbox"


def analyze_new_files(files: list[Path], offline: bool,
                      quiet: bool = False) -> tuple[list[dict], list[Path]]:
    """分析给定邮件文件：跳过自己投递的信 -> 多进程分析 -> 父进程串行落盘。

    抽成独立函数供两条路径共用：一次性取信（``_analyze``）与**轮询式实时分析**
    （``app/mailbox/watch.py``，每轮只分析新到的几封）。返回 (报告列表, 被跳过的自寄文件)。

    自己投递的信不参与分析：它们不是钓鱼目标，且"自寄"形态会触发一批与伪装无关的
    启发式（服务商 CDN 链接、附件通用 MIME、缺认证头、QQ 号数字本地部分）。
    判据见 ``is_self_sent``——文件夹 + From/Sender/Return-Path 双判据。
    """
    from concurrent.futures import ProcessPoolExecutor, as_completed

    from app.mailbox.imap_client import is_self_sent, own_addresses
    from app.pipeline import analyze_batch_item
    from app.response.report import save_report

    skipped_self: list[Path] = []
    if settings.mailbox_skip_self_sent and files:
        own = own_addresses()
        keep: list[Path] = []
        for path in files:
            if is_self_sent(path.read_bytes(), own, folder=path.parent.name):
                skipped_self.append(path)
            else:
                keep.append(path)
        files = keep
    if not files:
        return [], skipped_self

    if not quiet:
        print()
        print("开始分析 {} 封（{}模式）...".format(
            len(files), "离线" if offline else "在线情报"))
    results: list[dict] = []
    # 抑制 spawn 子进程重执行"主模块文件"：由主脚本调用时（如 python scripts/xxx.py），
    # 子进程会把该脚本从头再跑一遍（重复建连/重复取信）；详见 app/utils/mproc.py
    from app.utils.mproc import suppress_spawn_main_reexec

    with suppress_spawn_main_reexec(), ProcessPoolExecutor(max_workers=min(8, len(files))) as ex:
        futures = {ex.submit(analyze_batch_item, (str(f), "", offline, True, "mailbox")): f
                   for f in files}
        for i, fut in enumerate(as_completed(futures), 1):
            try:
                results.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                log.warning("分析失败 %s: %s", futures[fut].name, exc)
            if not quiet and i % 25 == 0:
                print("  ... {}/{}".format(i, len(files)))
    # 报告落盘由父进程串行执行（cache.db 为 sqlite，多进程并发写会锁竞争）
    for report in results:
        save_report(report)
    return results, skipped_self


def _analyze(files: list[Path], root: Path, offline: bool) -> int:
    """分析指定邮件（打印完整汇总）。

    ``files`` 是**本次要分析的邮件**而不是目录：取信路径只传本次新落盘的那些，
    ``--analyze-only``（规则更新后重跑）才传本地全部 .eml。
    """
    _enable_mailbox_profile()
    from app.mailbox.reputation import rebuild as rebuild_history

    if not files:
        print("没有需要分析的邮件。")
        return 0
    # 取信后走**增量**：只计入台账里没有的新文件，不再把整个目录重扫一遍
    stats = rebuild_history(root, incremental=True)
    if stats.get("skipped"):
        note = "（输入未变，复用上次结果）"
    elif stats.get("processed", stats["files"]) < stats["files"]:
        note = "（增量：新计入 {} 封，其余已在台账中）".format(stats["processed"])
    else:
        note = "（首次全量）"
    print("[信任上下文] 往来历史{}: 本地共 {} 封，入站发件人 {} 条，标记自己投递 {} 条".format(
        note, stats["files"], stats["inbound"], stats["replied_marks"]))
    results, skipped_self = analyze_new_files(sorted(files), offline)
    if skipped_self:
        print()
        print("[自己投递] 跳过分析 {} 封（已发送文件夹或 From 命中本人地址；本地 .eml 仍保留在 data/mailbox）".format(len(skipped_self)))
    if not results:
        print("没有需要分析的邮件（其余均为自己投递）。")
        return 0

    order = {"MALICIOUS": 0, "SUSPICIOUS": 1, "SPAM": 2, "BENIGN": 3}
    results.sort(key=lambda r: (order.get(r["verdict"], 9), -r["score"]))
    print(f"\n分析完成 {len(results)} 封：")
    counts: dict[str, int] = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print("  " + " | ".join(f"{k} {v}" for k, v in sorted(counts.items(),
                                                           key=lambda kv: order.get(kv[0], 9))))

    flagged = [r for r in results if r["verdict"] in ("MALICIOUS", "SUSPICIOUS")]
    if flagged:
        print(f"\n需要关注的 {len(flagged)} 封：")
        for r in flagged[:25]:
            subj = str(r.get("subject", ""))[:52]
            print(f"  [{r['verdict']:10s} {r['score']:3d}] {subj}")
            top = [s["id"] for s in r.get("signals", [])][:4]
            if top:
                print(f"      信号: {', '.join(top)}")
    spam = [r for r in results if r["verdict"] == "SPAM"]
    if spam:
        print(f"\n（另有 {len(spam)} 封判为营销/垃圾 SPAM，不进人工队列）")
    return 0


def cmd_analyze_only(args: argparse.Namespace) -> int:
    """不连邮箱，直接分析本地已取到的目录（规则更新后重跑用）。"""
    root = Path(args.out) if args.out else DEFAULT_OUT_ROOT
    if not root.is_dir():
        print(f"目录不存在: {root}（先跑一次取信）")
        return 1
    dirs = [d for d in sorted(root.iterdir()) if d.is_dir()]
    if not dirs:
        print(f"{root} 下没有子目录")
        return 1
    files = sorted(f for d in dirs for f in d.glob("*.eml"))
    print("重跑本地目录: {}（共 {} 封）—— 这是显式全量重算，规则更新后用".format(
        ", ".join(d.name for d in dirs), len(files)))
    return _analyze(files, root=root, offline=not args.online)


def main() -> int:
    ap = argparse.ArgumentParser(description="IMAP 只读取信并分析（默认离线）")
    ap.add_argument("--list", action="store_true", help="只列出文件夹与邮件数，不取信")
    ap.add_argument("--analyze-only", action="store_true",
                    help="不连邮箱，只分析本地已取到的邮件（规则更新后重跑）")
    ap.add_argument("--folder", action="append", default=[],
                    help="要取的文件夹（可多次指定，默认 INBOX/Junk/Sent Messages）")
    ap.add_argument("--limit", type=int, default=0, help="每个文件夹最多下载 N 封（0=不限）")
    ap.add_argument("--recent", type=int, default=0,
                    help="只看最新的 N 封（抽样浏览用；不推进同步游标）")
    ap.add_argument("--since-date", default="", help="只取该日期之后的邮件（含当天），如 01-Sep-2026")
    ap.add_argument("--until-date", default="",
                    help="取到该日期为止（**含当天**），如 15-Sep-2026；"
                         "与 --since-date 合用即闭区间（GUI 的日历选择器走同一条路）")
    ap.add_argument("--full", action="store_true", help="忽略同步游标，从头重扫")
    ap.add_argument("--headers-only", action="store_true",
                    help="只取头部（快速看有什么，不下载正文与附件）")
    ap.add_argument("--max-bytes", type=int, default=None, help="单封下载上限（默认取配置）")
    ap.add_argument("--out", default="", help=f"输出目录（默认 {DEFAULT_OUT_ROOT}）")
    ap.add_argument("--online", action="store_true",
                    help="启用在线情报查询（会把邮件中的 IOC 发给第三方平台，需自行确认授权）")
    ap.add_argument("--no-analyze", action="store_true", help="只取信不分析")
    ap.add_argument("--export-labels", action="store_true",
                    help="导出人工标注集到 data/labeled/（先分析并在 GUI 里标注）")
    ap.add_argument("--watch", action="store_true",
                    help="轮询模式：每 --interval 秒取一次新邮件并自动分析（Ctrl+C 退出）")
    ap.add_argument("--interval", type=int, default=60,
                    help="轮询间隔秒数（默认 60，最小 15）")
    ap.add_argument("--bell", action="store_true", help="轮询模式下发现可疑/恶意邮件时响铃")
    ap.add_argument("--notify", action="store_true",
                    help="轮询模式下把 MALICIOUS/SUSPICIOUS 推成桌面通知"
                         "（跨平台：Windows PowerShell Toast / macOS 通知中心 / Linux notify-send；"
                         "零额外依赖，失败只记日志不影响分析）")
    ap.add_argument("--notify-window", type=int, default=12,
                    help="同一发件人的通知去重窗口（小时，默认 12；0=不去重）")
    args = ap.parse_args()
    if args.max_bytes is None:
        args.max_bytes = settings.mailbox_max_bytes or DEFAULT_MAX_BYTES

    if args.watch:
        from app.mailbox.watch import run_watch

        folders = args.folder or list(DEFAULT_FOLDERS)
        interval = max(15, int(args.interval))       # 最小 15s，避免把邮箱当靶子打
        # 桌面通知挂在 on_round 回调上（与 GUI 的监控共用同一套去重/限流）
        notifier = None
        if args.notify:
            from app.response.notify import Notifier

            notifier = Notifier(enabled=True, window_hours=args.notify_window)
            print(f"桌面通知：已启用（同一发件人 {args.notify_window}h 内只提醒一次）")

        def _on_round(info: dict) -> None:
            if notifier is not None and info.get("reports"):
                pushed = notifier.notify_reports(info["reports"])
                if pushed:
                    print(f"      已推送 {len(pushed)} 条桌面通知", flush=True)

        try:
            return run_watch(folders, interval, offline=not args.online, bell=args.bell,
                             on_round=_on_round if notifier is not None else None)
        except KeyboardInterrupt:
            print()
            print("已停止轮询。")
            return 0

    if args.export_labels:
        from app.config import DATA_DIR
        from app.mailbox.labels import export as export_labels

        counts = export_labels(DATA_DIR / "mailbox", DATA_DIR / "labeled")
        print(f"标注集已导出到 {DATA_DIR / 'labeled'}：正常 {counts['benign']} 封 / "
              f"钓鱼 {counts['phishing']} 封（未标注跳过 {counts['skipped']} 封）")
        print("下一步：python scripts/eval_labels.py --simulate")
        return 0
    if args.list:
        return cmd_list()
    if args.analyze_only:
        return cmd_analyze_only(args)
    return cmd_fetch(args)


if __name__ == "__main__":
    sys.exit(main())
