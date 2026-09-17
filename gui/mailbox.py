"""邮箱取信分析：IMAP 只读取信 -> 复用分析流水线 -> 结果矩阵与报告查看。

随 `streamlit run dashboard.py` 作为多页应用的一页加载。

设计上的几条硬约束（与 CLI `python -m app.mailbox.fetch` 完全一致，共用同一套实现）：
  - **只读**：`select(readonly=True)` + `BODY.PEEK[]`，不标已读、不动标志位、不删除；
  - **增量**：按 UID 取信并记录 UIDVALIDITY，游标存 cache.db，避免每次全量重下；
  - **默认离线**：个人邮箱属未脱敏生产邮件，勾选后才把 IOC 发往第三方情报平台；
  - **自己投递的信不分析**：本人发出的邮件不是钓鱼目标，且自寄形态会触发一批与
    "伪装"无关的启发式（服务商 CDN 链接、附件通用 MIME、缺认证头、QQ 号数字本地部分）。
页面只做"发起 + 展示"，取信与分析逻辑一律调用 `app.mailbox.*`，避免 GUI 与 CLI 两套口径漂移。
"""
from __future__ import annotations

import sys
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings  # noqa: E402
from app.mailbox.imap_client import to_imap_date  # noqa: E402
from app.scoring.rule_loader import get_rule_engine  # noqa: E402
from app.ui import hud_header, sidebar_status, verdict_badge  # noqa: E402

_engine = get_rule_engine()
sidebar_status(_engine.version, len(_engine.rules))

_VERDICT_COLOR = {"MALICIOUS": "#ef4444", "SUSPICIOUS": "#f97316",
                  "SPAM": "#a3a3a3", "BENIGN": "#22c55e"}
_ORDER = {"MALICIOUS": 0, "SUSPICIOUS": 1, "SPAM": 2, "BENIGN": 3}

hud_header("MAILBOX // 邮箱取信分析", "邮箱取信分析",
           "IMAP 只读取信 → 落 .eml → 复用分析流水线；不标已读、不动标志位、不删除。")

# ---------------------------------------------------------------- 凭据与连接
configured = bool(settings.mailbox_imap_user and settings.mailbox_imap_auth_code)
if not configured:
    st.warning(
        "未配置邮箱凭据。请在项目根目录的 `.env` 里填写：\n\n"
        "```\nMAILBOX_IMAP_HOST=imap.qq.com\nMAILBOX_IMAP_PORT=993\n"
        "MAILBOX_IMAP_USER=你的邮箱地址\n"
        "MAILBOX_IMAP_AUTH_CODE=16位授权码\n"
        "MAILBOX_OWN_ADDRESSES=你的其它地址（可选，逗号分隔）\n```\n\n"
        "QQ 邮箱的授权码在「设置 → 账户 → 开启 IMAP/SMTP 服务」生成（短信验证），"
        "**不是登录密码**。"
    )
    st.stop()

c1, c2, c3 = st.columns([3, 1, 1])
c1.markdown(f"**ACCOUNT** `{settings.mailbox_imap_user}` @ "
            f"`{settings.mailbox_imap_host}:{settings.mailbox_imap_port}`")
if c2.button("TEST // 测试连接", width="stretch"):
    with st.spinner("连接中…"):
        try:
            from app.mailbox.imap_client import _client
            conn = _client()
            conn.logout()
            st.session_state["mb_ok"] = "连接成功，已登录（只读取信）"
        except Exception as exc:  # noqa: BLE001
            st.session_state["mb_ok"] = f"连接失败：{type(exc).__name__}: {exc}"
if st.session_state.get("mb_ok"):
    (st.success if st.session_state["mb_ok"].startswith("连接成功") else st.error)(
        st.session_state["mb_ok"])

# ---------------------------------------------------------------- 文件夹与进度
st.divider()
hud_header("FOLDERS", "文件夹与同步进度", "显示每个文件夹的邮件数与已同步到的 UID")

if st.button("REFRESH // 刷新文件夹", type="primary"):
    with st.spinner("读取文件夹…"):
        try:
            from app.mailbox.imap_client import _client, folder_status, list_folders
            from app.utils.cache import cache

            conn = _client()
            try:
                rows = []
                for f in list_folders(conn):
                    if not f.selectable:
                        continue
                    stt = folder_status(conn, f.raw)
                    cur = cache.get_mailbox_cursor(f.raw)
                    rows.append({
                        "文件夹": f.name,
                        "邮件数": stt.get("messages", 0),
                        "已同步至 UID": cur["last_uid"] if cur else None,
                        "上次同步": (cur or {}).get("last_sync", "")[:19].replace("T", " ") or "未同步",
                        "_raw": f.raw,
                    })
                st.session_state["mb_folders"] = rows
            finally:
                try:
                    conn.logout()
                except Exception:  # noqa: BLE001
                    pass
        except Exception as exc:  # noqa: BLE001
            st.error(f"读取文件夹失败：{type(exc).__name__}: {exc}")

folders = st.session_state.get("mb_folders") or []
if folders:
    st.dataframe(pd.DataFrame(folders).drop(columns=["_raw"]),
                 width="stretch", hide_index=True)
else:
    st.info("点击 REFRESH 读取邮箱文件夹（只读操作，不会改变邮箱任何状态）")

# ---------------------------------------------------------------- 取信参数
st.divider()
hud_header("FETCH", "取信参数", "取到的邮件落在 data/mailbox/<文件夹>/，可随时用现有报告页回看")

names = [f["文件夹"] for f in folders]
name_to_raw = {f["文件夹"]: f["_raw"] for f in folders}
default_sel = [n for n in ("INBOX", "Junk") if n in names] or names[:1]

col_a, col_b = st.columns([2, 2])
with col_a:
    picked = st.multiselect("FOLDERS // 要取信的文件夹", names, default=default_sel)
    mode = st.radio("RANGE // 取信范围", ["增量（从上次游标继续）", "最新 N 封（不动游标）",
                                       "按日期区间", "全量重扫"], horizontal=False)
with col_b:
    limit = st.number_input("LIMIT // 本次最多下载封数（0=不限，防误触频率限制）",
                            min_value=0, max_value=50000, value=100)
    recent_n = st.number_input("RECENT // “最新 N 封”模式下的 N", min_value=1,
                               max_value=5000, value=50, disabled=(mode != "最新 N 封（不动游标）"))
    # 日历区间选择器：点开就是月历，选"从哪天到哪天"（含两端）。此前是手填
    # SINCE DATE 文本框——格式写错就静默取不到东西，而且只有下界没有上界。
    today = date.today()
    date_range = st.date_input(
        "DATE RANGE // 取信日期区间（含两端，点开日历选起止两天）",
        value=(today - timedelta(days=30), today),
        max_value=today,
        format="YYYY-MM-DD",
        disabled=(mode != "按日期区间"),
        help="只按服务端日期（INTERNALDATE）过滤，与 UID 游标无关：回扫历史窗口"
             "不影响“增量”的进度，游标只前进不回退。只选一天 = 取该日一天。")
    max_mb = st.number_input("MAX SIZE // 单封下载上限（MB，超限不下正文）",
                            min_value=1, max_value=200, value=max(1, settings.mailbox_max_bytes // 1048576))

# 区间两端 -> IMAP 的 DD-Mon-YYYY；结束日 +1 天（IMAP 的 BEFORE 不含当天）
_range = date_range if isinstance(date_range, (tuple, list)) else (date_range, date_range)
if len(_range) == 2 and all(_range):
    since_date = to_imap_date(_range[0])
    until_date = to_imap_date(_range[1])          # 含当天；+1 的排他换算在 search_uids 里
    date_span = f"{_range[0]:%Y-%m-%d} ~ {_range[1]:%Y-%m-%d}"
else:
    # 用户只点了区间里的一天（Streamlit 的中间态）：当作"从那一天起"，等他点完第二天
    since_date = to_imap_date(_range[0]) if _range[0] else ""
    until_date = ""
    date_span = f"{_range[0]:%Y-%m-%d} 起（结束日未选）" if _range[0] else ""
if mode == "按日期区间" and date_span:
    st.caption(f"取信区间：**{date_span}**　—　共 {(int(limit) or 0) if limit else '不限'} 封上限；"
               f"服务端筛选条件 SINCE {since_date or '-'}"
               f"{f' BEFORE {to_imap_date(_range[1] + timedelta(days=1))}' if until_date else ''}")

offline = st.checkbox("OFFLINE MODE（离线，不查威胁情报）", value=True,
                      help="个人邮箱属未脱敏生产邮件。取消勾选会把邮件中的 URL/域名/附件哈希"
                           "发往 VT/URLScan，请自行确认授权。")
skip_self = st.checkbox("SKIP SELF-SENT // 自己投递的信不参与分析", value=settings.mailbox_skip_self_sent,
                        help="本人发出的邮件不是钓鱼目标；本地 .eml 仍保留，只是不进分析。"
                             "判定依据：来自已发送文件夹，或 From/Sender/Return-Path 命中本人地址")
own_preview = []
if skip_self:
    from app.mailbox.imap_client import own_addresses
    own_preview = sorted(own_addresses())
    st.caption(f"本人地址清单：{'、'.join(own_preview) or '（未配置，仅按文件夹判定）'}"
               f"　—　其它地址请在 `.env` 的 `MAILBOX_OWN_ADDRESSES` 中补充")

# ---------------------------------------------------------------- 执行取信 + 分析
st.divider()
hud_header("ENGAGE", "执行", "取信与分析分离：先落 .eml，再交给现有流水线（与手工上传同一口径）")

b1, b2 = st.columns([1, 1])
run_fetch = b1.button("ENGAGE // 取信并分析", type="primary", width="stretch")


def _fetch_selected() -> tuple[list[Path], int, int]:
    """按页面参数取信。返回 (落盘目录列表, 成功封数, 跳过封数)。"""
    from app.config import DATA_DIR
    from app.mailbox.fetch import advance_cursor, resolve_since_uid
    from app.mailbox.imap_client import _client, fetch_folder, folder_status, save_mail
    from app.utils.cache import cache

    conn = _client()
    dirs: list[Path] = []
    # 本次真正落盘的邮件：取信后**只分析这些**（此前是把目录下全部 .eml 重扫一遍，
    # 取 1 封也要分析几百封：单封 134ms、627 封 8 进程约 30s 且随邮箱线性变差）
    fetched_files: list[Path] = []
    written_total = skipped_total = 0
    try:
        out_root = DATA_DIR / "mailbox"
        use_recent = mode == "最新 N 封（不动游标）"
        date_mode = mode == "按日期区间"
        for name in picked:
            raw_name = name_to_raw.get(name, name)
            stt = folder_status(conn, raw_name)
            cursor = None if (mode == "全量重扫" or use_recent) else cache.get_mailbox_cursor(raw_name)
            # 游标口径与 CLI 共用一套（resolve_since_uid）：只有"增量"用游标，
            # 按日期区间/全量/抽样都从 0 开始——被游标截断就取不到历史窗口。
            since_uid = resolve_since_uid(raw_name, stt, cursor, use_cursor=mode.startswith("增量"))
            if cursor and not mode.startswith("增量") and stt.get("uidvalidity") \
                    and stt["uidvalidity"] != cursor["uidvalidity"]:
                st.warning(f"{name}：UIDVALIDITY 变化，游标作废，下次增量会从头重扫")

            out_dir = out_root / raw_name.replace("/", "_")
            progress = st.progress(0.0, text=f"{name}：准备取信…")
            written = skipped = 0
            max_uid = since_uid
            # 先数一遍要取多少封，用于进度条
            total_hint = limit or recent_n or stt.get("messages", 0)
            for mail in fetch_folder(conn, raw_name, since_uid=since_uid,
                                    since_date=(since_date if date_mode else ""),
                                    until_date=(until_date if date_mode else ""),
                                    limit=int(limit), recent=(int(recent_n) if use_recent else 0),
                                    max_bytes=int(max_mb) * 1048576):
                max_uid = max(max_uid, int(mail.uid))
                if mail.raw is None:
                    skipped += 1
                    continue
                fetched_files.append(save_mail(mail, out_dir, index=written))
                written += 1
                if total_hint:
                    progress.progress(min(1.0, written / total_hint),
                                      text=f"{name}：已取 {written} 封")
            progress.progress(1.0, text=f"{name}：取到 {written} 封（跳过 {skipped} 封）")
            if not use_recent:
                advance_cursor(raw_name, stt, cursor, max_uid)
            if written:
                dirs.append(out_dir)
            written_total += written
            skipped_total += skipped
    finally:
        try:
            conn.logout()
        except Exception:  # noqa: BLE001
            pass
    return dirs, fetched_files, written_total, skipped_total


def _analyze_dirs(files: list[Path], root: Path, offline_mode: bool,
                  skip_self_sent: bool) -> None:
    """分析指定邮件（父进程串行落盘报告，多进程只做分析）。

    ``files`` 是**本次要分析的邮件**而不是目录：取信路径只传本次新落盘的，
    「重跑本地已取邮件」才传本地全部 .eml。
    """
    from concurrent.futures import ProcessPoolExecutor, as_completed

    from app.mailbox.fetch import _enable_mailbox_profile
    from app.mailbox.imap_client import is_self_sent, own_addresses
    from app.pipeline import analyze_batch_item
    from app.response.report import save_report
    from app.ui import suppress_spawn_main_reexec

    # 档位须在起子进程之前设置（spawn 继承环境变量）：邮箱直读时"缺认证头"是渠道形态
    _enable_mailbox_profile()
    from app.mailbox.reputation import rebuild as rebuild_history

    hstats = rebuild_history(root, incremental=True)
    _verb = ("复用（输入未变，跳过重扫）" if hstats.get("skipped")
             else "增量更新（新计入 {} 封）".format(hstats.get("processed", 0)))
    st.caption(f"信任上下文：往来历史{_verb}（本地共 {hstats['files']} 封，"
               f"入站发件人 {hstats['inbound']} 条，'你写过信' {hstats['replied_marks']} 条）")
    files = sorted(files)
    skipped_self: list[str] = []
    if skip_self_sent:
        own = own_addresses()
        keep = []
        for p in files:
            if is_self_sent(p.read_bytes(), own, folder=p.parent.name):
                skipped_self.append(p.name)
            else:
                keep.append(p)
        files = keep
    st.session_state["mb_skipped_self"] = skipped_self

    if not files:
        st.warning("没有需要分析的邮件（其余均为自己投递或目录为空）。")
        return
    progress = st.progress(0.0, text=f"分析 0/{len(files)}")
    results: list[dict] = []
    errors: list[tuple[str, str]] = []
    # spawn 子进程会把**本页面文件**当主模块重执行一遍（整页 bare 模式渲染，实测单次分析
    # 1089 条 missing ScriptRunContext 警告）；用抑制窗口避免这次无谓的重复执行
    with suppress_spawn_main_reexec():
        with ProcessPoolExecutor(max_workers=8) as ex:
            futures = {ex.submit(analyze_batch_item,
                                 (str(p), "", offline_mode, True, "mailbox")): p
                       for p in files}
            for i, fut in enumerate(as_completed(futures), 1):
                try:
                    results.append(fut.result())
                except Exception as exc:  # noqa: BLE001
                    errors.append((futures[fut].name, f"{type(exc).__name__}: {exc}"))
                progress.progress(i / len(files), text=f"分析 {i}/{len(files)}")
    for r in results:
        save_report(r)
    st.session_state["mb_results"] = sorted(
        results, key=lambda r: (_ORDER.get(r["verdict"], 9), -r["score"]))
    st.session_state["mb_errors"] = errors


if run_fetch:
    if not picked:
        st.warning("请先选择要取信的文件夹")
    else:
        try:
            dirs, new_files, written, skipped = _fetch_selected()
            st.success(f"取信完成：新增 {written} 封，跳过（超限/空响应）{skipped} 封")
            if new_files:
                _analyze_dirs(new_files, Path("data/mailbox"), offline, skip_self)
            else:
                st.info("本次没有取到新邮件，跳过分析（增量游标已是最新）。"
                        "要按新规则重算历史结论，用下面的「重跑本地已取邮件」。")
        except Exception as exc:  # noqa: BLE001
            st.error(f"取信失败：{type(exc).__name__}: {exc}")

if b2.button("REANALYZE // 重跑本地已取邮件", width="stretch",
             help="不连邮箱，直接分析 data/mailbox 下已有的 .eml（改完规则后用）"):
    root = Path("data/mailbox")
    dirs = [d for d in sorted(root.iterdir()) if d.is_dir()] if root.is_dir() else []
    all_files = sorted(p for d in dirs for p in d.glob("*.eml"))
    if not all_files:
        st.warning("data/mailbox 下没有已取到的邮件，请先取信")
    else:
        with st.spinner(f"全量重算本地 {len(all_files)} 封 …"):
            _analyze_dirs(all_files, root, offline, skip_self)

# ---------------------------------------------------------------- 实时监控
st.divider()
hud_header("WATCH", "实时监控", "轮询取信 → 自动分析 → 桌面通知；与 CLI 的 --watch 共用同一套实现"
                              "（分析成功才推进游标、断线自愈、空轮次不重建往来历史）")

from app.mailbox.service import monitor as _monitor  # noqa: E402
from app.response.notify import desktop_notify  # noqa: E402

_m: object = _monitor()

w1, w2, w3 = st.columns([2, 2, 2])
with w1:
    watch_interval = st.number_input("INTERVAL // 轮询间隔（秒，最小 15）",
                                     min_value=15, max_value=3600, value=60,
                                     help="延迟 = 间隔；IMAP IDLE 真推送待做（见开发文档待办）")
    watch_notify = st.checkbox("NOTIFY // 桌面通知（只推 MALICIOUS/SUSPICIOUS）", value=True,
                               help="跨平台零依赖：Windows PowerShell Toast / macOS 通知中心 / "
                                    "Linux notify-send；发送失败只记日志，不影响分析")
    watch_window = st.number_input("去重窗口（小时）", min_value=0, max_value=168, value=12,
                                   help="同一发件人 N 小时内只提醒一次（0=不去重）。"
                                        "不做去重的话，营销邮件会把人吵到关掉通知")
with w2:
    if _m.running():
        st.success("监控中")
        if st.button("STOP // 停止监控", width="stretch"):
            _m.stop()
            st.rerun()
    else:
        st.info("未启动")
        if not picked:
            st.caption("先点上面的 **TEST // 测试连接**（或 REFRESH）加载文件夹，"
                       "再选择要监控的文件夹——START 才会可用。")
        if st.button("START // 启动监控", type="primary", width="stretch",
                     disabled=not picked, help="按上面的「取信范围」选中的文件夹轮询"):
            _m.start(picked and [name_to_raw.get(n, n) for n in picked] or ["INBOX"],
                     int(watch_interval), offline=offline, notify=bool(watch_notify),
                     window_hours=int(watch_window))
            st.rerun()
with w3:
    if st.button("CHECK NOW // 立即检查一次", width="stretch",
                 help="同步跑一轮（取信 + 分析 + 通知），不必等间隔"):
        with st.spinner("检查中…"):
            _m.check_once(picked and [name_to_raw.get(n, n) for n in picked] or ["INBOX"],
                          offline=offline, notify=bool(watch_notify),
                          window_hours=int(watch_window))
    if st.button("TEST // 发一条测试通知", width="stretch"):
        ok = desktop_notify("Phishing Analyzer 测试通知", "看到这条说明桌面通知通道可用")
        (st.success if ok else st.warning)("已发送" if ok else "发送失败（见日志）")

st.caption("⚠️ 这个监控随 Streamlit 进程存活：页面服务重启就停了。要长期常驻请用 CLI "
           "`python -m app.mailbox.fetch --watch --notify` 并交给系统服务管理"
           "（Windows 任务计划/NSSM、systemd、容器 sidecar）。")


def _watch_panel() -> None:
    """状态 + 最近告警。放在 fragment 里定时自刷新（5s），不用手点刷新。"""
    st_ = _m.status()
    m1, m2, m3, m4 = st.columns(4)
    # border=True：与「分析结果」区的 KPI 卡片同一形态（裸 metric 无边框、高度不齐会错位）
    m1.metric("ROUNDS / 轮次", st_["rounds"], border=True)
    m2.metric("NEW MAILS / 新邮件", st_["new_mails"], border=True)
    m3.metric("PUSHED / 已推送", st_["pushed"], border=True)
    m4.metric("LAST / 最后检查", st_["last_round_at"] or "—", border=True)
    if st_["last_error"]:
        st.warning(f"最近一轮出错（会自动重连）：{st_['last_error']}")
    if st_["alerts"]:
        import pandas as _pd

        st.markdown("**最近告警（MALICIOUS / SUSPICIOUS）**")
        st.dataframe(_pd.DataFrame(list(reversed(st_["alerts"]))), width="stretch",
                     hide_index=True)
    with st.expander(f"运行日志（最近 {len(st_['log'])} 行）", expanded=False):
        st.code(chr(10).join(st_["log"][-60:]) or "（暂无）", language="text")


try:
    st.fragment(run_every="5s")(_watch_panel)()
except Exception:  # noqa: BLE001 - 老版本 Streamlit 没有 fragment 时退化为静态展示
    _watch_panel()

# ---------------------------------------------------------------- 信任上下文
st.divider()
hud_header("TRUST", "信任上下文（往来历史）",
           "按「收过多少封 / 你是否回过信」给已建立往来的发件人降权话术类信号；硬信号永不动")
from app.scoring.trust import trust_context_enabled as _trust_on  # noqa: E402

tcol1, tcol2 = st.columns([1, 3])
if tcol1.button("REBUILD // 重建历史", width="stretch",
                help="扫描 data/mailbox 下的邮件重算往来历史（取信与分析时也会自动重建）"):
    from app.mailbox.reputation import rebuild as _rebuild

    stats = _rebuild(Path("data/mailbox"), clear=True, force=True)   # 手动按钮=显式重建
    st.success(f"历史已重建：扫描 {stats['files']} 封，入站发件人 {stats['inbound']} 条，"
               f"'你写过信' {stats['replied_marks']} 条")
tcol2.caption(f"当前档位下信任上下文{'**已启用**' if _trust_on() else '未启用（网关档位或 TRUST_CONTEXT=0）'}；"
              "`TRUST_CONTEXT=0` 可关闭做对照")

from app.utils.cache import cache as _cache  # noqa: E402

_senders = _cache.list_senders(300)
if _senders:
    import pandas as _pd  # noqa: E402

    with st.expander(f"SENDERS // 往来发件人（{len(_senders)} 条，按收件数排序）"):
        st.dataframe(_pd.DataFrame([{
            "发件地址": s["addr"], "域": s["domain"], "收过": s["count"],
            "你写过信": "是" if s["replied"] else "",
            "首次": (s["first_seen"] or "")[:10], "最近": (s["last_seen"] or "")[:10],
        } for s in _senders]), width="stretch", hide_index=True)
        st.caption("信任档位：回复过 → 直接「已建立」；否则域级 ≥5 封且跨度 ≥14 天 → 已建立；"
                   "地址 ≥2 封 → 已知（只降营销/结构类）。降权信号在报告里带 `trust_demoted` 标记。")
else:
    st.info("还没有往来历史：取信或点 REBUILD 后生成")

# ---------------------------------------------------------------- 结果
results = st.session_state.get("mb_results") or []
if results:
    st.divider()
    hud_header("RESULT", "分析结果", "与自己投递的信已排除；全部结论与手工上传口径一致")
    counts = Counter(r["verdict"] for r in results)
    n_total = len(results)
    # 与「看板首页」的 KPI 行保持同一写法：**border=True**（无边框时卡片与 HUD 主题错位，
    # 看起来"飘"在页面上）+ 中文标签与占比。两页样式必须一致，否则同一套主题下两种观感。
    # 列数与「看板首页」一致（TOTAL + 四档 + 平均分），两页 KPI 宽度也相同
    cols = st.columns(6)
    cols[0].metric("TOTAL / 本次分析", n_total, border=True)
    for i, (v, label) in enumerate((("MALICIOUS", "恶意"), ("SUSPICIOUS", "可疑"),
                                    ("SPAM", "垃圾"), ("BENIGN", "正常")), start=1):
        n = counts.get(v, 0)
        cols[i].metric(f"{v} {label} · {n / n_total * 100:.0f}%", n, border=True)
    cols[5].metric("AVG SCORE 平均分",
                   f"{sum(r['score'] for r in results) / n_total:.0f}", border=True)

    flagged = [r for r in results if r["verdict"] in ("MALICIOUS", "SUSPICIOUS")]
    badge = " ｜ ".join(f"{v} {counts[v]}" for v in
                        ("MALICIOUS", "SUSPICIOUS", "SPAM", "BENIGN") if counts.get(v))
    st.markdown(f"**需要关注 {len(flagged)} / {len(results)}**　{badge}")
    if not flagged:
        st.success("没有需要关注的邮件")

    filt = st.multiselect("FILTER // 只看", ["MALICIOUS", "SUSPICIOUS", "SPAM", "BENIGN"],
                          default=["MALICIOUS", "SUSPICIOUS"])
    shown = [r for r in results if r["verdict"] in filt]

    # 人工判定已迁到独立页「人工研判」（gui/label.py）：批量处置需要多选表格 + 批量表单 +
    # 标注列表三块 UI，塞在结果流里会把"取信 → 结果"主流程冲散、页面也被拉长
    st.caption("要标注「正常·营销 / 确认钓鱼」？用左侧栏的 **人工研判** 页（支持批量勾选处置与撤销）")

    if shown:
        table = pd.DataFrame([{
            "判定": r["verdict"],
            "分数": r["score"],
            "类别": r.get("category", ""),
            "主题": str(r.get("subject", ""))[:70],
            "发件人": str(r.get("from", ""))[:46],
            "信号数": len(r.get("signals", [])),
            "报告": r["report_id"],
        } for r in shown])
        st.dataframe(table, width="stretch", hide_index=True,
                     column_config={"分数": st.column_config.ProgressColumn(
                         "分数", min_value=0, max_value=100, format="%d")})

        sel = st.selectbox("REPORT // 查看报告明细",
                           [f"{r['verdict']} | {r['score']} | {str(r.get('subject',''))[:50]}"
                            f" | {r['report_id']}" for r in shown])
        if sel:
            rid = sel.rsplit("|", 1)[-1].strip()
            rec = next((r for r in shown if r["report_id"] == rid), None)
            if rec:
                st.markdown(verdict_badge(rec["verdict"]), unsafe_allow_html=True)
                # 三个块用 tab 平铺：早前三段竖向堆叠（依据列表 + 信号表 + 760px 报告 iframe）
                # 会把页面拉得很长，且报告 iframe 自带标题，视觉上像"另起一屏"（错位感来源）
                tb1, tb2, tb3 = st.tabs(["研判依据", "信号明细", "完整报告"])
                with tb1:
                    for reason in rec["reasons"][:14]:
                        st.markdown(f"- {reason}")
                with tb2:
                    sig_df = pd.DataFrame([{"规则": s["id"], "分值": s.get("points", ""),
                                            "说明": str(s.get("reason", ""))[:110]}
                                           for s in rec.get("signals", [])])
                    if sig_df.empty:
                        st.info("无信号")
                    else:
                        st.dataframe(sig_df, width="stretch", hide_index=True)
                with tb3:
                    html_path = Path("data/reports") / f"{rid}.html"
                    if html_path.is_file():
                        st.iframe(html_path, height=620)
                    else:
                        st.info("报告文件不存在")

    skipped_self = st.session_state.get("mb_skipped_self") or []
    if skipped_self:
        with st.expander(f"SKIPPED // 自己投递的信（{len(skipped_self)} 封未参与分析）"):
            st.caption("本人发出的邮件不是钓鱼目标；本地 .eml 仍保留在 data/mailbox/ 下。")
            for nm in skipped_self:
                st.markdown(f"- {nm}")

    errors = st.session_state.get("mb_errors") or []
    if errors:
        with st.expander(f"ERRORS // 失败明细（{len(errors)} 封）"):
            for nm, err in errors:
                st.markdown(f"- {nm}: {err}")
