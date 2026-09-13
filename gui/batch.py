"""批量分析：多文件上传 / 本地目录 -> 批量研判 -> 结果矩阵 + 报告查看 + IOC/CSV 导出。

随 `streamlit run dashboard.py` 作为多页应用的一页加载。
"""
from __future__ import annotations

import asyncio
import io
import sys
from collections import Counter
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.extractor.ioc_extractor import count_iocs  # noqa: E402
from app.pipeline import analyze_bytes  # noqa: E402
from app.scoring.rule_loader import get_rule_engine  # noqa: E402
from app.ui import (  # noqa: E402
    discover_cached, hud_header, pick_folder, resolve_folder, sidebar_status, verdict_badge,
)

_engine = get_rule_engine()
sidebar_status(_engine.version, len(_engine.rules))

hud_header("BATCH SCAN // 批量扫描矩阵", "批量分析",
           "解析 → IOC 提取 → 情报富化 → 评分 → 报告落盘；结果同步进入态势总览。")

mode = st.radio("INPUT MODE", ["上传文件", "本地目录"], horizontal=True,
                label_visibility="collapsed")
offline = st.checkbox("OFFLINE MODE（跳过威胁情报查询）", value=True)

_VERDICT_COLOR = {"MALICIOUS": "#ef4444", "SUSPICIOUS": "#f97316", "BENIGN": "#22c55e"}

# ---- 本地目录选择 ----
def _default_dir() -> str:
    """目录输入框的初始值：优先示例语料目录，否则留空。"""
    cand = Path("../phishing_pot-main/email")
    return str(cand) if cand.is_dir() else ""


def _on_browse_folder() -> None:
    """浏览按钮回调：弹出系统文件夹选择框并写回目标路径。

    必须走 on_click：脚本执行到按钮时，路径输入框已实例化，此时直接改它的
    session_state 会被 Streamlit 拒绝（StreamlitWidgetAlreadyInstantiatedError）；
    回调先于脚本重跑执行，没有这个限制，也不会弹出"点了没反应"的陈旧值问题。
    """
    chosen = pick_folder(st.session_state.get("dir_target", ""))
    if chosen:
        st.session_state["dir_target"] = str(chosen)
        st.session_state.pop("dir_pick_failed", None)
    else:
        st.session_state["dir_pick_failed"] = True


def _run_analysis(inputs: list[tuple[str, bytes]]) -> None:
    rows, reports, errors = [], [], []
    progress = st.progress(0.0, text="SCANNING…")
    for i, (name, raw) in enumerate(inputs, 1):
        progress.progress(i / len(inputs), text=f"SCANNING {i}/{len(inputs)} :: {name}")
        try:
            rep = asyncio.run(analyze_bytes(raw, filename=name, offline=offline))
            reports.append(rep)
            rows.append({
                "文件": name,
                "结论": rep["verdict"],
                "评分": rep["score"],
                "IOC数": count_iocs(rep["iocs"]),
                "耗时ms": rep["processing_time_ms"],
                "报告ID": rep["report_id"],
            })
        except Exception as exc:  # noqa: BLE001 - 单封失败不中断批量
            errors.append((name, str(exc)[:120]))
    progress.empty()
    st.success(f"SCAN COMPLETE // 完成 {len(rows)} 封，失败 {len(errors)} 封")
    st.session_state["batch_rows"] = rows
    st.session_state["batch_reports"] = reports
    st.session_state["batch_errors"] = errors


def _show_results() -> None:
    rows = st.session_state.get("batch_rows", [])
    reports = st.session_state.get("batch_reports", [])
    if not rows:
        return

    hud_header("SCAN RESULTS // 扫描结果", "扫描结果矩阵")
    df = pd.DataFrame(rows)

    def _color(val):
        return (f"color: {_VERDICT_COLOR.get(val, '#94A3B8')}; font-weight: 700; "
                f"text-shadow: 0 0 8px currentColor"
                if val in _VERDICT_COLOR else "")

    st.dataframe(df.style.map(_color, subset=["结论"]),
                 width='stretch', hide_index=True)

    vc = df["结论"].value_counts()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("MALICIOUS", int(vc.get("MALICIOUS", 0)), border=True)
    c2.metric("SUSPICIOUS", int(vc.get("SUSPICIOUS", 0)), border=True)
    c3.metric("BENIGN", int(vc.get("BENIGN", 0)), border=True)
    c4.metric("AVG LATENCY", f"{df['耗时ms'].mean():.0f}ms", border=True)

    # ---- 报告详情查看（内嵌 HTML 报告） ----
    hud_header("RECORD DETAIL // 报告详情", "报告详情")
    # 选择项用「下标」而不是 rows 里的 dict 对象。
    # 背景（真实缺陷）：此前直接把 rows（list[dict]）交给 selectbox，再按
    # selected["报告ID"] 去 reports 里回查。无 key 的 selectbox 会把**上一轮**的
    # option 对象原样返回，而本轮 report_id 是新 uuid，next(...) 必然查不到 ->
    # rep 为 None -> 详情块（含内嵌报告）整体不渲染，表现为"第二次点击后报告消失"。
    # 改用下标 + 固定 key，并把越界下标夹回 0，消除跨轮对象同一性问题。
    idx_key = "batch_selected_idx"
    n = len(rows)
    if not isinstance(st.session_state.get(idx_key), int) \
            or not 0 <= st.session_state[idx_key] < n:
        st.session_state[idx_key] = 0
    sel = st.selectbox(
        "SELECT RECORD", options=list(range(n)), key=idx_key,
        format_func=lambda i: f"[{rows[i]['结论']} {rows[i]['评分']:03d}] {rows[i]['文件']}")
    rep = reports[sel] if isinstance(sel, int) and 0 <= sel < len(reports) else None
    if rep:
        mode = "离线（未查情报）" if rep.get("offline") else "在线（已查情报）"
        st.markdown(f"{verdict_badge(rep['verdict'])} &nbsp; "
                    f"<span style='color:#E5F2FF;font-weight:700'>{rep['filename']}</span>"
                    f" &nbsp; <span style='color:#94A3B8'>{rep['score']} PTS · "
                    f"{rep['processing_time_ms']} ms · {mode}</span>",
                    unsafe_allow_html=True)
        with st.expander("REASONS // 研判依据", expanded=True):
            for reason in rep["reasons"]:
                st.markdown(f"- {reason}")
        html_path = Path(rep["report_files"]["html"])
        if html_path.is_file():
            # st.iframe 传 Path 时会读取本地 .html 并以内联 srcdoc 嵌入：
            # 报告自带全局 <style>（body/h1/table…），必须隔离在 iframe 里，
            # 否则会污染整个应用的样式。
            st.iframe(html_path, height=800)

    # ---- 导出 ----
    hud_header("EXPORT // 导出", "导出")
    buf = io.StringIO()
    df.to_csv(buf, index=False, encoding="utf-8-sig")
    d1, d2 = st.columns(2)
    d1.download_button("DOWNLOAD CSV // 结果表", buf.getvalue(),
                       file_name="batch_results.csv", mime="text/csv")

    # IOC 汇总（跨样本去重，SOC 直接可用）
    urls, domains, ips, hashes = Counter(), Counter(), Counter(), Counter()
    for rep in reports:
        urls.update(rep["iocs"].get("urls", []))
        domains.update(rep["iocs"].get("domains", []))
        ips.update(rep["iocs"].get("ips", []))
        hashes.update(rep["iocs"].get("hashes", []))
    ioc_lines = ["# IOC FEED（跨样本去重）", f"# urls: {len(urls)}, domains: {len(domains)}, "
                                              f"ips: {len(ips)}, hashes: {len(hashes)}", ""]
    for title, counter in (("URL", urls), ("DOMAIN", domains), ("IP", ips), ("SHA256/MD5", hashes)):
        ioc_lines.append(f"## {title}")
        ioc_lines += [ioc for ioc, _ in counter.most_common()]
        ioc_lines.append("")
    d2.download_button("DOWNLOAD IOC FEED // IOC 汇总", "\n".join(ioc_lines),
                       file_name="batch_iocs.txt", mime="text/plain")

    if urls or domains or ips:
        t1, t2, t3 = st.tabs([f"URL ({len(urls)})", f"DOMAIN ({len(domains)})", f"IP ({len(ips)})"])
        t1.dataframe(pd.DataFrame(urls.most_common(20), columns=["IOC", "出现次数"]),
                     width='stretch', hide_index=True)
        t2.dataframe(pd.DataFrame(domains.most_common(20), columns=["IOC", "出现次数"]),
                     width='stretch', hide_index=True)
        t3.dataframe(pd.DataFrame(ips.most_common(20), columns=["IOC", "出现次数"]),
                     width='stretch', hide_index=True)

    if st.session_state.get("batch_errors"):
        with st.expander("ERRORS // 失败明细"):
            for name, err in st.session_state["batch_errors"]:
                st.markdown(f"- {name}: {err}")


if mode == "上传文件":
    files = st.file_uploader("LOAD TARGETS // 选择 .eml / .msg 文件（可多选）",
                             type=["eml", "msg"], accept_multiple_files=True)
    if files and st.button("ENGAGE // 开始分析", type="primary"):
        _run_analysis([(f.name, f.getvalue()) for f in files])
    _show_results()

else:
    # 与"上传文件"对称：一个目标选择控件 + 开始分析。
    # 选文件夹没有原生控件，这里用「路径框 + 浏览文件夹…」组合：按钮弹出系统
    # 文件夹选择框，路径框同时作为展示与手工兜底（无图形界面时仍可粘贴路径）。
    st.session_state.setdefault("dir_target", _default_dir())
    row = st.columns([4, 1], vertical_alignment="bottom")
    row[0].text_input("FOLDER // 目标文件夹（可点右侧浏览，或直接粘贴路径）",
                      key="dir_target", placeholder=r"例如 E:\mail\samples")
    row[1].button("📂 浏览文件夹…", width='stretch', on_click=_on_browse_folder)
    if st.session_state.pop("dir_pick_failed", False):
        st.warning("未选择文件夹：对话框被取消，或当前环境无法弹出系统对话框"
                   "（如无图形界面的容器）。可直接在上方粘贴路径。")

    target = resolve_folder(st.session_state.get("dir_target"))
    recursive = st.checkbox("RECURSIVE // 递归包含子目录", value=True,
                            help="勾选后连同各级子目录中的邮件一起分析")
    limit = st.number_input("LIMIT // 最多分析封数（0 = 不限）",
                            min_value=0, max_value=100000, value=100)

    if target is None:
        st.info("SELECT FOLDER // 请选择或粘贴一个已存在的目录")
    else:
        # 带缓存：控件交互触发的重跑不再重走目录树（大目录下按钮长时间变灰的根因）
        found = discover_cached(st.session_state, target, recursive)
        st.info(f"TARGETS // {target} 下发现 {len(found)} 封邮件"
                + (f"，本次将分析前 {limit} 封" if limit and limit < len(found) else ""))
        if st.button("ENGAGE // 扫描并分析", type="primary"):
            if not found:
                st.warning("NO TARGETS // 目录中没有 .eml/.msg 文件"
                           + ("" if recursive else "（可勾选递归包含子目录再试）"))
            else:
                chosen = found[:limit] if limit else found
                _run_analysis([(p.name, p.read_bytes()) for p in chosen])
    _show_results()
