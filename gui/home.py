"""态势总览：威胁统计、分数/结论分布、规则触发排行、IOC 汇总与报告查看。

随 `streamlit run dashboard.py` 作为多页应用的一页加载。
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scoring.rule_loader import get_rule_engine  # noqa: E402
from app.ui import (  # noqa: E402
    hud_header,
    radar_widget,
    sidebar_status,
    verdict_badge,
)
from app.utils.cache import cache  # noqa: E402
from app.utils.maintenance import analysis_data_stats, purge_analysis_data  # noqa: E402

# 清理后会失效的批量分析页会话状态：不清会让页面继续显示已被删除的旧结果
_BATCH_STATE_KEYS = ("batch_rows", "batch_reports", "batch_errors",
                     "batch_selected_idx", "discovery")


def _reset_analysis_data() -> None:
    """执行清理并清掉会话里的旧结果（放在按钮回调里，避免控件实例化后改状态）。"""
    stats = analysis_data_stats()
    result = purge_analysis_data(include_intel_cache=st.session_state.get("purge_intel", False))
    for key in _BATCH_STATE_KEYS:
        st.session_state.pop(key, None)
    st.session_state["purge_done"] = {
        **result, "indexed_before": stats["indexed_reports"],
    }


_engine = get_rule_engine()
sidebar_status(_engine.version, len(_engine.rules))

# ---------------- 指挥面板头 ----------------
head_row = st.columns([5, 1])
with head_row[0]:
    hud_header("THREAT OVERVIEW // PHISHING ANALYZER v0.1", "威胁态势总览",
               "全局研判视图 · 分析入口 批量分析 · 策略调整 规则管理")
with head_row[1]:
    radar_widget()

# ---------------- 清理重置（放在无数据早退之前，保证任何时候都可用） ----------------
_stats = analysis_data_stats()
with st.expander(f"MAINTENANCE // 清理重置（当前 {_stats['report_files']} 个报告文件 / "
                 f"{_stats['report_bytes'] / 1024:.0f} KB、索引 {_stats['indexed_reports']} 条、"
                 f"情报缓存 {_stats['intel_entries']} 条）"):
    st.caption(f"将清空：`{_stats['reports_dir']}` 下的报告文件（.json/.html）与报告索引。"
               "规则、字典、样本与评估语料不受影响。此操作不可撤销。")
    st.checkbox("同时清空情报查询缓存（下次分析会重新查询情报源）", key="purge_intel")
    st.checkbox("我确认清空以上分析数据", key="purge_confirm")
    st.button("PURGE // 执行清理", type="primary",
              disabled=not st.session_state.get("purge_confirm", False),
              on_click=_reset_analysis_data)
    done = st.session_state.pop("purge_done", None)
    if done:
        st.success(f"CLEARED // 已删除报告文件 {done['removed_report_files']} 个"
                   f"（{done['removed_bytes'] / 1024:.0f} KB）、索引 {done['removed_index_rows']} 条"
                   + (f"、情报缓存 {done['removed_intel_rows']} 条"
                      if done["intel_cache_cleared"] else ""))

# ---------------- 数据加载与筛选 ----------------
metas = cache.list_reports(limit=1000)

st.sidebar.header("FILTER // 筛选")
ALL_VERDICTS = ["MALICIOUS", "SUSPICIOUS", "SPAM", "BENIGN"]
verdict_filter = st.sidebar.multiselect("VERDICT", ALL_VERDICTS, default=ALL_VERDICTS,
                                        format_func=lambda v: {"MALICIOUS": "恶意",
                                                               "SUSPICIOUS": "可疑",
                                                               "SPAM": "垃圾",
                                                               "BENIGN": "正常"}.get(v, v))
search = st.sidebar.text_input("FILENAME // 文件名搜索").lower().strip()

if metas and verdict_filter:
    filtered = [m for m in metas
                if m["verdict"] in verdict_filter
                and (not search or search in m["filename"].lower())]
else:
    filtered = []

if not metas:
    st.info("NO DATA // 暂无分析记录。前往「批量分析」执行扫描，或运行 "
            "`python -m app.cli analyze data/samples/phishing_01.eml --offline`")
    st.stop()
if not filtered:
    st.warning("NO MATCH // 当前筛选条件下没有记录")
    st.stop()

# ---------------- KPI ----------------
total = len(filtered)
vc = Counter(m["verdict"] for m in filtered)
mal, susp, spam, ben = (vc.get("MALICIOUS", 0), vc.get("SUSPICIOUS", 0),
                        vc.get("SPAM", 0), vc.get("BENIGN", 0))
scores = [m["score"] for m in filtered]
avg_score = sum(scores) / total

c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("SCANNED / 已分析", total, border=True)
c2.metric(f"MALICIOUS 恶意 · {mal / total * 100:.0f}%", mal, border=True)
c3.metric(f"SUSPICIOUS 可疑 · {susp / total * 100:.0f}%", susp, border=True)
c4.metric(f"SPAM 垃圾 · {spam / total * 100:.0f}%", spam, border=True)
c5.metric(f"BENIGN 正常 · {ben / total * 100:.0f}%", ben, border=True)
c6.metric("AVG SCORE 平均分", f"{avg_score:.0f}", border=True)

# ---------------- 加载报告明细（用于信号/IOC 聚合，上限 300 份控制读取量） ----------------
report_jsons: list[dict] = []
for meta in filtered[:300]:
    full = cache.get_report_meta(meta["report_id"])  # 完整元数据含 report_path
    if not full:
        continue
    try:
        report_jsons.append(json.loads(Path(full["report_path"]).read_text(encoding="utf-8")))
    except Exception:  # noqa: BLE001 - 单份报告损坏不影响整体
        continue

hud_header("DISTRIBUTION // 分布与趋势", "分布与趋势")
left, mid, right = st.columns(3)

with left:
    st.caption("VERDICT // 结论分布")
    verdict_df = pd.DataFrame({"数量": [mal, susp, spam, ben]},
                              index=["恶意", "可疑", "垃圾", "正常"])
    st.bar_chart(verdict_df, color="#06B6D4")

with mid:
    st.caption("SCORE // 分数分布")
    buckets = Counter(min(s // 10, 10) for s in scores)
    hist = pd.Series({("100" if b == 10 else f"{b * 10:02d}-{b * 10 + 9:02d}"):
                      buckets.get(b, 0) for b in range(11)})
    st.bar_chart(hist, color="#22D3EE")

with right:
    st.caption("TIMELINE // 按日趋势")
    days = Counter()
    for m in filtered:
        try:
            days[str(datetime.fromisoformat(m["created_at"]).date())] += 1
        except Exception:  # noqa: BLE001
            continue
    if len(days) >= 2:
        st.bar_chart(pd.Series(days).sort_index(), color="#0EA5E9")
    elif days:
        st.caption(f"数据集中在 {next(iter(days))}（共 {sum(days.values())} 封），暂无趋势")
    else:
        st.caption("无时间数据")

# ---------------- 规则触发排行（规则调优的依据） ----------------
sig_counter: Counter = Counter()
for rep in report_jsons:
    for sig in rep.get("signals", []):
        sig_counter[sig.get("id", "?")] += 1

hud_header("SIGNAL MATRIX // 规则触发矩阵", "规则触发矩阵")
left2, right2 = st.columns(2)
with left2:
    st.caption("TOP 10 TRIGGERED RULES")
    if sig_counter:
        sig_df = pd.DataFrame(sig_counter.most_common(10), columns=["规则", "触发次数"])
        st.bar_chart(sig_df.set_index("规则"), horizontal=True, color="#06B6D4")
    else:
        st.caption("无信号数据")

with right2:
    st.caption("SIGNAL DETAIL // 信号明细")
    if sig_counter:
        st.dataframe(sig_df, width='stretch', hide_index=True,
                     column_config={"规则": st.column_config.TextColumn("规则 ID",
                                                                          width="medium"),
                                    "触发次数": st.column_config.NumberColumn("触发次数")})
        st.caption("统计来自最新 300 份报告；在「规则管理」页可调整规则分值与开关")
    else:
        st.caption("无信号数据")

# ---------------- IOC 汇总 ----------------
hud_header("IOC FEED // IOC 汇总", "TOP IOC")
urls, domains, ips = Counter(), Counter(), Counter()
for rep in report_jsons:
    for u in rep.get("iocs", {}).get("urls", []):
        urls[u] += 1
    for d in rep.get("iocs", {}).get("domains", []):
        domains[d] += 1
    for i in rep.get("iocs", {}).get("ips", []):
        ips[i] += 1
t1, t2, t3 = st.tabs([f"URL ({len(urls)})", f"DOMAIN ({len(domains)})", f"IP ({len(ips)})"])
t1.dataframe(pd.DataFrame(urls.most_common(15), columns=["IOC", "出现次数"]),
             width='stretch', hide_index=True)
t2.dataframe(pd.DataFrame(domains.most_common(15), columns=["IOC", "出现次数"]),
             width='stretch', hide_index=True)
t3.dataframe(pd.DataFrame(ips.most_common(15), columns=["IOC", "出现次数"]),
             width='stretch', hide_index=True)

# ---------------- 报告明细查看 ----------------
hud_header("RECORDS // 分析记录", "分析记录")
df = pd.DataFrame([{
    "报告ID": m["report_id"], "文件": m["filename"], "结论": m["verdict"],
    "评分": m["score"], "IOC数": m["ioc_count"], "时间": m["created_at"][:19],
} for m in filtered])
_verdict_color = {"MALICIOUS": "#ef4444", "SUSPICIOUS": "#f97316", "SPAM": "#a3a3a3", "BENIGN": "#22c55e"}


def _color(val):
    return (f"color: {_verdict_color.get(val, '#94A3B8')}; font-weight: 700; "
            f"text-shadow: 0 0 8px currentColor"
            if val in _verdict_color else "")


st.dataframe(df.style.map(_color, subset=["结论"]), width='stretch', hide_index=True)

selected_id = st.selectbox("选择报告查看完整报告",
                           [m["report_id"] for m in filtered],
                           format_func=lambda rid: next(
                               (f"[{m['verdict']} {m['score']:03d}] {m['filename']}"
                                for m in filtered if m["report_id"] == rid), rid))
if selected_id:
    meta = cache.get_report_meta(selected_id)
    st.markdown(f"{verdict_badge(meta['verdict'])} &nbsp; "
                f"<span style='color:#E5F2FF;font-weight:700'>{meta['filename']}</span>",
                unsafe_allow_html=True)
    html_path = Path(meta["report_path"]).with_suffix(".html")
    if html_path.is_file():
        # st.iframe 传 Path 会读取本地 .html 并以 srcdoc 内嵌，报告自带的全局
        # <style> 因此被隔离在 iframe 内（components.v1.html 已弃用）
        st.iframe(html_path, height=900)
    else:
        st.warning("REPORT MISSING // 该报告的 HTML 文件不存在")
