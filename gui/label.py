"""人工研判：批量标注发件人 + 标注集管理（L1 显式反馈 + L4 评测语料导出）。

单独成页的原因：批量处置需要多选表格、批量表单、标注列表三块 UI，塞进「邮箱取信分析」
会把那个页面的"取信 → 结果"主流程冲散、页面也被拉得过长。

数据来源是**已落盘的报告**（`data/reports/*.json`），不重新分析——标注是对已经看过的结论
做判断，不需要再跑一遍流水线。作用对象是**发件人**（地址级优先，可显式升级到域），
带留痕/到期/可撤销；硬信号永不免除（见 `app/scoring/trust.py`）。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import DATA_DIR  # noqa: E402
from app.mailbox.labels import apply_batch, revoke_batch, sender_keys  # noqa: E402
from gui.tables import (  # noqa: E402
    all_rows_selection,
    empty_selection,
    sender_pairs,
    verdict_keys,
)
from app.scoring.rule_loader import get_rule_engine  # noqa: E402
from app.ui import hud_header, sidebar_status  # noqa: E402
from app.utils.cache import cache  # noqa: E402

_engine = get_rule_engine()
sidebar_status(_engine.version, len(_engine.rules))

hud_header("REVIEW // 人工研判", "人工研判",
           "把「看一眼就知道是营销/正常」的判断批量变成系统知识：作用于发件人，留痕、可到期、可撤销。")

SCOPE_ADDR, SCOPE_DOMAIN = "仅该地址", "整个域"
LABEL_OPTIONS = ["正常·营销", "确认钓鱼"]
EXPIRY = {"永不过期": None, "30 天": 30, "90 天": 90, "365 天": 365}


@st.cache_data(ttl=30, show_spinner=False)
def load_reports(limit: int) -> pd.DataFrame:
    """读最近的分析报告（含发件人/主题/判定/信号/来源），供批量标注挑选。"""
    from app.mailbox.labels import is_mailbox_mail
    from app.scoring.features import parse_from_header, registrable_domain

    # 邮箱实际落盘的文件集：老报告没有 source 字段时用来精确判断"是不是邮箱邮件"
    mailbox_dir = DATA_DIR / "mailbox"
    mailbox_names = ({p.name for p in mailbox_dir.rglob("*.eml")}
                     if mailbox_dir.is_dir() else set())

    rows = cache.list_reports(limit=limit)
    out: list[dict] = []
    for meta in rows:
        full = cache.get_report_meta(meta["report_id"]) or {}
        path = full.get("report_path")
        if not path or not Path(path).is_file():
            continue
        try:
            rep = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        _name, addr, _dom = parse_from_header({"from": rep.get("from", "")})
        addr = (addr or "").lower()
        dom = registrable_domain(addr.split("@")[-1]) if "@" in addr else ""
        out.append({
            "report_id": rep.get("report_id", meta["report_id"]),
            "时间": (rep.get("created_at", "") or "")[:16].replace("T", " "),
            "判定": rep.get("verdict", ""),
            "分数": rep.get("score", 0),
            "发件人": addr,
            "域": dom,
            "主题": str(rep.get("subject", ""))[:60],
            "信号": ";".join(s["id"] for s in rep.get("signals", [])),
            # 来源：新报告读 source 字段；老报告用文件名约定/邮箱实际文件集兜底
            "来源": "邮箱" if is_mailbox_mail(rep.get("filename", ""),
                                            rep.get("source", ""), mailbox_names)
                    else "其他",
        })
    return pd.DataFrame(out)


total = cache.stats()["total"]
if total == 0:
    st.info("还没有分析报告。先到「邮箱取信分析」或「批量分析」跑一批邮件，再回来研判。")
    st.stop()

limit = st.number_input("REPORTS // 载入最近多少份报告", min_value=50, max_value=5000,
                        value=500, step=50)
df = load_reports(int(limit))
if df.empty:
    st.warning("报告索引存在但报告文件读不到（可能已被清理）。")
    st.stop()

# 标注状态：地址级优先，其次域级
df["标注"] = [
    (cache.get_human_verdict(a, d) or {}).get("verdict", "")
    for a, d in zip(df["发件人"], df["域"])
]

c1, c2, c3, c4 = st.columns([2, 2, 2, 2])
v_filter = c1.multiselect("FILTER // 判定", sorted(df["判定"].unique()),
                          default=[v for v in ("MALICIOUS", "SUSPICIOUS", "SPAM")
                                   if v in set(df["判定"])])
label_filter = c2.selectbox("FILTER // 标注状态", ["全部", "只看未标注", "只看已标注"])
# 来源筛选：样例/测试邮件会在报告列表里重复几百条（同一封样例跑多次），
# 把真实邮箱邮件淹没——研判时看到的"误报"多数来自它们，故默认只看邮箱
src_filter = c3.selectbox("FILTER // 来源", ["只看真实邮箱邮件", "只看其他（样例/上传/目录）", "全部"],
                          help="邮箱=取信落盘的邮件；其他=样例、界面上传、目录批量的邮件")
kw = c4.text_input("FILTER // 关键词（主题/发件人）").strip().lower()

view = df.copy()
if src_filter == "只看真实邮箱邮件":
    view = view[view["来源"] == "邮箱"]
elif src_filter.startswith("只看其他"):
    view = view[view["来源"] == "其他"]
if v_filter:
    view = view[view["判定"].isin(v_filter)]
if label_filter == "只看未标注":
    view = view[view["标注"] == ""]
elif label_filter == "只看已标注":
    view = view[view["标注"] != ""]
if kw:
    view = view[view["主题"].str.lower().str.contains(kw, na=False)
                | view["发件人"].str.lower().str.contains(kw, na=False)]

n_mail = int((df["来源"] == "邮箱").sum())
st.caption(f"共 {len(df)} 份报告（其中真实邮箱邮件 {n_mail} 份），当前筛选出 {len(view)} 份；"
           "勾选要处置的邮件 → 点下方批量按钮一次性标注（同一发件人的多封会自动去重）")

# ---------------- 批量标注 ----------------
with st.container(border=True):
    st.markdown("**① 勾选要处置的邮件 → ② 批量标注**")
    if view.empty:
        st.info("没有符合条件的报告（换个筛选条件试试）")
        pick_view = view
        positions: list[int] = []
    else:
        # 用 st.dataframe 的**原生多选行**（`selection_mode="multi-row"`）而不是 data_editor：
        # 勾选框由 Streamlit 自己画，不需要手工造列；还自带 Ctrl+A 全选与 Shift+点选区间
        # （实测 Ctrl+A 可全选）。下游只看"选中了哪些位置"，不需要就地编辑。
        pick_view = view[["发件人", "域", "判定", "分数", "主题", "标注"]].reset_index(drop=True)
        b_all, b_none, _sp = st.columns([1, 1, 4])
        pick_epoch = st.session_state.setdefault("pick_epoch", 0)
        if b_all.button("全选当前筛选结果", width="stretch", disabled=pick_view.empty):
            st.session_state["pick_default"] = all_rows_selection(len(pick_view))
            st.session_state["pick_epoch"] = pick_epoch + 1
            st.rerun()
        if b_none.button("清空选择", width="stretch"):
            st.session_state["pick_default"] = empty_selection()
            st.session_state["pick_epoch"] = pick_epoch + 1
            st.rerun()
        # 换 epoch = 换 widget key：Streamlit 会把它当成新控件，从而让 selection_default 生效
        # （同 key 时 default 只在首次渲染被采用，按钮就改不动已有选择）
        pick_state = st.dataframe(
            pick_view, hide_index=True, on_select="rerun", selection_mode="multi-row",
            key=f"label_pick_{pick_epoch}",
            selection_default=st.session_state.pop("pick_default", None) or empty_selection(),
            column_config={
                "发件人": st.column_config.TextColumn("发件人", width="medium"),
                "域": st.column_config.TextColumn("域", width="medium"),
                "主题": st.column_config.TextColumn("主题", width="large"),
                "分数": st.column_config.NumberColumn("分数", width="small"),
                "标注": st.column_config.TextColumn("标注", width="small"),
            },
        )
        positions = [int(r) for r in pick_state.selection.rows]
        st.caption(f"已勾选 {len(positions)} 行（点表头勾选框或按 Ctrl+A 可全选，Shift+点击可选区间）")

    picked = sender_pairs(pick_view, positions) if len(pick_view) else []

    b1, b2, b3, b4 = st.columns([2, 2, 2, 2])
    mark = b1.radio("标注为", LABEL_OPTIONS, horizontal=True)
    scope_choice = b2.radio("作用域", [SCOPE_ADDR, SCOPE_DOMAIN], horizontal=True,
                            help="默认只作用于该地址。「整个域」会把同域所有发件地址一起标记——"
                                 "同一域下不同用途（交易通知 vs 抽奖营销）可信度可能不同，谨慎使用")
    expiry = b3.selectbox("有效期", list(EXPIRY))
    b4.markdown("&nbsp;", unsafe_allow_html=True)

    uniq = sender_keys(picked, scope_domain=(scope_choice == SCOPE_DOMAIN))
    dest = "benign" if mark == "正常·营销" else "phishing"
    if st.button(f"APPLY // 批量标注（选中 {len(picked)} 封 → {len(uniq)} 个发件人）",
                 type="primary", disabled=not uniq):
        n = apply_batch(picked, dest, scope_domain=(scope_choice == SCOPE_DOMAIN),
                        days=EXPIRY[expiry], source="gui", note=f"{mark}（批量，{expiry}）")
        st.success(f"已标注 {n} 个发件人（{mark}，{scope_choice}，{expiry}）；"
                   "到「邮箱取信分析」重跑分析即可看到效果")
        st.cache_data.clear()
        st.rerun()

# ---------------- 标注集管理（批量撤销） ----------------
st.divider()
hud_header("LABELS", "已保存的人工判定", "撤销同样支持批量：勾选 → 撤销")
marks = cache.list_human_verdicts()
if not marks:
    st.info("还没有人工标注")
else:
    mdf = pd.DataFrame([{
        "作用域": "地址" if m["scope"] == "addr" else "域",
        "对象": m["key"],
        "判定": "正常·营销" if m["verdict"] == "benign" else "确认钓鱼",
        "备注": m.get("note", ""),
        "建立": (m.get("created_at") or "")[:10],
        "到期": (m.get("expires_at") or "永不过期")[:10],
    } for m in marks])
    mdf = mdf.reset_index(drop=True)
    rev_epoch = st.session_state.setdefault("revoke_epoch", 0)
    r_all, r_none, _rsp = st.columns([1, 1, 4])
    if r_all.button("全选全部标注", width="stretch", disabled=mdf.empty):
        st.session_state["revoke_default"] = all_rows_selection(len(mdf))
        st.session_state["revoke_epoch"] = rev_epoch + 1
        st.rerun()
    if r_none.button("清空撤销选择", width="stretch"):
        st.session_state["revoke_default"] = empty_selection()
        st.session_state["revoke_epoch"] = rev_epoch + 1
        st.rerun()
    rev_state = st.dataframe(
        mdf, hide_index=True, on_select="rerun", selection_mode="multi-row",
        key=f"label_revoke_{rev_epoch}",
        selection_default=st.session_state.pop("revoke_default", None) or empty_selection(),
        column_config={"备注": st.column_config.TextColumn("备注", width="large")},
    )
    victims = verdict_keys(mdf, [int(r) for r in rev_state.selection.rows])
    rc1, rc2 = st.columns([2, 5])
    if rc1.button(f"REVOKE // 撤销选中（{len(victims)} 条）", disabled=not victims):
        n = revoke_batch(victims)
        st.success(f"已撤销 {n} 条标注")
        st.cache_data.clear()
        st.rerun()
    rc2.caption("标注是**发件人级**的：该发件人的其它邮件会继承同一标签；"
                "「正常·营销」只降权话术/结构类信号，硬信号永不免除")

# ---------------- L4：导出标注集 ----------------
st.divider()
hud_header("EXPORT", "导出标注集（L4）",
           "把人工判断变成评测语料：后续每次调权都能用它做 A/B，回答「这条规则该不该降权」")
if st.button("EXPORT // 导出到 data/labeled/"):
    from app.mailbox.labels import export as export_labels

    with st.spinner("导出并分析标注样本…"):
        counts = export_labels(DATA_DIR / "mailbox", DATA_DIR / "labeled")
    st.success(f"已导出：正常 {counts['benign']} 封 / 钓鱼 {counts['phishing']} 封"
               f"（未标注跳过 {counts['skipped']} 封）→ data/labeled/")
    st.code("python scripts/eval_labels.py --simulate", language="bash")
