"""规则管理页：规则列表（行内调分值/开关）、YAML 在线编辑、新建规则、字典维护、样本试跑。

随 `streamlit run dashboard.py` 作为多页应用的一页加载。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scoring import rule_admin  # noqa: E402
from app.scoring.rule_loader import get_rule_engine  # noqa: E402
from app.scoring.rule_schema import RuleLoadError  # noqa: E402
from app.ui import sidebar_status, verdict_badge  # noqa: E402

from app.ui import hud_header  # noqa: E402

hud_header("RULE MATRIX // 规则矩阵", "规则管理",
           "rules/builtin 内置 · rules/custom 自定义（同 id 覆盖）· rules/dicts 字典；"
           "所有修改热重载即时生效，无需重启服务。")

engine = get_rule_engine()
sidebar_status(engine.version, len(engine.rules))
st.metric("当前规则版本", engine.version, f"{len(engine.rules)} 条规则",
          border=True)

tab_list, tab_edit, tab_new, tab_dict, tab_test = st.tabs(
    ["RULES 规则列表", "YAML 编辑", "NEW 新建规则", "DICTS 字典维护", "TEST 样本试跑"])

# ---------------- 规则列表 ----------------
with tab_list:
    rules = engine.list_rules()
    df = pd.DataFrame(rules)
    cols = ["enabled", "points", "id", "name", "category", "kind", "source"]
    edited = st.data_editor(
        df[cols],
        disabled=["id", "name", "category", "kind", "source"],
        column_config={
            "enabled": st.column_config.CheckboxColumn("启用"),
            "points": st.column_config.NumberColumn("分值", min_value=0, max_value=30),
            "id": st.column_config.TextColumn("规则 ID"),
            "name": st.column_config.TextColumn("名称"),
            "source": st.column_config.TextColumn("来源"),
        },
        width='stretch', hide_index=True, key="rule_editor",
    )
    if st.button("COMMIT // 保存修改（写入 custom 覆盖并热重载）", type="primary"):
        changed = 0
        for _, row in edited.iterrows():
            orig = next(r for r in rules if r["id"] == row["id"])
            if orig["enabled"] != row["enabled"] or orig["points"] != row["points"]:
                try:
                    rule_admin.update_rule(row["id"], {"enabled": bool(row["enabled"]),
                                                       "points": int(row["points"])})
                    changed += 1
                except (rule_admin.RuleAdminError, RuleLoadError) as exc:
                    st.error(f"{row['id']}: {exc}")
        if changed:
            st.success(f"已更新 {changed} 条规则")
            st.rerun()
        else:
            st.info("没有修改")

    del_id = st.text_input("删除自定义规则覆盖（恢复内置默认），输入规则 id")
    if st.button("PURGE // 删除覆盖") and del_id:
        try:
            rule_admin.delete_rule(del_id.strip())
            st.success(f"已删除 {del_id} 的自定义覆盖")
            st.rerun()
        except (rule_admin.RuleAdminError, RuleLoadError) as exc:
            st.error(str(exc))

# ---------------- YAML 在线编辑 ----------------
with tab_edit:
    st.markdown("直接编辑规则 YAML（保存后写入 `rules/custom/` 覆盖，内置规则升级不受影响）。"
                "字段参考特征字典：`subject`、`body`、`text`、`raw_html`、`url_count`、"
                "`from.domain`、`from.display_name`…；URL 作用域：`url`、`host`、`label_count`；"
                "附件作用域：`filename`、`extension`、`size`。")
    edit_id = st.selectbox("选择规则", [r["id"] for r in rules],
                           format_func=lambda rid: next(
                               (f"{r['id']}（{r['name']}，{r['source']}）"
                                for r in rules if r["id"] == rid), rid))
    rule_obj = next(r for r in engine.rules if r.id == edit_id)
    current_yaml = yaml.safe_dump([rule_obj.model_dump(exclude_none=True)],
                                  allow_unicode=True, sort_keys=False)
    edited_yaml = st.text_area("规则 YAML", value=current_yaml, height=420,
                               key=f"yaml_{edit_id}_{engine.version}")
    c_save, c_hint = st.columns([1, 2])
    if c_save.button("💾 保存 YAML", type="primary"):
        try:
            data = yaml.safe_load(edited_yaml)
            rule_dict = data[0] if isinstance(data, list) else data
            result = rule_admin.upsert_custom_rule(rule_dict)
            c_hint.success(f"已保存并生效（版本 {result['version']}）")
            st.rerun()
        except yaml.YAMLError as exc:
            c_hint.error(f"YAML 语法错误: {exc}")
        except (rule_admin.RuleAdminError, RuleLoadError) as exc:
            c_hint.error(f"保存失败: {exc}")
    else:
        c_hint.caption("保存即写入 custom 覆盖文件；删除覆盖（规则列表页）可恢复内置默认。")

# ---------------- 新建规则（表单） ----------------
with tab_new:
    st.markdown("表单方式新建声明式规则；复杂规则请用 **YAML 编辑** 页签直接写。")
    with st.form("new_rule"):
        c1, c2 = st.columns(2)
        rule_id = c1.text_input("规则 ID（小写下划线）", placeholder="my_custom_rule")
        rule_name = c2.text_input("规则名称", placeholder="示例：内部敏感词")
        c3, c4 = st.columns(2)
        scope = c3.selectbox("作用域", ["mail", "url", "domain", "attachment"])
        points = c4.number_input("分值", 0, 30, 5)
        c5, c6 = st.columns(2)
        field_path = c5.text_input("字段", placeholder="subject")
        operator = c6.selectbox("算子", sorted(
            {"contains_any", "contains_all", "regex_any", "equals_any", "suffix_any",
             "exists", "gt", "lt", "length_gt", "length_lt", "count_gt", "regex_count_gt"}))
        c7, c8 = st.columns(2)
        values_text = c7.text_area("匹配值（每行一个，可引用 @dict:brands 等字典）", height=100)
        reason = c8.text_input("研判依据文案（支持 {value} 与 {字段路径} 占位）",
                               placeholder="主题命中内部敏感词: {value}")
        exclude_field = st.text_input("排除字段（可选，命中则不触发）")
        exclude_values = st.text_area("排除值（每行一个，可选）", height=60)

        if st.form_submit_button("COMMIT // 保存规则"):
            values = [v.strip() for v in values_text.splitlines() if v.strip()]
            match = {"field": field_path.strip(), "operator": operator, "values": values}
            if exclude_field.strip() and exclude_values.strip():
                match["exclude"] = {
                    "field": exclude_field.strip(), "operator": "contains_any",
                    "values": [v.strip() for v in exclude_values.splitlines() if v.strip()],
                }
            try:
                result = rule_admin.upsert_custom_rule({
                    "id": rule_id.strip(), "name": rule_name.strip() or rule_id.strip(),
                    "category": "custom", "scope": scope, "points": int(points),
                    "reason": reason.strip() or None, "match": match,
                })
                st.success(f"规则已保存并生效（版本 {result['version']}）: {result['file']}")
            except (rule_admin.RuleAdminError, RuleLoadError) as exc:
                st.error(f"保存失败: {exc}")

# ---------------- 字典维护 ----------------
with tab_dict:
    dicts = rule_admin.list_dicts()
    dict_name = st.selectbox("选择字典", sorted(dicts))
    entries = dicts[dict_name]
    c1, c2 = st.columns([2, 1])
    with c1:
        st.write(f"`{dict_name}` 当前 {len(entries)} 条：")
        st.text("\n".join(entries[:200]))
    with c2:
        new_entries = st.text_area("追加词条（每行一个）", height=150)
        if st.button("APPEND // 追加并重载"):
            try:
                result = rule_admin.append_dict_entries(dict_name, new_entries.splitlines())
                if result["status"] == "appended":
                    st.success(f"已追加 {result['added']} 条（版本 {result['version']}）")
                    st.rerun()
                else:
                    st.info(result.get("reason", "无变化"))
            except (rule_admin.RuleAdminError, RuleLoadError) as exc:
                st.error(str(exc))

        to_remove = st.multiselect("移除词条（选中后点击移除）", entries)
        if st.button("REMOVE // 移除选中词条"):
            try:
                result = rule_admin.remove_dict_entries(dict_name, to_remove)
                if result["removed"]:
                    st.success(f"已移除 {result['removed']} 条（版本 {result['version']}）")
                    st.rerun()
                else:
                    st.info("没有匹配的词条")
            except (rule_admin.RuleAdminError, RuleLoadError) as exc:
                st.error(str(exc))

# ---------------- 样本试跑 ----------------
with tab_test:
    st.markdown("上传一封样本邮件，用**当前规则集**试跑（离线、不落盘），"
                "即时查看命中信号与结论预览——相当于 SIEM 的规则测试器。")
    test_file = st.file_uploader("样本邮件 (.eml)", type=["eml", "msg"], key="test_file")
    filter_id = st.text_input("只看指定规则（可选）")
    if test_file and st.button("RUN TEST // 试跑"):
        try:
            result = rule_admin.test_on_bytes(test_file.getvalue(),
                                              filename=test_file.name,
                                              rule_id=filter_id.strip() or None)
            st.markdown(f"{verdict_badge(result['verdict'])} &nbsp; 离线结论预览 "
                        f"<b>{result['score']} 分</b> &nbsp;·&nbsp; "
                        f"命中 <b>{len(result['signals'])}</b> 条信号 "
                        f"（启发式原始分 {result['raw_signals_points']}/30）",
                        unsafe_allow_html=True)
            st.caption(f"规则版本 {result['version']}")
            if result["signals"]:
                st.dataframe(pd.DataFrame(result["signals"]),
                             width='stretch', hide_index=True)
            else:
                st.success("无信号命中")
        except RuleLoadError as exc:
            st.error(str(exc))
