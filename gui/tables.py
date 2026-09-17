"""GUI 表格辅助（可导入、无副作用，故可单测）。

为什么单独一个模块：Streamlit 页面文件"执行即渲染"，**无法被测试 import**；而 `AppTest`
既不暴露 `data_editor`、也不暴露表格的"选中行"（实测 `hasattr(at, "data_editor") is False`）。
于是"表格少列/选中行为错"这类问题在自动检查里全都看不见——线上表现只能靠肉眼发现
（本项目真发生过：勾选列没插进 DataFrame，表格里根本没有勾选框）。

所以凡是能从表格里**算出来**的东西（选中行 → 发件人键、全选/清空的选择状态）都放这里，
页面只负责渲染。另外两个踩过的语义坑记在这里：

1. `st.data_editor` 的 `column_order`/`column_config` **只能作用于已存在的列**，不会新增列；
2. `st.dataframe` 的 `selection_default` 必须是
   ``{"selection": {"rows": [...], "columns": [], "cells": []}}`` 这个结构（少一层会抛
   `StreamlitAPIException`），读取选中行是 ``sel.selection.rows``（``list[int]`` 位置）。
"""
from __future__ import annotations

from typing import Any

ADDR_COL, DOMAIN_COL = "发件人", "域"
SCOPE_COL, KEY_COL = "作用域", "对象"


def empty_selection() -> dict[str, Any]:
    """空选择（用于"清空选择"按钮）。"""
    return {"selection": {"rows": [], "columns": [], "cells": []}}


def all_rows_selection(n_rows: int) -> dict[str, Any]:
    """全选（用于"全选当前筛选"按钮）。"""
    return {"selection": {"rows": list(range(max(n_rows, 0))), "columns": [], "cells": []}}


def sender_pairs(df: Any, positions: list[int]) -> list[tuple[str, str]]:
    """把选中行位置映射成 [(发件地址, 可注册域)]，跳过越界与无 `@` 的脏行。

    越界保护是必要的：`on_select="rerun"` 下用户切筛选条件后，旧的选中位置可能落在新的
    行数之外（页面用 `reset_index` 后按位置取行，越界会直接取到错行或抛异常）。
    """
    out: list[tuple[str, str]] = []
    for pos in positions:
        if not isinstance(pos, int) or pos < 0 or pos >= len(df):
            continue
        row = df.iloc[pos]
        addr = str(row.get(ADDR_COL, "") or "").lower().strip()
        if "@" not in addr:
            continue
        out.append((addr, str(row.get(DOMAIN_COL, "") or "").lower()))
    return out


def verdict_keys(df: Any, positions: list[int]) -> list[tuple[str, str]]:
    """把标注列表的选中行映射成 [(scope, key)]，供批量撤销。"""
    out: list[tuple[str, str]] = []
    for pos in positions:
        if not isinstance(pos, int) or pos < 0 or pos >= len(df):
            continue
        row = df.iloc[pos]
        scope = "addr" if str(row.get(SCOPE_COL, "")) == "地址" else "domain"
        key = str(row.get(KEY_COL, "") or "").lower().strip()
        if key:
            out.append((scope, key))
    return out
