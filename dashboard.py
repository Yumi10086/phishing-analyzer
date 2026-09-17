"""应用入口：导航路由（看板首页 / 批量分析 / 邮箱取信分析 / 人工研判 / 规则管理）。

`streamlit run dashboard.py` 启动；全局主题与页面配置在此统一设置。
"""
from pathlib import Path

import streamlit as st

from app.ui import apply_theme

st.set_page_config(page_title="钓鱼邮件自动化研判系统", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")
apply_theme()

home = st.Page(Path("gui/home.py"), title="看板首页", default=True)
batch = st.Page(Path("gui/batch.py"), title="批量分析")
mailbox = st.Page(Path("gui/mailbox.py"), title="邮箱取信分析")
review = st.Page(Path("gui/label.py"), title="人工研判")
rules = st.Page(Path("gui/rules.py"), title="规则管理")

pg = st.navigation([home, batch, mailbox, review, rules])
pg.run()
