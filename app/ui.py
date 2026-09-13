"""GUI 统一主题与小组件（Sci-Fi HUD 设计规范）。

视觉系统：
  - 深空背景 #020617，全局扫描线覆层（Data Overload：hover 增强）
  - 面板 rgba(15,23,42,.85) + backdrop-blur，青色发光边框 0 0 20px rgba(6,182,212,.5)
  - L 型角标装饰，Tactical Lock：hover 时角标向内锁定位移（150ms）
  - 状态指示器持续脉冲（2s ease-in-out），关键提示闪烁
  - Holographic Pierce：active 用高亮内发光，不做重力下沉
  - 等宽字体 + 大写 + 宽字距；中文回退系统 CJK 字体

页面在入口调用 apply_theme()；verdict_badge() 输出脉冲状态徽标；
hud_header() 输出 "英文标签 // 中文标题" 的 HUD 区块头。
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import streamlit as st

from app.utils.logger import get_logger

log = get_logger(__name__)

# (文字色, 边框色, 底色, 中文, 英文) —— HUD 状态语义色
_VERDICT_STYLES = {
    "MALICIOUS": ("#EF4444", "rgba(239, 68, 68, 0.45)", "rgba(239, 68, 68, 0.08)", "恶意", "MALICIOUS"),
    "SUSPICIOUS": ("#F97316", "rgba(249, 115, 22, 0.45)", "rgba(249, 115, 22, 0.08)", "可疑", "SUSPICIOUS"),
    "BENIGN": ("#22C55E", "rgba(34, 197, 94, 0.45)", "rgba(34, 197, 94, 0.08)", "正常", "BENIGN"),
}

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap');

:root {
  --bg: #020617;
  --panel: rgba(15, 23, 42, 0.85);
  --panel-2: rgba(15, 23, 42, 0.55);
  --line: rgba(6, 182, 212, 0.30);
  --line-soft: rgba(6, 182, 212, 0.16);
  --glow-sm: 0 0 10px rgba(6, 182, 212, 0.20);
  --glow-md: 0 0 15px rgba(6, 182, 212, 0.30);
  --glow-lg: 0 0 25px rgba(6, 182, 212, 0.50);
  --focus-glow: 0 0 20px rgba(6, 182, 212, 0.40);
  --text: #E5F2FF;
  --text-2: #94A3B8;
  --text-3: #64748b;
  --cyan: #06B6D4;
  --neon: #22D3EE;
  --sky: #0EA5E9;
  --ok: #22C55E;
  --warn: #F97316;
  --danger: #EF4444;
  --mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Consolas,
          'Courier New', 'PingFang SC', 'Microsoft YaHei', monospace;
}

/* ---------------- 全局 ---------------- */
html, body, [data-testid="stApp"] {
  font-family: var(--mono);
  background: var(--bg);
  color: var(--text);
  font-size: 14px;
}
/* 深空底色 + 极淡环境辉光 */
[data-testid="stApp"] {
  background:
    radial-gradient(1000px 420px at 15% -8%, rgba(6, 182, 212, 0.055), transparent 55%),
    radial-gradient(900px 400px at 92% 105%, rgba(14, 165, 233, 0.045), transparent 55%),
    var(--bg);
}
/* 全局扫描线覆层（Data Overload 由面板级 hover 增强） */
[data-testid="stApp"]::before {
  content: '';
  position: fixed; inset: 0; z-index: 999; pointer-events: none;
  background: repeating-linear-gradient(0deg,
    rgba(34, 211, 238, 0.022) 0px, rgba(34, 211, 238, 0.022) 1px,
    transparent 1px, transparent 3px);
}
.block-container { padding-top: 1.5rem; padding-bottom: 4rem; max-width: 1280px; }
::selection { background: rgba(6, 182, 212, 0.35); color: #fff; }

/* 隐藏部署/菜单装饰。
   顶栏（stToolbar）容器保留——侧边栏收起后的展开按钮渲染在其中；
   只精确移除无用的子件：Deploy 按钮、工具栏动作区、主菜单。 */
#MainMenu, footer, [data-testid="stStatusWidget"], #stDecoration,
[data-testid="stAppPromo"], [data-testid="stToast"],
[data-testid="stAppDeployButton"], [data-testid="stToolbarActions"],
[data-testid="stMainMenu"], [data-testid="stMainMenuButton"],
[data-testid="stHeader"] [data-testid="stBaseButton-header"] { display: none !important; }
[data-testid="stHeader"] {
  background: rgba(2, 6, 23, 0.78);
  backdrop-filter: blur(8px);
  box-shadow: 0 1px 0 0 var(--line-soft);
}
/* 压缩顶栏高度（默认 3.75rem -> 2.25rem），侧边栏头同步对齐 */
[data-testid="stHeader"],
[data-testid="stSidebarHeader"] {
  height: 2.25rem !important;
  min-height: unset !important;
}
[data-testid="stSidebarCollapseButton"] button {
  padding: .15rem .35rem;
}

/* 侧边栏：指挥舱面板 */
[data-testid="stSidebar"] {
  background: var(--panel);
  border-right: 1px solid var(--line);
  backdrop-filter: blur(12px);
}
[data-testid="stSidebar"] .block-container { padding-top: 1.8rem; }
[data-testid="stSidebar"] * { color: var(--text-2); }
[data-testid="stSidebar"] h2 {
  color: var(--neon); font-size: .68rem; font-weight: 500;
  letter-spacing: .14em; text-transform: uppercase; margin-bottom: .6rem;
}
[data-testid="stSidebar"] [data-testid="stSidebarNav"] a span {
  color: var(--text-2); font-size: .9rem; font-weight: 500; letter-spacing: .04em;
  text-transform: uppercase;
}
[data-testid="stSidebar"] [data-testid="stSidebarNav"] a {
  padding: .45rem .75rem; transition: background .15s ease, color .15s ease;
}
[data-testid="stSidebar"] [data-testid="stSidebarNav"] a:hover {
  background: rgba(6, 182, 212, 0.08);
}
[data-testid="stSidebar"] [data-testid="stSidebarNav"] a:hover span { color: var(--neon); }
[data-testid="stSidebar"] [data-testid="stSidebarNav"] a[aria-current="page"] {
  background: rgba(6, 182, 212, 0.12);
  box-shadow: inset 2px 0 0 0 var(--cyan);
}
[data-testid="stSidebar"] [data-testid="stSidebarNav"] a[aria-current="page"] span {
  color: var(--text); font-weight: 600;
  text-shadow: 0 0 12px rgba(34, 211, 238, 0.55);
}

/* 侧边栏系统状态块：填充导航下方的留白，同时是功能性信息 */
.hud-side-status {
  margin-top: 1.5rem; padding: .9rem 1rem;
  border: 1px solid var(--border-soft); border-radius: 4px;
  background: rgba(2, 6, 23, 0.55);
  font-family: var(--mono); font-size: .7rem; letter-spacing: .04em;
}
.hud-side-row {
  display: flex; align-items: center; gap: 8px;
  padding: .28rem 0; color: var(--text-2);
}
.hud-side-row .k { color: var(--text-3); letter-spacing: .1em; font-size: .62rem;
  text-transform: uppercase; margin-right: auto; }
.hud-side-row .v { color: var(--neon); }
.hud-side-legend {
  margin-top: .6rem; padding-top: .6rem;
  border-top: 1px solid var(--border-soft);
  display: flex; flex-direction: column; gap: .35rem;
}
.hud-side-legend > div {
  display: flex; align-items: center; gap: 8px; color: var(--text-2);
}

/* ---------------- HUD 区块头 ---------------- */
.hud-head { margin: 1.2rem 0 .55rem; }
.hud-head-label {
  font-family: var(--mono); font-size: .66rem; font-weight: 500;
  letter-spacing: .18em; text-transform: uppercase; color: var(--neon);
  text-shadow: 0 0 10px rgba(34, 211, 238, 0.5);
}
.hud-head-title {
  font-family: var(--mono); font-size: 1.05rem; font-weight: 700;
  letter-spacing: .06em; color: var(--text); margin-top: .15rem;
}
h1, h2, h3 { font-family: var(--mono); color: var(--text); letter-spacing: .04em; }
h1 { font-size: 1.35rem; font-weight: 700; }
h2 { font-size: .95rem; font-weight: 700; }
h3 { font-size: .85rem; font-weight: 500; }
[data-testid="stCaptionContainer"] { color: var(--text-3); font-size: .75rem; }
p, li { color: var(--text-2); font-size: .8125rem; line-height: 1.7; }
strong { color: var(--text); font-weight: 700; }
a { color: var(--neon); text-decoration: none; }
a:hover { text-shadow: 0 0 8px rgba(34, 211, 238, 0.6); }
hr { border: none; height: 1px; background: var(--line-soft); }

/* ---------------- HUD 面板：角标 + 战术锁定 ---------------- */
.hud-panel, [data-testid="stMetric"], [data-testid="stExpander"] > details {
  position: relative;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 4px;
  backdrop-filter: blur(12px);
  box-shadow: var(--glow-sm), inset 0 0 24px rgba(6, 182, 212, 0.04);
  transition: box-shadow .15s ease, border-color .15s ease;
}
/* L 型角标：左上 + 右下（Tactical Lock：hover 向内锁定位移） */
.hud-panel::before,
[data-testid="stMetric"]::before,
[data-testid="stExpander"] > details::before,
[data-testid="stAlert"]::before {
  content: ''; position: absolute; top: 5px; left: 5px;
  width: 10px; height: 10px; pointer-events: none;
  border-top: 2px solid var(--cyan); border-left: 2px solid var(--cyan);
  opacity: .65; transition: all .15s ease;
}
.hud-panel::after,
[data-testid="stMetric"]::after,
[data-testid="stExpander"] > details::after,
[data-testid="stAlert"]::after {
  content: ''; position: absolute; bottom: 5px; right: 5px;
  width: 10px; height: 10px; pointer-events: none;
  border-bottom: 2px solid var(--cyan); border-right: 2px solid var(--cyan);
  opacity: .65; transition: all .15s ease;
}
/* Tactical Lock + Data Overload：hover 锁定位移 + 辉光增强 */
[data-testid="stMetric"]:hover,
[data-testid="stExpander"] > details:hover {
  border-color: rgba(34, 211, 238, 0.55);
  box-shadow: var(--glow-lg), inset 0 0 30px rgba(6, 182, 212, 0.07);
}
[data-testid="stMetric"]:hover::before,
[data-testid="stExpander"] > details:hover::before {
  top: 2px; left: 2px; opacity: 1; border-color: var(--neon);
}
[data-testid="stMetric"]:hover::after,
[data-testid="stExpander"] > details:hover::after {
  bottom: 2px; right: 2px; opacity: 1; border-color: var(--neon);
}

/* ---------------- 指标卡 ---------------- */
[data-testid="stMetricLabel"] p {
  color: var(--text-3); font-size: .68rem; font-weight: 500;
  letter-spacing: .12em; text-transform: uppercase; margin-bottom: 3px;
}
[data-testid="stMetricValue"] {
  color: var(--text); font-weight: 700; font-size: 1.6rem;
  font-variant-numeric: tabular-nums;
  text-shadow: 0 0 14px rgba(34, 211, 238, 0.35);
}

/* ---------------- 表格 ---------------- */
[data-testid="stDataFrame"] {
  border: 1px solid var(--line);
  border-radius: 4px;
  overflow: hidden;
  background: rgba(2, 6, 23, 0.6);
}

/* ---------------- 页签 ---------------- */
.stTabs [data-baseweb="tab-list"] {
  gap: 6px; box-shadow: 0 1px 0 0 var(--line); border: none;
}
.stTabs [data-baseweb="tab"] {
  padding: .5rem .875rem; color: var(--text-3);
  font-family: var(--mono); font-size: .75rem; letter-spacing: .08em;
  text-transform: uppercase;
  border-bottom: 2px solid transparent; transition: color .15s ease;
}
.stTabs [data-baseweb="tab"]:hover { color: var(--neon); background: transparent; }
.stTabs [aria-selected="true"] { color: var(--neon) !important; font-weight: 500; }
.stTabs [data-baseweb="tab-highlight"] {
  background-color: var(--neon); height: 2px;
  box-shadow: 0 0 8px rgba(34, 211, 238, 0.6);
}

/* ---------------- 按钮：终端风格 ---------------- */
.stButton > button, .stDownloadButton > button {
  font-family: var(--mono);
  font-size: .75rem; font-weight: 500;
  letter-spacing: .12em; text-transform: uppercase;
  background: rgba(15, 23, 42, 0.80);
  border: 1px solid rgba(6, 182, 212, 0.40);
  color: var(--neon);
  border-radius: 4px;
  padding: .5rem 1rem;
  transition: all .3s ease;
}
.stButton > button:hover, .stDownloadButton > button:hover {
  box-shadow: var(--glow-lg);
  border-color: rgba(34, 211, 238, 0.7);
  transform: translateY(-2px);
  color: var(--text);
}
.stButton > button:active, .stDownloadButton > button:active {
  /* Holographic Pierce：内发光反馈，非重力下沉 */
  transform: none;
  box-shadow: inset 0 0 14px rgba(34, 211, 238, 0.35);
}
.stButton > button[kind="primary"], .stDownloadButton > button[kind="primary"] {
  background: rgba(6, 182, 212, 0.10);
  border-color: rgba(34, 211, 238, 0.55);
  color: #eafcff;   /* 近白主文字：低透底上对比度优先于霓虹感 */
  text-shadow: 0 0 6px rgba(34, 211, 238, 0.35);
}
.stButton > button[kind="primary"]:hover {
  background: rgba(6, 182, 212, 0.26);
  box-shadow: var(--glow-lg);
}
.stButton > button:focus-visible {
  outline: none; box-shadow: var(--focus-glow);
  border-color: rgba(34, 211, 238, 0.7);
}

/* ---------------- 输入控件 ---------------- */
[data-baseweb="input"], [data-baseweb="select"], [data-baseweb="textarea"] {
  border-radius: 4px; border: none !important;
  box-shadow: inset 0 0 0 1px var(--line);
  background: rgba(2, 6, 23, 0.75) !important;
}
[data-baseweb="baseInput"] { background: transparent; }
[data-baseweb="baseInput"] input, [data-baseweb="baseInput"] textarea {
  font-family: var(--mono); color: var(--text) !important; font-size: .8125rem;
  background: transparent;
}
[data-baseweb="baseInput"] input::placeholder { color: var(--text-3); }
[data-baseweb="baseInput"]:focus-within {
  box-shadow: inset 0 0 0 1px rgba(34, 211, 238, 0.6), var(--focus-glow);
}

/* 多选标签（VERDICT 芯片）：暗色底 + 高亮青字，保证对比度。
   1.63 版多选已迁移到 react-aria，实际结构是
   stMultiSelectTagsContainer > span > span（底色层）> span（文字层），
   旧的 [data-baseweb="tag"] 选择器匹配不到。 */
[data-testid="stMultiSelectTagsContainer"] > span > span {
  background: rgba(6, 182, 212, 0.12) !important;
  border: 1px solid rgba(6, 182, 212, 0.32) !important;
  border-radius: 3px;
}
[data-testid="stMultiSelectTagsContainer"] > span > span > span,
[data-testid="stMultiSelectTagsContainer"] span span span {
  color: #7deffc !important;   /* 高亮青字：暗底上的高对比 */
}
[data-testid="stMultiSelectTagsContainer"] svg { fill: #7deffc !important; }

/* ---------------- 折叠面板 / 提示框 ---------------- */
[data-testid="stExpander"] summary {
  font-family: var(--mono); font-weight: 500; color: var(--text-2);
  font-size: .8125rem; letter-spacing: .03em; transition: color .15s ease;
}
[data-testid="stExpander"] summary:hover { color: var(--neon); }
/* 提示框压暗：!important 压过 Streamlit 原生 success/info 底色 */
[data-testid="stAlert"] {
  background: rgba(8, 25, 43, 0.92) !important;
  border: 1px solid var(--line) !important;
  border-radius: 4px;
  box-shadow: inset 0 0 0 1px rgba(6, 182, 212, 0.10), var(--glow-sm);
}
[data-testid="stAlert"] p,
[data-testid="stAlert"] div[data-testid="stMarkdownContainer"] p {
  color: #e2ecf7 !important; font-family: var(--mono); font-size: .75rem;
}

/* 进度条。
   结构（1.63）：stProgress
     ├─ div（文字轨道区）> stMarkdownContainer > p（"SCANNING n/m :: file"）
     └─ div > stProgressBarTrack > div（填充条）
   坑：`stProgress > div > div` 会同时命中「文字容器」和「进度轨道」，
   把青色渐变刷到文字层，导致灰字压在青底上无法辨认。
   因此只对 stProgressBarTrack 及其填充条上色，文字层强制透明。 */
[data-testid="stProgress"],
[data-testid="stProgress"] > div:first-child,
[data-testid="stProgress"] [data-testid="stMarkdownContainer"] {
  background: transparent !important;
  background-image: none !important;
  box-shadow: none !important;
}
/* 进度文字：高对比浅色（暗底上的可读性优先于霓虹感） */
[data-testid="stProgress"] p,
[data-testid="stProgress"] [data-testid="stMarkdownContainer"] p {
  color: #cfe6f5 !important;
  font-family: var(--mono); font-size: .75rem; letter-spacing: .04em;
}
/* 轨道 */
[data-testid="stProgressBarTrack"] {
  background: rgba(15, 23, 42, 0.9) !important;
  background-image: none !important;
  border-radius: 2px;
  box-shadow: inset 0 0 0 1px var(--line-soft);
  height: 7px;
}
/* 填充条：渐变 + 辉光 */
[data-testid="stProgressBarTrack"] > div {
  background: linear-gradient(90deg, var(--cyan), var(--sky)) !important;
  box-shadow: 0 0 10px rgba(6, 182, 212, 0.55);
  border-radius: 2px;
}

/* 滚动条 */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-thumb { background: #12283a; border-radius: 0; }
::-webkit-scrollbar-thumb:hover { background: rgba(6, 182, 212, 0.45); }
::-webkit-scrollbar-track { background: #050a18; }
::selection { background: rgba(6, 182, 212, 0.4); color: #fff; }

/* ---------------- 徽标与状态 ---------------- */
.vbadge {
  display: inline-flex; align-items: center; gap: 7px;
  padding: 2px 10px; border-radius: 3px;
  font-family: var(--mono); font-weight: 500; font-size: .72rem;
  letter-spacing: .08em; text-transform: uppercase;
  border: 1px solid;
}
.hud-dot {
  display: inline-block; width: 7px; height: 7px; border-radius: 50%;
  background: currentColor; animation: hudPulse 2s ease-in-out infinite;
}
@keyframes hudPulse {
  0%, 100% { opacity: 1; box-shadow: 0 0 8px currentColor; }
  50% { opacity: .35; box-shadow: 0 0 2px currentColor; }
}

/* 雷达扫描装饰 */
.hud-radar {
  position: relative; width: 84px; height: 84px; border-radius: 50%;
  border: 1px solid var(--line);
  background:
    radial-gradient(circle, transparent 58%, rgba(6, 182, 212, 0.08) 60%, transparent 62%),
    radial-gradient(circle, transparent 34%, rgba(6, 182, 212, 0.08) 36%, transparent 38%),
    var(--panel);
  overflow: hidden;
}
.hud-radar::before {
  content: ''; position: absolute; inset: 0; border-radius: 50%;
  background: conic-gradient(from 0deg, rgba(34, 211, 238, 0.35), transparent 70deg);
  animation: hudRadar 6s linear infinite;
}
.hud-radar::after {
  content: ''; position: absolute; left: 50%; top: 0; bottom: 0; width: 1px;
  background: var(--line-soft);
  box-shadow: 42px 0 0 0 var(--line-soft);
}
@keyframes hudRadar { to { transform: rotate(360deg); } }

@media (prefers-reduced-motion: reduce) {
  * { transition: none !important; animation: none !important; }
  .hud-radar::before { animation: none; }
}
</style>
"""


def apply_theme() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)


# ---- 本地文件夹选择（批量分析的"目录模式"用） ----

MAIL_EXTS = (".eml", ".msg")

# 在子进程中运行的对话框脚本。必须独立成子进程，原因见 pick_folder() 的说明。
_PICK_FOLDER_CODE = (
    "import sys\n"
    "try:\n"
    "    import tkinter as tk\n"
    "    from tkinter import filedialog\n"
    "except Exception:\n"
    "    sys.exit(3)\n"
    "root = tk.Tk()\n"
    "root.withdraw()\n"
    "root.attributes('-topmost', True)\n"
    "path = filedialog.askdirectory(initialdir=(sys.argv[1] or None), mustexist=True,\n"
    "                              title='选择要分析的邮件目录')\n"
    "root.destroy()\n"
    "sys.stdout.write(path or '')\n"
)


def resolve_folder(raw: str | None) -> Path | None:
    """校验路径文本：去引号/空白，且必须指向一个已存在的目录，否则返回 None。

    tkinter 在 Windows 上返回的是正斜杠路径（E:/mail），Path 可正常处理。
    """
    cleaned = (raw or "").strip().strip('"').strip("'").strip()
    if not cleaned:
        return None
    try:
        p = Path(cleaned)
        return p if p.is_dir() else None
    except OSError:
        return None


def iter_mail_files(root: Path, recursive: bool = True) -> list[Path]:
    """收集目录下的 .eml/.msg 文件（跳过不可读项，结果排序稳定）。

    用 ``os.scandir`` 而不是 ``Path.rglob`` + ``Path.is_file()``：Windows 上
    scandir 返回的 dirent 自带类型信息，无需为每个条目额外做一次 stat。实测
    8615 个条目 523ms -> 26ms、10 万条个条目 6334ms -> 310ms（结果完全一致）。
    原实现的耗时九成花在逐条 ``is_file()`` 的 stat 上，而不是遍历本身。
    """
    found: list[Path] = []
    stack: list[str] = [str(root)]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if recursive:
                                stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False) and \
                                os.path.splitext(entry.name)[1].lower() in MAIL_EXTS:
                            found.append(Path(entry.path))
                    except OSError:  # 断链符号链接、权限不足的条目
                        continue
        except OSError:  # 目录不存在/无权限
            continue
    return sorted(found)


def discover_cached(store, target: Path, recursive: bool, ttl: float = 30.0,
                    *, clock=time.monotonic) -> list[Path]:
    """按 (路径, 递归) 缓存目录发现结果；TTL 到期或目标变化即重新遍历。

    动机：页面每次控件交互都会重跑脚本（切换 offline 开关、改递归、改上限、在路径框
    输入），若每次都重走目录树，控件会在大目录下长时间变灰——实测切换 offline 触发的
    重跑：8614 封 558ms、10 万封 7352ms。命中缓存时零文件系统开销。

    TTL 的作用是让"往目录里新增了邮件"这类变化在有限时间内自动反映，从而不需要额外
    的刷新按钮。``store`` 传 st.session_state（或普通 dict，便于测试）。
    """
    key = f"{target}|{int(recursive)}"
    hit = store.get("discovery")
    if isinstance(hit, dict) and hit.get("key") == key and clock() - hit.get("at", 0.0) < ttl:
        return hit["files"]
    files = iter_mail_files(target, recursive)
    store["discovery"] = {"key": key, "files": files, "at": clock()}
    return files


def _subprocess_kwargs() -> dict:
    """子进程调用参数：把编码钉死成 UTF-8，避免中文 Windows 上按 GBK 解码出错。

    不显式指定时，``text=True`` 会按系统区域编码解码（简体中文 Windows = cp936）。
    子进程只要向 stdout/stderr 写出任何非 GBK 字节（Tcl/Tk 的报错信息就会），
    subprocess 的读取线程就会抛 UnicodeDecodeError 而静默死掉，主进程拿不到结果——
    表现为"文件夹选完没反应"。``errors="replace"`` 再兜一层：任何编码不匹配都降级为
    替代字符，绝不让读取线程崩。
    """
    kwargs: dict = {
        "encoding": "utf-8",
        "errors": "replace",
        "env": {**os.environ, "PYTHONIOENCODING": "utf-8"},
        "timeout": 600,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return kwargs


def pick_folder(initial: str = "") -> Path | None:
    """弹出系统原生"选择文件夹"对话框；取消或环境不支持时返回 None。

    通过**子进程**运行 tkinter，而不是在当前进程里直接调用。原因：Streamlit 的
    页面脚本运行在非主线程，而 Tcl/Tk 不是线程安全的——在非主线程里创建 Tk 并进入
    对话框事件循环有挂死整个页面的风险（表现为点了按钮页面永久卡住）。子进程拥有
    自己的主线程，且无图形界面（Docker/CI）时只会返回 None，页面不受影响，调用方可
    回退到手工粘贴路径。

    失败原因会写入日志（Streamlit 控制台可见），便于排查"点了没反应"。
    """
    try:
        proc = subprocess.run(
            [sys.executable, "-X", "utf8", "-c", _PICK_FOLDER_CODE, initial or ""],
            capture_output=True, text=True, **_subprocess_kwargs())
    except Exception as exc:  # noqa: BLE001 - 选目录失败绝不能让页面崩
        log.warning("文件夹选择对话框调用失败: %s: %s", type(exc).__name__, exc)
        return None
    if proc.returncode != 0:
        # 退出码 3 = 该解释器没有 tkinter；其他 = Tk 初始化/对话框报错
        log.warning("文件夹选择对话框子进程退出码 %s: %s",
                    proc.returncode, (proc.stderr or "").strip()[:400])
        return None
    return resolve_folder(proc.stdout)


def verdict_badge(verdict: str) -> str:
    """HUD 状态徽标：脉冲圆点 + 中英双语，边框发光。"""
    key = verdict.upper()
    fg, border, bg, zh, en = _VERDICT_STYLES.get(
        key, ("#94A3B8", "rgba(148, 163, 184, 0.4)", "rgba(148, 163, 184, 0.08)",
              verdict, verdict.upper()))
    return (f"<span class='vbadge' style='color:{fg};border-color:{border};"
            f"background:{bg};'><span class='hud-dot'></span>{zh} // {en}</span>")


def hud_header(en: str, zh: str, sub: str = "") -> None:
    """HUD 区块头：mono 大写英文标签 + 中文标题。"""
    sub_html = f"<div class='hud-head-sub'>{sub}</div>" if sub else ""
    st.markdown(
        f"<div class='hud-head'>"
        f"<div class='hud-head-label'>// {en}</div>"
        f"<div class='hud-head-title'>{zh}</div>"
        f"{sub_html}</div>",
        unsafe_allow_html=True,
    )


def radar_widget() -> None:
    """雷达扫描装饰件（纯 CSS 动画，6s 线性旋转）。"""
    st.markdown("<div class='hud-radar'></div>", unsafe_allow_html=True)


def sidebar_status(engine_version: str, rule_count: int) -> None:
    """侧边栏系统状态块：在线指示 + 规则集版本 + 结论色图例。

    填充导航下方的留白，同时展示真实运行时信息（每次页面运行时刷新）。
    """
    import html as _html
    v = _html.escape(engine_version)
    st.sidebar.markdown(
        f"<div class='hud-side-status'>"
        f"<div class='hud-side-row'><span class='hud-dot' style='color:#22C55E'></span>"
        f"SYSTEM ONLINE</div>"
        f"<div class='hud-side-row'><span class='k'>RULESET</span>"
        f"<span class='v'>{v}</span></div>"
        f"<div class='hud-side-row'><span class='k'>RULES</span>"
        f"<span class='v'>{rule_count}</span></div>"
        f"<div class='hud-side-legend'>"
        f"<div><span class='hud-dot' style='color:#EF4444'></span>MALICIOUS · 恶意</div>"
        f"<div><span class='hud-dot' style='color:#F97316'></span>SUSPICIOUS · 可疑</div>"
        f"<div><span class='hud-dot' style='color:#22C55E'></span>BENIGN · 正常</div>"
        f"</div></div>",
        unsafe_allow_html=True,
    )
