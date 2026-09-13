"""报告生成：JSON 报告落盘 + HTML 战术报告（Sci-Fi HUD 风格，内嵌模板零依赖）。"""
from __future__ import annotations

import html
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import REPORTS_DIR
from app.extractor.ioc_extractor import count_iocs
from app.utils.cache import cache

# HUD 状态语义色：Danger / Warning / Success
_VERDICT_COLORS = {
    "MALICIOUS": ("#EF4444", "恶意"),
    "SUSPICIOUS": ("#F97316", "可疑"),
    "BENIGN": ("#22C55E", "正常"),
}


def new_report_id() -> str:
    return uuid.uuid4().hex[:16]


def build_report(filename: str, parsed: dict[str, Any], iocs: dict[str, Any],
                 auth: dict[str, Any], scored: dict[str, Any],
                 intel_results: list[dict[str, Any]], elapsed_ms: int,
                 offline: bool = False) -> dict[str, Any]:
    """组装统一的 JSON 报告结构。

    ``offline`` 会落盘：报告此前不记录分析模式，导致事后无法区分"没查情报"与
    "查了但无有效数据"，用户也容易把旧报告当成新报告。
    """
    return {
        "report_id": new_report_id(),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "filename": filename,
        "offline": bool(offline),
        "processing_time_ms": elapsed_ms,
        "source_format": parsed.get("source_format"),
        "score": scored["score"],
        "verdict": scored["verdict"],
        "reasons": scored["reasons"],
        "score_breakdown": scored["breakdown"],
        "signals": scored.get("signals", []),
        "auth": auth,
        "iocs": iocs,
        "intel": intel_results,
        "headers": parsed.get("headers", {}),
        "attachments": parsed.get("attachments", []),
        "subject": parsed.get("headers", {}).get("subject", ""),
        "from": parsed.get("headers", {}).get("from", ""),
    }


def save_report(report: dict[str, Any]) -> dict[str, str]:
    """JSON + HTML 落盘，并写入报告索引。返回路径字典。"""
    rid = report["report_id"]
    json_path = REPORTS_DIR / f"{rid}.json"
    html_path = REPORTS_DIR / f"{rid}.html"

    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    html_path.write_text(render_html(report), encoding="utf-8")

    cache.index_report(rid, report.get("filename", ""), report.get("verdict", ""),
                       report.get("score", 0), report.get("created_at", ""),
                       count_iocs(report["iocs"]), str(json_path))
    return {"json": str(json_path), "html": str(html_path)}


def _intel_empty_note(report: dict[str, Any]) -> str:
    """INTEL 段为空时的说明。

    空的原因有三种，必须说清是哪一种，否则使用者会误以为"提取到 IOC 但没送去富化"：
      1. 旧版报告未记录分析模式 —— 不可臆断；
      2. 离线模式 —— 本轮没查；
      3. 在线但邮件里没有可提取的外部 IOC —— 没有东西可查（此前的"已查询，但邮件中
         没有可用的 IOC"读起来像已经查过了）。
    """
    if "offline" not in report:
        return "<tr><td>（无情报数据：旧版报告未记录分析模式）</td></tr>"
    if report.get("offline"):
        return "<tr><td>（离线模式：本次未查询威胁情报）</td></tr>"
    return "<tr><td>（未发出查询：邮件中没有可提取的 IOC）</td></tr>"


def render_html(report: dict[str, Any]) -> str:
    color, label = _VERDICT_COLORS.get(report.get("verdict", ""), ("#94A3B8", "未知"))
    # 徽标淡色底（HUD 暗色系）
    bg = {"MALICIOUS": "rgba(239, 68, 68, 0.08)",
          "SUSPICIOUS": "rgba(249, 115, 22, 0.08)",
          "BENIGN": "rgba(34, 197, 94, 0.08)"}.get(
        report.get("verdict", ""), "rgba(148, 163, 184, 0.08)")
    e = html.escape
    if "offline" not in report:      # 旧版报告无此字段 -> 如实标注"未记录"，不臆断
        mode_label = "未记录（旧版报告）"
    else:
        mode_label = "离线（未查询威胁情报）" if report["offline"] else "在线（已查询威胁情报）"

    ioc_rows = ""
    for kind, items in report.get("iocs", {}).items():
        if not items:
            continue
        ioc_rows += (f'<tr><td class="k">{e(kind)}</td>'
                     f'<td>{e("; ".join(map(str, items[:15])))}</td></tr>')

    intel_rows = ""
    for item in report.get("intel", []):
        badge = {"hit": "命中", "clean": "干净", "unknown": "无历史",
                 "no_key": "未启用", "error": "错误"}.get(item.get("status"), item.get("status", ""))
        intel_rows += (f"<tr><td>{e(item.get('source', ''))}</td>"
                       f"<td>{e(item.get('ioc', ''))}</td>"
                       f"<td>{e(badge)}</td>"
                       f"<td>{e(str(item.get('malicious_score', 0)))}</td>"
                       f"<td>{e(item.get('summary', ''))}</td></tr>")

    reason_items = "".join(f"<li>{e(r)}</li>" for r in report.get("reasons", []))
    att_rows = "".join(
        f"<tr><td>{e(a['filename'])}</td><td>{e(a['content_type'])}</td>"
        f"<td>{a['size']}</td><td class='mono'>{e(a['sha256'][:16])}…</td></tr>"
        for a in report.get("attachments", []))

    breakdown = report.get("score_breakdown", {})
    b = breakdown.get("weights", {})

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>TACTICAL REPORT {e(report.get('report_id', ''))}</title>
<style>
 /* Sci-Fi HUD 战术报告：深空底 + 青色发光 + 等宽标签；中文回退系统字体 */
 body {{ font-family: 'JetBrains Mono', ui-monospace, Consolas, 'PingFang SC',
        'Microsoft YaHei', monospace; margin: 0; background: #020617;
        color: #E5F2FF; font-size: 14px; -webkit-font-smoothing: antialiased; }}
 body::before {{ content: ''; position: fixed; inset: 0; pointer-events: none; z-index: 9;
        background: repeating-linear-gradient(0deg, rgba(34,211,238,.02) 0 1px,
                    transparent 1px 3px); }}
 .wrap {{ max-width: 920px; margin: 32px auto; position: relative;
         background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(6, 182, 212, 0.30);
         border-radius: 4px; padding: 36px;
         box-shadow: 0 0 25px rgba(6, 182, 212, 0.25), inset 0 0 40px rgba(6, 182, 212, 0.03); }}
 .wrap::before {{ content: ''; position: absolute; top: -1px; left: -1px; width: 16px; height: 16px;
        border-top: 2px solid #22D3EE; border-left: 2px solid #22D3EE; }}
 .wrap::after {{ content: ''; position: absolute; bottom: -1px; right: -1px; width: 16px; height: 16px;
        border-bottom: 2px solid #22D3EE; border-right: 2px solid #22D3EE; }}
 .label {{ font-size: .66rem; font-weight: 500; letter-spacing: .18em;
        text-transform: uppercase; color: #22D3EE;
        text-shadow: 0 0 10px rgba(34, 211, 238, .5); margin-bottom: .4rem; }}
 h1 {{ font-size: 1.25rem; font-weight: 700; letter-spacing: .04em; margin: 0 0 .6rem;
       display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }}
 .verdict {{ display: inline-flex; align-items: center; gap: 8px; padding: 3px 12px;
        border-radius: 3px; color: {color}; background: {bg};
        border: 1px solid {color}; font-size: .8125rem; font-weight: 500;
        letter-spacing: .08em; text-transform: uppercase;
        text-shadow: 0 0 10px {color}; }}
 .score {{ font-size: 2rem; font-weight: 700; letter-spacing: -0.01em;
        color: #E5F2FF; font-variant-numeric: tabular-nums;
        text-shadow: 0 0 16px rgba(34, 211, 238, .45); }}
 .dot {{ display: inline-block; width: 7px; height: 7px; border-radius: 50%;
        background: currentColor; animation: pulse 2s ease-in-out infinite; }}
 @keyframes pulse {{ 0%,100% {{ opacity: 1; box-shadow: 0 0 8px currentColor; }}
        50% {{ opacity: .35; box-shadow: 0 0 2px currentColor; }} }}
 @media (prefers-reduced-motion: reduce) {{ .dot {{ animation: none; }} }}
 .sub {{ color: #94A3B8; font-size: .8125rem; line-height: 1.7; }}
 .sub b {{ color: #E5F2FF; }}
 h2 {{ font-size: .8rem; font-weight: 500; letter-spacing: .12em; color: #22D3EE;
       text-transform: uppercase; margin: 1.8rem 0 .6rem; padding-bottom: .4rem;
       border-bottom: 1px solid rgba(6, 182, 212, 0.22); }}
 table {{ width: 100%; border-collapse: collapse; font-size: .8125rem; }}
 td {{ padding: 7px 10px; text-align: left; vertical-align: top; word-break: break-all;
       border-bottom: 1px solid rgba(6, 182, 212, 0.12); color: #cbd5e1; }}
 td.k {{ color: #94A3B8; width: 150px; white-space: nowrap; }}
 ul {{ padding-left: 1.2rem; margin: .5rem 0; }}
 li {{ margin: .35rem 0; font-size: .8125rem; line-height: 1.7; color: #cbd5e1; }}
 .meta {{ color: #64748b; font-size: .7rem; margin-top: 2rem; padding-top: .9rem;
          border-top: 1px solid rgba(6, 182, 212, 0.16); line-height: 1.8; }}
</style></head>
<body><div class="wrap">
<div class="label">// TACTICAL REPORT // PHISHING ANALYZER</div>
<h1>钓鱼邮件分析报告
<span class="verdict"><span class="dot"></span>{label} {e(report.get('verdict', ''))}</span>
<span class="score">{report.get('score', 0)}</span></h1>
<p class="sub">TARGET <b>{e(report.get('filename', ''))}</b> ｜ 阈值 BENIGN &lt;30 ≤ SUSPICIOUS &lt;55 ≤ MALICIOUS</p>

<h2>// REASONING 研判依据</h2><ul>{reason_items}</ul>

<h2>// SCORE BREAKDOWN 评分构成</h2>
<table>
<tr><td class="k">威胁情报 ({b.get('intel', 55)}%)</td><td>{breakdown.get('intel', '-')}</td></tr>
<tr><td class="k">邮件认证 ({b.get('auth', 15)}%)</td><td>{breakdown.get('auth', '-')}</td></tr>
<tr><td class="k">启发式规则 ({b.get('heuristic', 30)}%)</td><td>{breakdown.get('heuristic', '-')}</td></tr>
</table>

<h2>// AUTH 认证结果</h2>
<table>
<tr><td class="k">SPF</td><td>{e(str(report.get('auth', {}).get('spf', 'N/A')))}</td>
    <td class="k">DKIM</td><td>{e(str(report.get('auth', {}).get('dkim', 'N/A')))}</td></tr>
<tr><td class="k">DMARC</td><td>{e(str(report.get('auth', {}).get('dmarc', 'N/A')))}</td>
    <td class="k">Reply-To</td><td>{e(str(report.get('auth', {}).get('reply_to_domain', '-')))}</td></tr>
</table>

<h2>// IOC</h2><table>{ioc_rows}</table>
<h2>// INTEL 情报富化</h2><table>{intel_rows or _intel_empty_note(report)}</table>
<h2>// ATTACHMENTS 附件</h2><table>{att_rows or '<tr><td>无附件</td></tr>'}</table>

<p class="meta">MODE: {e(mode_label)} ｜
REPORT ID: {e(report.get('report_id', ''))} ｜
GENERATED: {e(report.get('created_at', ''))} ｜
LATENCY: {report.get('processing_time_ms', 0)} ms ｜
PHISHING ANALYZER v0.1</p>
</div></body></html>"""
