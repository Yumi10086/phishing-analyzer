"""FastAPI 入口：/analyze /report /reports /health 接口。"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, HTMLResponse

from app import __version__
from app.config import REPORTS_DIR
from app.pipeline import analyze_bytes
from app.response.thehive import create_alert
from app.scoring import rule_admin
from app.scoring.rule_schema import RuleLoadError
from app.utils.cache import cache
from app.utils.logger import get_logger
from app.utils.maintenance import analysis_data_stats, purge_analysis_data

log = get_logger(__name__)

app = FastAPI(
    title="Phishing Analyzer API",
    description="钓鱼邮件自动化研判与响应系统：解析 → IOC 提取 → 情报富化 → 评分 → 报告 → 工单",
    version=__version__,
)


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "version": __version__}


@app.post("/analyze")
async def analyze(
    file: UploadFile | None = File(default=None),
    offline: bool = Query(default=False, description="离线模式：跳过威胁情报查询"),
    create_thehive: bool = Query(default=False, description="是否同步创建 TheHive 工单"),
) -> dict[str, Any]:
    """上传 .eml / .msg 文件进行自动化研判。"""
    if file is None:
        raise HTTPException(status_code=400, detail="请上传 .eml 或 .msg 文件（multipart 字段名: file）")
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="文件内容为空")
    if len(raw) > 20 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="文件超过 20MB 上限")

    try:
        report = await analyze_bytes(raw, filename=file.filename or "mail.eml", offline=offline)
    except Exception as exc:  # noqa: BLE001
        log.exception("分析失败: %s", exc)
        raise HTTPException(status_code=500, detail=f"分析失败: {exc}") from exc

    if create_thehive:
        report["thehive"] = create_alert(report)
    return report


@app.get("/reports")
async def list_reports(limit: int = Query(default=50, le=500), offset: int = 0) -> dict[str, Any]:
    """列出历史分析记录（含统计概览）。"""
    return {"stats": cache.stats(), "items": cache.list_reports(limit=limit, offset=offset)}


@app.get("/reports/stats")
async def report_data_stats() -> dict[str, Any]:
    """预览分析数据规模（清理前确认用）。"""
    return analysis_data_stats()


@app.delete("/reports")
async def purge_reports(
        include_intel_cache: bool = Query(default=False),
        confirm: bool = Query(default=False)) -> dict[str, Any]:
    """清空分析数据：报告文件 + 报告索引（可选连同情报查询缓存）。

    破坏性操作，必须显式 ``confirm=true``；只清理分析产物，不触碰规则/字典/样本。
    """
    if not confirm:
        raise HTTPException(status_code=400, detail="破坏性操作需显式 confirm=true")
    result = purge_analysis_data(include_intel_cache=include_intel_cache)
    return {"status": "purged", **result}


@app.get("/report/{report_id}")
async def get_report(report_id: str, format: str = Query(default="json", pattern="^(json|html)$")):
    """按 ID 获取历史报告（json 或 html）。"""
    meta = cache.get_report_meta(report_id)
    if not meta:
        raise HTTPException(status_code=404, detail="报告不存在")
    if format == "html":
        html_path = Path(meta["report_path"]).with_suffix(".html")
        if html_path.is_file():
            return HTMLResponse(html_path.read_text(encoding="utf-8"))
        raise HTTPException(status_code=404, detail="HTML 报告不存在")
    json_path = Path(meta["report_path"])
    if not json_path.is_file():
        raise HTTPException(status_code=404, detail="报告文件不存在")
    return json.loads(json_path.read_text(encoding="utf-8"))


@app.get("/report/{report_id}/download")
async def download_report(report_id: str):
    meta = cache.get_report_meta(report_id)
    if not meta:
        raise HTTPException(status_code=404, detail="报告不存在")
    path = Path(meta["report_path"])
    if not path.is_file():
        raise HTTPException(status_code=404, detail="报告文件不存在")
    return FileResponse(path, media_type="application/json", filename=path.name)


# ---------------- 规则管理（SIEM 式自定义规则） ----------------

def _admin_error(exc: Exception) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


@app.get("/rules")
async def get_rules() -> dict[str, Any]:
    """列出当前规则集（含来源 builtin/custom、开关与分值）。"""
    return rule_admin.list_rules()


@app.post("/rules", status_code=201)
async def create_rule(rule: dict[str, Any]) -> dict[str, Any]:
    """新建（或整体覆盖同 id）自定义规则，写入 rules/custom/ 并立即生效。"""
    try:
        return rule_admin.upsert_custom_rule(rule)
    except (rule_admin.RuleAdminError, RuleLoadError) as exc:
        raise _admin_error(exc) from exc


@app.put("/rules/{rule_id}")
async def patch_rule(rule_id: str, patch: dict[str, Any]) -> dict[str, Any]:
    """局部修改规则元数据（enabled/points/name/description/reason）。"""
    try:
        return rule_admin.update_rule(rule_id, patch)
    except (rule_admin.RuleAdminError, RuleLoadError) as exc:
        raise _admin_error(exc) from exc


@app.delete("/rules/{rule_id}")
async def remove_rule(rule_id: str) -> dict[str, Any]:
    """删除自定义覆盖文件（恢复内置默认）。"""
    try:
        return rule_admin.delete_rule(rule_id)
    except (rule_admin.RuleAdminError, RuleLoadError) as exc:
        raise _admin_error(exc) from exc


@app.post("/rules/reload")
async def reload_rule_engine() -> dict[str, Any]:
    """从磁盘热重载规则集与字典。"""
    try:
        return rule_admin.reload()
    except RuleLoadError as exc:
        raise _admin_error(exc) from exc


@app.get("/rules/dicts")
async def get_dicts() -> dict[str, Any]:
    """列出全部字典内容（brands/tlds/shorteners/关键词）。"""
    return rule_admin.list_dicts()


@app.post("/rules/dicts/{dict_name}")
async def append_dict(dict_name: str, entries: list[str] = Body(...)) -> dict[str, Any]:
    """向字典追加词条（去重后写入并重载）。"""
    try:
        return rule_admin.append_dict_entries(dict_name, entries)
    except (rule_admin.RuleAdminError, RuleLoadError) as exc:
        raise _admin_error(exc) from exc


@app.post("/rules/test")
async def test_rules(
    file: UploadFile = File(...),
    rule_id: str | None = Query(default=None, description="只看指定规则的命中结果"),
) -> dict[str, Any]:
    """用样本邮件试跑当前规则集（离线、不落盘），返回命中信号。"""
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="文件内容为空")
    try:
        return rule_admin.test_on_bytes(raw, filename=file.filename or "mail.eml",
                                        rule_id=rule_id)
    except RuleLoadError as exc:
        raise _admin_error(exc) from exc
