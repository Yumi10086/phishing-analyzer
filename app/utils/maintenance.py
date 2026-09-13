"""分析数据清理：清空报告文件 + 报告索引（可选情报查询缓存）。

只清理**分析产物**，不触碰规则、字典、样本与评估语料：
  - 报告文件   data/reports/*.json、*.html
  - 报告索引   cache.db 的 reports 表
  - 情报缓存   cache.db 的 intel_cache 表（可选：下次分析会重新查询情报源）

对外只暴露两个函数：先 ``analysis_data_stats()`` 预览、再 ``purge_analysis_data()`` 执行，
便于调用方（GUI/API）在执行前把"将删除什么"展示给使用者确认。
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from app.config import REPORTS_DIR
from app.utils.cache import cache
from app.utils.logger import get_logger

log = get_logger(__name__)

# 只删这两种扩展名，且只删 reports 目录的直接子文件（不递归、不碰子目录）
_REPORT_SUFFIXES = (".json", ".html")


def _report_files(reports_dir: Path) -> list[Path]:
    """列出待清理的报告文件；目录不存在或无权限时返回空列表。"""
    try:
        return [p for p in reports_dir.iterdir()
                if p.is_file() and p.suffix.lower() in _REPORT_SUFFIXES]
    except OSError as exc:
        log.warning("读取报告目录失败 %s: %s", reports_dir, exc)
        return []


def analysis_data_stats(cache_instance=None,
                        reports_dir: Path | None = None) -> dict[str, Any]:
    """预览当前分析数据规模（执行清理前展示给使用者确认）。

    ``cache_instance`` / ``reports_dir`` 留空时取模块级默认值（在调用时解析，
    便于测试用 monkeypatch 把二者指向临时目录，避免碰到真实数据）。
    """
    cache_instance = cache_instance or cache
    reports_dir = Path(reports_dir) if reports_dir else REPORTS_DIR
    files = _report_files(reports_dir)
    total_bytes = 0
    for p in files:
        try:
            total_bytes += p.stat().st_size
        except OSError:
            continue
    return {
        "report_files": len(files),
        "report_bytes": total_bytes,
        "indexed_reports": cache_instance.stats().get("total", 0),
        "intel_entries": cache_instance.count_intel(),
        "reports_dir": str(reports_dir),
    }


def purge_analysis_data(include_intel_cache: bool = False,
                        cache_instance=None,
                        reports_dir: Path | None = None) -> dict[str, Any]:
    """清空分析数据，返回各部分的实际删除量。可重复调用（幂等）。

    cache_instance / reports_dir 留空时取模块级默认值（调用时解析），
    便于测试在不触碰真实 ``data/cache.db`` 与 ``data/reports`` 的前提下验证清理语义。
    """
    cache_instance = cache_instance or cache
    reports_dir = Path(reports_dir) if reports_dir else REPORTS_DIR
    files = _report_files(reports_dir)
    removed_files = 0
    removed_bytes = 0
    for p in files:
        try:
            size = p.stat().st_size
            p.unlink()
        except OSError as exc:      # 被占用/无权限：跳过，不影响其余文件
            log.warning("删除报告文件失败 %s: %s", p, exc)
            continue
        removed_files += 1
        removed_bytes += size

    removed_index = cache_instance.clear_reports()
    removed_intel = cache_instance.clear_intel_cache() if include_intel_cache else 0

    log.info("分析数据已清理: 报告文件 %d 个(%.1f KB)、索引 %d 条、情报缓存 %d 条",
             removed_files, removed_bytes / 1024, removed_index, removed_intel)
    return {
        "removed_report_files": removed_files,
        "removed_bytes": removed_bytes,
        "removed_index_rows": removed_index,
        "removed_intel_rows": removed_intel,
        "intel_cache_cleared": bool(include_intel_cache),
    }
