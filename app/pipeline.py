"""分析流水线：解析 -> 附件内容分析(OCR/归档/Office/PDF) -> IOC 提取 -> 认证检查 -> 情报富化 -> 评分 -> 报告。"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from app.attachment.analyzer import annotate_attachments
from app.enrichment.enricher import Enricher
from app.extractor.auth_checker import check_auth
from app.extractor.ioc_extractor import extract_iocs
from app.parser.eml_parser import parse_eml
from app.parser.msg_parser import parse_msg
from app.response.report import build_report, save_report
from app.scoring.risk_engine import score_mail
from app.utils.logger import get_logger

log = get_logger(__name__)


async def analyze_bytes(raw: bytes, filename: str = "mail.eml",
                        offline: bool = False, save: bool = True,
                        source: str = "") -> dict[str, Any]:
    """核心分析入口：输入邮件原始字节，输出完整分析报告 dict。

    ``source`` 记录**这封邮件从哪来**（``mailbox`` = 邮箱取信、``upload`` = 界面上传、
    ``dir`` = 目录批量、空 = 未标注）。它让下游能按来源筛选（例如人工研判页"只看真实
    邮箱邮件"，避免样例/测试邮件淹没真信号）；老报告没有该字段，那边用文件名约定兜底。
    """
    start = time.perf_counter()
    lower = filename.lower()

    # 1. 解析
    if lower.endswith(".msg"):
        parsed = parse_msg(raw)
    else:
        parsed = parse_eml(raw)

    # 2. 附件内容分析（P1/P2）：OCR 图内文字回收、压缩包递归、Office 宏与远程模板、
    # PDF 关键字。**必须先于 IOC 提取**——OCR 文本直接并入 body_text，图内的
    # 钓鱼 URL/域名因此能走完整的「提取 -> VT/URLScan -> 情报 55 分」链路；
    # 结论同时写回 attachments[i] 的 archive/office/pdf 子字典供附件规则计分
    annotate_attachments(parsed)

    # 3. IOC 提取 + 4. 认证检查
    iocs = extract_iocs(parsed)
    auth = check_auth(parsed)

    # 5. 情报富化（离线模式跳过）
    enricher = Enricher(enabled=not offline)
    intel_results = await enricher.enrich(iocs)

    # 6. 评分（离线模式下按可用维度归一化到 0-100；内部完成类别判定与 SPAM 降档）
    scored = score_mail(parsed, iocs, auth, intel_results, offline=offline)

    # 6. 报告
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    report = build_report(filename, parsed, iocs, auth, scored, intel_results, elapsed_ms,
                          offline=offline, source=source)
    if save:
        paths = save_report(report)
        report["report_files"] = paths
    return report


async def analyze_file(path: str, offline: bool = False, save: bool = True,
                       source: str = "") -> dict[str, Any]:
    from pathlib import Path
    p = Path(path)
    raw = p.read_bytes()
    return await analyze_bytes(raw, filename=p.name, offline=offline, save=save, source=source)


def analyze_batch_item(args: tuple) -> dict[str, Any]:
    """多进程批量分析的 worker 入口（模块顶层函数，Windows spawn 可序列化）。

    args = (name_or_path, payload, offline, is_path[, source])：
      - is_path=True  时 payload 为文件路径（worker 内读取，免大字节跨进程传输）；
      - is_path=False 时 payload 为邮件原始字节（GUI 上传场景）；
      - 可选的 source 为来源标签（"mailbox"/"upload"/"dir"），写进报告供按来源筛选。
    **save=False**：报告落盘与索引由父进程串行执行——cache.db 是 sqlite，
    多进程并发写会造成锁竞争。

    异步说明：analyze_bytes 的 enricher 是流水线里唯一的 await（离线时 no-op），
    批量并行收益来自**多进程**（OCR 是 CPU 密集，asyncio 无益）。

    **worker 启动即重定向 stdout/stderr 到 devnull**：spawn 子进程会继承父进程的
    管道写句柄，只要有一个 worker 活着，外层管道（`python -m app.cli batch | grep`）
    就等不到 EOF 而表现为"永远挂起"（实测：重定向到文件 3s 正常完成、走管道无限
    等待）。批量 worker 的日志无价值，所有输出由父进程负责。

    **注意**：`dup2` 是进程级的——在主进程里直接调用本函数（例如写测试或临时验证脚本），
    会把**该进程后续的 stdout 一起吞掉**（缓冲内容也会丢），表现为"脚本跑完了但什么都没
    打印"。要验证它的返回值就写文件或断言，别指望 print。
    """
    import os
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    os.close(devnull)

    # 第 5 项（可选）是来源标签，如 "mailbox"。用 *rest 解包以保持**向后兼容**——
    # 旧的 4 元组调用点与既有测试不需要改。
    name_or_path, payload, offline, is_path, *rest = args
    source = str(rest[0]) if rest else ""
    if is_path:
        return asyncio.run(analyze_file(name_or_path, offline=offline, save=False, source=source))
    return asyncio.run(analyze_bytes(payload, filename=name_or_path,
                                     offline=offline, save=False, source=source))
