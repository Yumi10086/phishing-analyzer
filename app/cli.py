"""命令行入口：

  python -m app.cli analyze data/samples/phishing_01.eml --html
  python -m app.cli batch data/samples --offline
  python -m app.cli serve --port 8000
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import sys
from pathlib import Path

from app.utils.logger import get_logger

log = get_logger(__name__)


def cmd_analyze(args: argparse.Namespace) -> int:
    from app.extractor.ioc_extractor import count_iocs
    from app.pipeline import analyze_file
    from app.response.thehive import create_alert

    path = Path(args.path)
    if not path.is_file():
        print(f"文件不存在: {path}")
        return 1

    report = asyncio.run(analyze_file(str(path), offline=args.offline))
    if args.thehive:
        report["thehive"] = create_alert(report)

    print(f"\n=== {path.name} ===")
    print(f"结论: {report['verdict']}  (评分 {report['score']}/100, 耗时 {report['processing_time_ms']}ms)")
    print(f"报告: {report.get('report_files', {}).get('json', '(未保存)')}")
    for r in report["reasons"][:10]:
        print(f"  - {r}")
    if len(report["reasons"]) > 10:
        print(f"  ... 共 {len(report['reasons'])} 条研判依据")
    return 0


def cmd_batch(args: argparse.Namespace) -> int:
    from app.pipeline import analyze_file

    directory = Path(args.directory)
    files = sorted(p for p in directory.iterdir()
                   if p.suffix.lower() in (".eml", ".msg"))
    if args.limit:
        files = files[: args.limit]
    if not files:
        print("目录中没有 .eml/.msg 文件")
        return 1

    out_path = Path(args.out)
    rows = []
    verdict_count = {"BENIGN": 0, "SUSPICIOUS": 0, "MALICIOUS": 0}
    for i, f in enumerate(files, 1):
        try:
            report = asyncio.run(analyze_file(str(f), offline=args.offline))
            verdict_count[report["verdict"]] = verdict_count.get(report["verdict"], 0) + 1
            rows.append({
                "filename": f.name, "verdict": report["verdict"],
                "score": report["score"], "iocs": count_iocs(report["iocs"]),
                "elapsed_ms": report["processing_time_ms"],
                "report_id": report["report_id"],
            })
            print(f"[{i}/{len(files)}] {f.name}: {report['verdict']} ({report['score']})")
        except Exception as exc:  # noqa: BLE001
            print(f"[{i}/{len(files)}] {f.name}: 解析失败 - {exc}")

    with out_path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    total = sum(verdict_count.values())
    print(f"\n批量完成 {total} 封 -> {out_path}")
    for v, c in verdict_count.items():
        pct = f"{c / total * 100:.0f}%" if total else "0%"
        print(f"  {v}: {c} ({pct})")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn
    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def cmd_purge(args: argparse.Namespace) -> int:
    """清空分析产物：报告文件 + 报告索引（可选情报缓存）。"""
    from app.utils.maintenance import analysis_data_stats, purge_analysis_data

    stats = analysis_data_stats()
    print(f"将清空：{stats['reports_dir']}")
    print(f"  报告文件 {stats['report_files']} 个（{stats['report_bytes'] / 1024:.0f} KB）"
          f"、索引 {stats['indexed_reports']} 条、情报缓存 {stats['intel_entries']} 条")
    print("  规则/字典/样本/评估语料不受影响。此操作不可撤销。")
    if not args.yes:
        answer = input("确认清空？输入 yes 继续: ").strip().lower()
        if answer != "yes":
            print("已取消。")
            return 1
    result = purge_analysis_data(include_intel_cache=args.include_intel_cache)
    print(f"已删除报告文件 {result['removed_report_files']} 个"
          f"（{result['removed_bytes'] / 1024:.0f} KB）、索引 {result['removed_index_rows']} 条"
          + (f"、情报缓存 {result['removed_intel_rows']} 条"
             if result["intel_cache_cleared"] else ""))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="钓鱼邮件自动化研判系统 CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser("analyze", help="分析单个邮件文件")
    p_analyze.add_argument("path", help=".eml / .msg 文件路径")
    p_analyze.add_argument("--offline", action="store_true", help="离线模式（跳过情报查询）")
    p_analyze.add_argument("--thehive", action="store_true", help="分析后创建 TheHive 工单")
    p_analyze.set_defaults(func=cmd_analyze)

    p_batch = sub.add_parser("batch", help="批量分析目录")
    p_batch.add_argument("directory", help="包含 .eml/.msg 的目录")
    p_batch.add_argument("--offline", action="store_true", help="离线模式")
    p_batch.add_argument("--limit", type=int, default=0, help="最多处理 N 封")
    p_batch.add_argument("--out", default="data/batch_results.csv", help="CSV 输出路径")
    p_batch.set_defaults(func=cmd_batch)

    p_serve = sub.add_parser("serve", help="启动 FastAPI 服务")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--reload", action="store_true")
    p_serve.set_defaults(func=cmd_serve)

    p_purge = sub.add_parser("purge", help="清空分析数据（报告文件 + 报告索引）")
    p_purge.add_argument("--include-intel-cache", action="store_true",
                         help="同时清空情报查询缓存（下次分析会重新查询情报源）")
    p_purge.add_argument("--yes", action="store_true", help="跳过确认（脚本/CI 用）")
    p_purge.set_defaults(func=cmd_purge)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
