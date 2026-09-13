"""数据集基准评估：对带标签数据集（默认全钓鱼）离线批量研判，输出指标与漏判归因。

用法:
  python scripts/eval_dataset.py --dir ../phishing_pot-main/email --limit 500
  python scripts/eval_dataset.py --dir ../phishing_pot-main/email   # 全量

判定口径（SOC 惯例）:
  flagged = SUSPICIOUS + MALICIOUS（可疑即进入人工复核队列）
  recall_strict  = MALICIOUS / total
  recall_flagged = flagged / total
  miss = BENIGN（完全未拦截）
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.pipeline import analyze_bytes  # noqa: E402


async def main() -> None:
    parser = argparse.ArgumentParser(description="数据集基线评估（离线模式）")
    parser.add_argument("--dir", required=True, help="包含 .eml 的目录")
    parser.add_argument("--limit", type=int, default=0, help="最多评估 N 封（0=全量）")
    parser.add_argument("--out", default="data/eval_results.csv", help="CSV 输出路径")
    parser.add_argument("--skip", type=int, default=0, help="跳过前 N 个文件（用于分段评估）")
    args = parser.parse_args()

    directory = Path(args.dir)
    files = sorted(p for p in directory.iterdir() if p.suffix.lower() == ".eml")
    files = files[args.skip:] if args.skip else files
    if args.limit:
        files = files[: args.limit]
    print(f"待评估: {len(files)} 封（离线模式）")

    rows: list[dict] = []
    parse_fail = 0
    start = time.perf_counter()

    for i, f in enumerate(files, 1):
        try:
            raw = f.read_bytes()
            r = await analyze_bytes(raw, filename=f.name, offline=True, save=False)
        except Exception as exc:  # noqa: BLE001
            parse_fail += 1
            rows.append({"filename": f.name, "verdict": "PARSE_ERROR", "score": -1,
                         "n_urls": 0, "n_att": 0, "has_auth": "", "signals": "",
                         "subject_len": 0, "body_len": 0, "error": str(exc)[:80]})
            continue
        rows.append({
            "filename": f.name,
            "verdict": r["verdict"],
            "score": r["score"],
            "n_urls": len(r["iocs"]["urls"]),
            "n_att": len(r["attachments"]),
            "has_auth": r["auth"].get("spf") or "none-header",
            "signals": ";".join(s["id"] for s in r["signals"]),
            "subject_len": len(str(r.get("subject", ""))),
            "body_len": len(r.get("reasons", [])) and len(str(r)) // 100,  # 近似值，仅诊断用
            "error": "",
        })
        if i % 250 == 0:
            elapsed = time.perf_counter() - start
            print(f"  进度 {i}/{len(files)}  ({elapsed:.0f}s, {i / elapsed:.0f} 封/秒)")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    # ---- 指标汇总 ----
    valid = [r for r in rows if r["verdict"] != "PARSE_ERROR"]
    total = len(valid)
    c = Counter(r["verdict"] for r in valid)
    mal = c.get("MALICIOUS", 0)
    susp = c.get("SUSPICIOUS", 0)
    ben = c.get("BENIGN", 0)
    flagged = mal + susp

    print("\n========== 评估结果 ==========")
    print(f"样本总数: {len(rows)}  (解析失败 {parse_fail})")
    print(f"MALICIOUS : {mal:5d}  ({mal / total * 100:.1f}%)   <- 直接定性")
    print(f"SUSPICIOUS: {susp:5d}  ({susp / total * 100:.1f}%)   <- 转人工复核")
    print(f"BENIGN    : {ben:5d}  ({ben / total * 100:.1f}%)   <- 漏判")
    print(f"recall_strict  (仅恶意)   : {mal / total * 100:.1f}%")
    print(f"recall_flagged (恶+可疑)  : {flagged / total * 100:.1f}%")
    scores = [r["score"] for r in valid]
    print(f"平均分: {sum(scores) / total:.1f}  中位分: {sorted(scores)[total // 2]}")

    # ---- 信号触发排行 ----
    sig_all: Counter = Counter()
    for r in valid:
        for s in (r["signals"] or "").split(";"):
            if s:
                sig_all[s] += 1
    print("\n信号触发 TOP10（全体样本）:")
    for sig, n in sig_all.most_common(10):
        print(f"  {sig:28s} {n:5d} ({n / total * 100:.1f}%)")

    # ---- 漏判归因 ----
    misses = [r for r in valid if r["verdict"] == "BENIGN"]
    if misses:
        n = len(misses)
        no_url = sum(1 for r in misses if r["n_urls"] == 0)
        no_att = sum(1 for r in misses if r["n_att"] == 0)
        no_signal = sum(1 for r in misses if not r["signals"])
        no_auth = sum(1 for r in misses if r["has_auth"] in ("none", "none-header"))
        print(f"\n漏判归因（{n} 封 BENIGN）:")
        print(f"  无任何 URL        : {no_url:5d} ({no_url / n * 100:.0f}%)")
        print(f"  无任何附件        : {no_att:5d} ({no_att / n * 100:.0f}%)")
        print(f"  未触发任何信号    : {no_signal:5d} ({no_signal / n * 100:.0f}%)")
        print(f"  无 SPF/DKIM/DMARC : {no_auth:5d} ({no_auth / n * 100:.0f}%)")
        print("\n漏判样本信号分布 TOP10:")
        sig_miss: Counter = Counter()
        for r in misses:
            for s in (r["signals"] or "").split(";"):
                if s:
                    sig_miss[s] += 1
        for sig, cnt in sig_miss.most_common(10):
            print(f"  {sig:28s} {cnt:5d}")
    print(f"\n明细已写入: {out_path}")


if __name__ == "__main__":
    asyncio.run(main())
