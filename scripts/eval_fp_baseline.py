"""误报基线评估：用正常邮件语料（如 Enron ham）测量规则引擎的误报率。

判定口径（SOC 惯例）：正常邮件被判为 SUSPICIOUS 或 MALICIOUS 即为误报（FP），
因为它会占用分析师复核工时；MALICIOUS 误报代价更高（可能触发自动封禁）。

用法：
  python scripts/eval_fp_baseline.py --dir ../enron --limit 500
  python scripts/eval_fp_baseline.py --dir ../enron/enron1/ham   # 指定单个 ham 目录

输出：
  - 误报率（整体 / 分档）与分数分布
  - 触发 TOP 信号（误报驱动规则，用于针对性调权或加白名单）
  - 高分段误报样本明细（便于人工核对是否真误报）
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

# Enron 数据集常见的噪声信号：这些在真实 MTA 投递的邮件上本就不会出现，
# 统计时单列，避免误导调优方向。
_NOISE_SIGNALS = {"header_missing_auth"}


async def main() -> None:
    parser = argparse.ArgumentParser(description="误报基线评估（离线模式）")
    parser.add_argument("--dir", required=True, help="正常邮件目录（递归查找）")
    parser.add_argument("--limit", type=int, default=0, help="最多评估 N 封（0=全量）")
    parser.add_argument("--out", default="data/eval_fp_baseline.csv", help="CSV 输出")
    parser.add_argument("--sample", type=int, default=0, help="随机抽样 N 封（0=顺序取）")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    root = Path(args.dir)
    exts = {".txt", ".eml", ".msg"}
    files = sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in exts)
    # 只取正常邮件：若目录里含 ham/ 子目录则只取 ham
    ham_only = [p for p in files if "ham" in [seg.lower() for seg in p.parts]]
    if ham_only:
        print(f"检测到 ham/ 结构，仅使用正常邮件 {len(ham_only)} 封（忽略 spam/）")
        files = ham_only
    if args.sample and args.sample < len(files):
        import random
        random.seed(args.seed)
        files = random.sample(files, args.sample)
    if args.limit:
        files = files[: args.limit]
    if not files:
        print("未找到可评估的邮件文件")
        return

    print(f"误报基线评估：{len(files)} 封正常邮件（离线模式，纯本地规则）")

    rows: list[dict] = []
    parse_fail = 0
    start = time.perf_counter()
    for i, f in enumerate(files, 1):
        try:
            raw = f.read_bytes()
            r = await analyze_bytes(raw, filename=f.name, offline=True, save=False)
        except Exception as exc:  # noqa: BLE001
            parse_fail += 1
            continue
        rows.append({
            "filename": str(f.relative_to(root)),
            "verdict": r["verdict"],
            "score": r["score"],
            "signals": ";".join(s["id"] for s in r["signals"]),
            "raw_points": r.get("score_breakdown", {}).get("raw_signals_points", 0),
            "reasons": " | ".join(r["reasons"][:4]),
        })
        if i % 500 == 0:
            el = time.perf_counter() - start
            print(f"  进度 {i}/{len(files)} ({i / el:.0f} 封/秒)")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    # ---- 指标 ----
    total = len(rows)
    c = Counter(r["verdict"] for r in rows)
    mal, susp, ben = c.get("MALICIOUS", 0), c.get("SUSPICIOUS", 0), c.get("BENIGN", 0)
    fp = mal + susp
    print("\n========== 误报基线结果 ==========")
    print(f"样本总数: {total}  (解析失败 {parse_fail})")
    print(f"BENIGN    : {ben:5d}  ({ben / total * 100:.1f}%)   <- 正确放行")
    print(f"SUSPICIOUS: {susp:5d}  ({susp / total * 100:.1f}%)   <- 误报（转人工）")
    print(f"MALICIOUS : {mal:5d}  ({mal / total * 100:.1f}%)   <- 误报（定性）")
    print(f"\n误报率 FP (恶+可疑)     : {fp / total * 100:.2f}%")
    print(f"严重误报率 (仅 MALICIOUS): {mal / total * 100:.2f}%")
    print(f"正确放行率 (BENIGN)     : {ben / total * 100:.2f}%")

    scores = [r["score"] for r in rows]
    print(f"平均分: {sum(scores) / total:.1f}  中位分: {sorted(scores)[total // 2]}  "
          f"最高分: {max(scores)}")

    # ---- 误报驱动信号 ----
    sig_fp: Counter = Counter()
    sig_all: Counter = Counter()
    for r in rows:
        for s in (r["signals"] or "").split(";"):
            if s:
                sig_all[s] += 1
                if r["verdict"] != "BENIGN":
                    sig_fp[s] += 1
    print("\n误报样本信号 TOP10（误报主要来源）:")
    for sig, n in sig_fp.most_common(10):
        covered = sum(1 for r in rows if r["verdict"] != "BENIGN" and sig in r["signals"])
        print(f"  {sig:30s} 出现在 {n:5d}/{fp} 误报中")
    noise = {s: sig_all[s] for s in _NOISE_SIGNALS if sig_all.get(s)}
    if noise:
        print(f"\n噪声信号（数据集缺头部导致，真实投递不会出现）: {noise}")

    # ---- 高分段误报明细 ----
    high = sorted([r for r in rows if r["verdict"] != "BENIGN"],
                  key=lambda r: -r["score"])[:10]
    if high:
        print("\n高分段误报样本（建议人工核对是否真误报）:")
        for r in high:
            print(f"  [{r['score']:3d}] {r['filename'][:50]}")
            print(f"        {r['reasons'][:120]}")
    print(f"\n明细已写入: {out_path}")


if __name__ == "__main__":
    asyncio.run(main())
