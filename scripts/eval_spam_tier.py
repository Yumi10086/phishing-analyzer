"""垃圾/钓鱼分离（SPAM 档）分类别评估：测降档率、类别分布与红线指标。

用法：
  python scripts/eval_spam_tier.py --dir <eml目录> [--sample N --seed 42] [--out data/xxx.csv]
  python scripts/eval_spam_tier.py --dir data/datacon2023-spoof-email-main/day1 \
                                   --dir data/datacon2023-spoof-email-main/day2 --workers 8

输出：
  - verdict × category 交叉分布
  - SPAM 降档统计：降档数 / 占非 BENIGN 比例 / 降档样本认证构成
  - 分档 TOP 信号（人工复核降档是否夹带钓鱼）
  - 全量明细 CSV（供红线抽查与回归测试抽样）

设计说明：
  - 统一离线模式（不查情报）：评估的是启发式 + 认证维度的确定性结论，不受
    API 配额与缓存状态影响，可重复；
  - 多进程：analyze_bytes 的解析/规则求值是 CPU 密集，asyncio 并发无收益；
  - 行内保留 spf/dkim/dmarc 原始结果，供回归测试复核"降档必带认证通过"。
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import os
import random
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.pipeline import analyze_bytes  # noqa: E402


def _eval_one(path: str) -> dict | None:
    """子进程 worker：单封邮件离线分析，返回明细行。"""
    try:
        p = Path(path)
        raw = p.read_bytes()
        r = asyncio.run(analyze_bytes(raw, p.name, offline=True, save=False))
        auth = r.get("auth", {}) or {}
        return {
            "file": str(p),
            "score": r["score"],
            "verdict": r["verdict"],
            "category": r.get("category", "unknown"),
            "signals": ";".join(s["id"] for s in r["signals"]),
            "spf": auth.get("spf") or "",
            "dkim": auth.get("dkim") or "",
            "dmarc": auth.get("dmarc") or "",
        }
    except Exception as exc:  # noqa: BLE001 - 单封失败不影响整体统计
        print(f"[跳过] {path}: {exc}", file=sys.stderr)
        return None


def collect_files(dirs: list[Path], sample: int, seed: int) -> list[Path]:
    files: list[Path] = []
    for d in dirs:
        files += sorted(p for p in d.rglob("*") if p.suffix.lower() in (".eml", ".msg", ".txt"))
    if sample and sample < len(files):
        rng = random.Random(seed)
        files = rng.sample(files, sample)
    return files


def summarize(rows: list[dict], label: str) -> None:
    total = len(rows)
    print(f"\n===== {label}（{total} 封）=====")
    vc = Counter(r["verdict"] for r in rows)
    cc = Counter(r["category"] for r in rows)
    print("verdict 分布:", dict(vc.most_common()))
    print("category 分布:", dict(cc.most_common()))

    # verdict × category 交叉表
    cross: dict[str, Counter] = {}
    for r in rows:
        cross.setdefault(r["category"], Counter())[r["verdict"]] += 1
    print("verdict × category:")
    for cat, c in sorted(cross.items()):
        print(f"  {cat:10s}: {dict(c.most_common())}")

    non_benign = total - vc.get("BENIGN", 0)
    spam_rows = [r for r in rows if r["verdict"] == "SPAM"]
    if non_benign:
        print(f"SPAM 降档: {len(spam_rows)} 封（占非 BENIGN {len(spam_rows) / non_benign * 100:.1f}%）")
        auth_ok = sum(1 for r in spam_rows
                      if "pass" in (r["spf"], r["dkim"], r["dmarc"]))
        print(f"  降档样本认证通过率: {auth_ok}/{len(spam_rows)}")
        print("  降档样本 TOP 信号:")
        for s, n in Counter(sig for r in spam_rows for sig in r["signals"].split(";") if sig).most_common(8):
            print(f"    {s}: {n}")
        # 红线线索：降档样本里命中"凭证索取类"规则的数量（应为 0/极低）
        cred = [r for r in spam_rows
                if {"body_credential_solicitation", "body_credentials",
                    "body_credentials_no_link", "html_password_field"} & set(r["signals"].split(";"))]
        print(f"  ⚠️ 降档但含凭证索取信号: {len(cred)} 封（应≈0）")

    flagged = sum(1 for r in rows if r["verdict"] != "BENIGN")
    if total:
        print(f"flagged 召回（SUSPICIOUS+SPAM+MALICIOUS）: {flagged}/{total} = {flagged / total * 100:.1f}%")
        mal = vc.get("MALICIOUS", 0)
        print(f"MALICIOUS 占比: {mal / total * 100:.1f}%")

    print("MALICIOUS 档 TOP 信号:")
    mal_rows = [r for r in rows if r["verdict"] == "MALICIOUS"]
    for s, n in Counter(sig for r in mal_rows for sig in r["signals"].split(";") if sig).most_common(8):
        print(f"    {s}: {n}")


def main() -> None:
    parser = argparse.ArgumentParser(description="SPAM 档分类别评估（离线、多进程）")
    parser.add_argument("--dir", action="append", required=True, help="邮件目录（可多次指定，递归）")
    parser.add_argument("--sample", type=int, default=0, help="随机抽样 N 封（0=全量）")
    parser.add_argument("--seed", type=int, default=20260914)
    parser.add_argument("--workers", type=int, default=0, help="并行进程数（0=CPU 核数一半）")
    parser.add_argument("--out", default="data/eval_spam_tier.csv", help="明细 CSV 输出")
    parser.add_argument("--label", default="", help="报告标题")
    args = parser.parse_args()

    dirs = [Path(d) for d in args.dir]
    files = collect_files(dirs, args.sample, args.seed)
    if not files:
        print("未找到可评估的邮件文件")
        return
    workers = args.workers or max(1, (os.cpu_count() or 4) // 2)
    print(f"评估 {len(files)} 封（workers={workers}，离线模式）...")
    with ProcessPoolExecutor(max_workers=workers) as pool:
        results = pool.map(_eval_one, [str(p) for p in files], chunksize=16)
    rows = [r for r in results if r]

    label = args.label or "、".join(d.name for d in dirs)
    summarize(rows, label)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"\n明细已写入 {out}")


if __name__ == "__main__":
    main()
