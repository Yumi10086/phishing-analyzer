"""把 MISP warninglists（CC0 公有领域）的 top-domain 列表合并成本项目的可信域字典。

**为什么用 MISP 而不是直接下 Tranco**：Tranco 自身没有单一许可声明，它混合了上游
Majestic（CC BY 3.0）、CrUX（CC BY-SA 4.0）与 **Cloudflare Radar（CC BY-NC 4.0）**——
NC/SA 组件让"随开源仓库分发"有法律模糊空间。MISP 的 warninglists 是 **CC0 1.0**
（公有领域）的再分发，许可干净且已经过一轮 curation。详见 README_dev「可信域名清单」。

**要下载什么**（放到 ``data/trusted_sources/``，平铺或 ``<列表名>/list.json`` 子目录都行，
脚本递归找 ``*.json`` 并按内容识别）：
    https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/tranco10k/list.json
    https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/cisco_top1000/list.json
    https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/cloudflare-top1k/list.json
    https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/majestic_million/list.json
    https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/cloudflare-top200/list.json
（可选，反向用途：一次性邮箱域）
    https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/disposable-email/list.json

**排除**：清单会剔除 `rules/dicts/abuse_prone_platforms.txt` 里的易滥用平台（免费建站/网盘/
粘贴板/短链/用户内容 CDN/在线表单）——它们流量高但常年寄居钓鱼页面，**不能**因为"知名"就跳过
情报查询。

**用法**：
    python scripts/update_trusted_domains.py --dry-run     # 只统计，不写文件
    python scripts/update_trusted_domains.py               # 写 rules/dicts/trusted_domains.txt
    python scripts/update_trusted_domains.py --limit 5000  # 只保留前 N 条（控制仓库体积）

输出保持项目既有字典约定：``rules/dicts/*.txt``，每行一个词条、``#`` 注释、加载时做
混淆还原 + 小写；改字典会改变规则版本哈希，报告里的 ``rules_version`` 随之变化（可复现）。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT / "data" / "trusted_sources"
OUT_FILE = ROOT / "rules" / "dicts" / "trusted_domains.txt"

# 默认启用的源（按此顺序处理，署名统计也按此优先级）。
# **Majestic 默认关闭**：它的 top 10k 与 Tranco 的 top 10k 只重叠约 55%，多出来的近 9.4k
# 基本是长尾噪声（实测合并后把 `0123tt.ru`、`000webhostapp.com` 这类域带进来）。要全量用
# --sources all。
DEFAULT_SOURCES = ("tranco", "cisco", "cloudflare")
SOURCE_KEYS = ("tranco", "cisco", "cloudflare", "majestic")
_DOMAIN_RE = re.compile(r"^(?:\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$")


def _load_misp_list(path: Path) -> tuple[list[str], str]:
    """读一份 MISP warninglist JSON，返回 (词条, 列表名)。

    格式（MISP warninglists 约定）：``{"name":..., "version":..., "type":"hostname",
    "matching_attributes":[...], "list":["example.com", ...]}``。缺 ``list`` 直接报错，
    不静默返回空——"文件下错了"必须立刻看得见。
    """
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"读不了 {path.name}: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("list"), list):
        raise SystemExit(f"{path.name} 不是 MISP warninglist 格式（缺 list 字段）")
    return [str(x) for x in doc["list"]], str(doc.get("name") or path.stem)


def _normalize(entry: str) -> str:
    """词条归一化：小写、去首尾点、去通配前缀；不合形状的丢弃（返回空串）。

    输出按**可注册域**收敛（`mail.google.com` → `google.com`）：匹配侧一律按可注册域比，
    留着子域既匹配不到又白占体积。可注册域用的是项目现有 `registrable_domain()`——
    它是 eTLD+1 的近似实现（含 edu.cn/com.cn 等二级后缀表），够用；将来换 Public Suffix
    List 时改那一处即可，本脚本不受影响。
    """
    from app.scoring.features import registrable_domain

    text = (entry or "").strip().lower().lstrip("*.").strip(".")
    if not text or "/" in text or " " in text:
        return ""
    if not _DOMAIN_RE.match(text):
        return ""
    return registrable_domain(text) or text


def _load_exclusions(path: Path) -> set[str]:
    """读易滥用平台排除表（每行一个域，# 注释）。缺失时报错而不是静默不排除——
    "排除表没生效"会让 pages.dev / drive.google.com 这类域进入可信清单，属于静默漏检。"""
    if not path.is_file():
        raise SystemExit(f"排除表不存在：{path}（应先有 rules/dicts/abuse_prone_platforms.txt）")
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            out.add(line)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=str(SRC_DIR), help=f"warninglists 目录（默认 {SRC_DIR}）")
    ap.add_argument("--out", default=str(OUT_FILE), help=f"输出字典（默认 {OUT_FILE}）")
    ap.add_argument("--limit", type=int, default=0, help="最多写 N 条（0=不限）")
    ap.add_argument("--dry-run", action="store_true", help="只统计不写文件")
    ap.add_argument("--sources", default=",".join(DEFAULT_SOURCES),
                    help="启用哪些源（逗号分隔，或 all）；默认 "
                         + ",".join(DEFAULT_SOURCES) + "，Majestic 默认关闭（长尾噪声）")
    ap.add_argument("--exclude", default=str(ROOT / "rules" / "dicts" / "abuse_prone_platforms.txt"),
                    help="易滥用平台排除表（这些域流量高但不能当'可信'）")
    args = ap.parse_args()

    src = Path(args.src)
    # 递归找：直接平铺（list.json）与 MISP 仓库那样的 <列表名>/list.json 子目录都要认
    files = sorted(src.rglob("*.json")) if src.is_dir() else []
    wanted = SOURCE_KEYS if args.sources == "all" else tuple(args.sources.split(","))
    files = [p for p in files
             if any(k in p.parent.name.lower() or k in p.name.lower() for k in wanted)]
    excluded = _load_exclusions(Path(args.exclude))
    if not files:
        print(f"没找到 MISP warninglist JSON：{src}")
        print("按脚本头部注释里的 URL 下载到该目录后再跑。")
        return 2

    per_source: dict[str, int] = {}
    merged: dict[str, str] = {}          # 域 -> 首次出现的源名
    for path in files:
        entries, name = _load_misp_list(path)
        kept = skipped_risk = 0
        for raw in entries:
            dom = _normalize(raw)
            if not dom:
                continue
            if dom in excluded:
                skipped_risk += 1
                continue
            if dom not in merged:
                merged[dom] = name
                kept += 1
        per_source[name] = kept
        print(f"  {str(path.relative_to(src)):<30} {name:<34} 原始 {len(entries):>7} 条，"
              f"新增 {kept:>6} 条，排除易滥用 {skipped_risk:>4} 条")

    domains = sorted(merged)
    if args.limit:
        domains = domains[: args.limit]
    print(f"\n合并去重后 {len(merged)} 条，写出 {len(domains)} 条"
          f"（{len(set(merged) - set(domains))} 条被 --limit 截掉）")

    if args.dry_run:
        print("--dry-run：未写文件。前 10 条示例:", domains[:10])
        return 0

    lines = [
        "# 可信域名清单（知名/高流量域）：用于①情报富化跳过（省配额）②报告里把 header 域",
        "# 标为“身份上下文”而非 IOC ③链接域判定的豁免候选（判定侧改动需实测后再上）。",
        "#",
        "# **只当“知名”用，不当“安全”用**：钓鱼可以托管在 Google Forms / Dropbox /",
        "# SharePoint 这类知名域上，也可能拿知名域当诱饵链接——所以它不参与降权/豁免的直接",
        "# 结论，只在上述三处按各自口径使用。",
        "#",
        "# 来源：MISP warninglists（https://github.com/MISP/misp-warninglists，CC0 1.0 公有领域）",
        "#   —— 经其再分发的 Tranco / Cisco Umbrella / Cloudflare Radar / Majestic 榜单。",
        "#   不直接打包 Tranco 原始数据：其上游含 Cloudflare Radar(CC BY-NC 4.0) 与 CrUX",
        "#   (CC BY-SA 4.0)，随开源仓库分发有许可模糊空间。",
        f"# 生成时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}（脚本 scripts/update_trusted_domains.py）",
        f"# 条目数: {len(domains)}",
    ]
    for name, n in sorted(per_source.items(), key=lambda kv: -kv[1]):
        lines.append(f"#   - {name}: 新增 {n} 条")
    lines.append("# 匹配口径：可注册域（eTLD+1 近似），子域已收敛到主域。")
    lines.append("")
    lines += domains
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"已写入 {out}（{out.stat().st_size / 1024:.0f} KB）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
