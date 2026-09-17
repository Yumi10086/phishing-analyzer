"""人工标注集导出（L4 第一步）：把带人工判定的邮件落成可复用的评测语料。

产物结构：
  data/labeled/
    benign/    *.eml        人工确认"正常·营销"的发件人发来的邮件
    phishing/  *.eml        人工确认"钓鱼"的发件人发来的邮件
    manifest.csv            每封的来源、发件人、标注作用域、当前判定/分数/信号

为什么需要它：人工判断的价值不在"当场改行为"（那是 L1 的降权，可被投毒），而在**变成评测集**——
后续每次调权都能用这批真实样本做 A/B，回答"这条规则到底该不该降权"。这也是本项目每轮
规则迭代一直在手工做的事（测量 → 改 → 门禁对照），把它自动化。
"""
from __future__ import annotations

import csv
import re
import shutil
from pathlib import Path

from app.utils.logger import get_logger

log = get_logger(__name__)


# 邮箱取信落盘的文件名约定：save_mail() 写的是 `{序号:05d}_uid{UID}_{主题}.eml`
MAILBOX_NAME_RE = re.compile(r"^\d{5}_uid\d+_")


def is_mailbox_mail(filename: str = "", source: str = "",
                    mailbox_names: set[str] | None = None) -> bool:
    """判断一份报告是不是"真实邮箱邮件"（用于人工研判页按来源过滤）。

    三级判据，从可靠到兜底：
      1. 报告的 ``source`` 字段（新报告有，最可靠）；
      2. 文件名是否出现在 `data/mailbox/` 的实际文件集里（老报告可精确匹配）；
      3. 文件名是否符合邮箱落盘约定 ``00048_uid2124_主题.eml``（老报告兜底）。

    加这一层的动机：样例/测试邮件（``phishing_01.eml``、``p.eml`` 等）会在报告列表里
    重复出现几百条，把真实邮箱邮件淹没——研判时看到的"误报"多数来自它们。
    """
    if source:
        return source == "mailbox"
    name = (filename or "").strip()
    if not name:
        return False
    if mailbox_names and name in mailbox_names:
        return True
    return bool(MAILBOX_NAME_RE.match(name))


def sender_keys(items: list[tuple[str, str]], scope_domain: bool = False) -> list[tuple[str, str]]:
    """把 [(地址, 可注册域)] 折叠成去重后的标注键 [(scope, key)]。

    批量标注必须按**发件人**去重：一次勾 20 封邮件可能只涉及 3 个发件人，不去重会写 20 次
    （结果相同但浪费、且标注列表会被噪声填满）。抽成函数是为了可单测——这段逻辑原先写在
    GUI 页面里，只能靠点界面验证。
    """
    keys: set[tuple[str, str]] = set()
    for addr, domain in items:
        addr = (addr or "").lower().strip()
        if "@" not in addr:
            continue
        if scope_domain:
            keys.add(("domain", (domain or addr.split("@")[-1]).lower()))
        else:
            keys.add(("addr", addr))
    return sorted(keys)


def apply_batch(pairs: list[tuple[str, str]], verdict: str, scope_domain: bool = False,
                days: int | None = None, source: str = "gui", note: str = "") -> int:
    """批量写入人工判定（按发件人去重）。返回实际写入的条数。

    从页面搬到这里是为了可单测：批量处置的"去重 + 落库"是这条链路最容易出错的一段
    （勾 20 封邮件通常只涉及几个发件人；作用域选错会把标注扩散到整个域）。
    """
    from app.utils.cache import cache

    keys = sender_keys(pairs, scope_domain=scope_domain)
    for scope, key in keys:
        cache.set_human_verdict(scope, key, verdict, days=days, source=source, note=note)
    return len(keys)


def revoke_batch(keys: list[tuple[str, str]]) -> int:
    """批量撤销人工判定，返回实际删除行数。"""
    from app.utils.cache import cache

    n = 0
    for scope, key in keys:
        n += cache.delete_human_verdict(scope, key)
    return n


def _sender_marks() -> tuple[dict[str, str], dict[str, str]]:
    """返回 (地址→标注, 域→标注)；地址级优先。"""
    from app.utils.cache import cache

    by_addr: dict[str, str] = {}
    by_domain: dict[str, str] = {}
    for v in cache.list_human_verdicts():
        (by_addr if v["scope"] == "addr" else by_domain)[v["key"]] = v["verdict"]
    return by_addr, by_domain


def export(root: Path, out_dir: Path, analyzed: bool = True) -> dict[str, int]:
    """导出标注集。``analyzed=True`` 时同时记录当前判定/分数/信号（供归因对照）。"""
    from app.mailbox.imap_client import is_self_sent, own_addresses
    from app.scoring.features import parse_from_header, registrable_domain

    by_addr, by_domain = _sender_marks()
    if not by_addr and not by_domain:
        log.warning("没有任何人工判定，先分析并在 GUI 里标注")
        return {"benign": 0, "phishing": 0, "skipped": 0}

    own = own_addresses()
    files = sorted(root.rglob("*.eml")) if root.is_dir() else []
    out_dir.mkdir(parents=True, exist_ok=True)
    for sub in ("benign", "phishing"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    rows: list[dict] = []
    counts = {"benign": 0, "phishing": 0, "skipped": 0}
    for p in files:
        raw = p.read_bytes()
        if is_self_sent(raw, own, folder=p.parent.name):
            continue
        try:
            _name, addr, _dom = parse_from_header({"from": _header(raw, "From")})
        except Exception:  # noqa: BLE001
            counts["skipped"] += 1
            continue
        addr = (addr or "").lower()
        dom = registrable_domain(addr.split("@")[-1]) if "@" in addr else ""
        label = by_addr.get(addr) or by_domain.get(dom) or ""
        if not label:
            counts["skipped"] += 1
            continue
        dest = out_dir / label / f"{p.parent.name}__{p.name}"
        try:
            shutil.copyfile(p, dest)
        except OSError:
            counts["skipped"] += 1
            continue
        counts[label] += 1
        row = {"file": str(dest), "source": str(p), "from": addr, "domain": dom,
               "label": label, "analyzed": ""}
        if analyzed:
            import asyncio

            from app.pipeline import analyze_bytes

            try:
                r = asyncio.run(analyze_bytes(raw, p.name, offline=True, save=False))
                row.update({"verdict": r["verdict"], "score": r["score"],
                            "signals": ";".join(s["id"] for s in r["signals"]),
                            "report_id": r["report_id"], "analyzed": "1"})
            except Exception:  # noqa: BLE001
                row.update({"verdict": "", "score": "", "signals": "", "report_id": ""})
        rows.append(row)

    manifest = out_dir / "manifest.csv"
    if rows:
        with manifest.open("w", newline="", encoding="utf-8-sig") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
    log.info("标注集导出: %s -> %s", counts, manifest)
    return counts


def _header(raw: bytes, name: str) -> str:
    from email import message_from_bytes

    try:
        return str(message_from_bytes(raw[:65536]).get(name) or "")
    except Exception:  # noqa: BLE001
        return ""
