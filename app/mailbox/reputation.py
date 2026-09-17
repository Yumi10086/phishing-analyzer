"""往来历史构建：从本地已取到的邮件里统计发件人，供信任上下文判定。

数据来源就是取信时顺手落下的 `.eml`，不需要任何新数据源：
  - **入站**（收件箱/垃圾箱等）：每个发件地址的累计封数、首末时间、历史用过的链接域；
  - **已发送**：To/Cc 收件人 = "你写过信的人"（最强信任信号，攻击者拿不到）。

只在取信/重跑分析时调用。**幂等性靠"先清空再重建"**：这里按文件遍历，重复调用同一目录会
重复累加，把计数吹大（计数直接决定信任档，吹大等于自毁门槛）。在此之上再加一层"输入没变
就跳过"的指纹比对（见 ``rebuild``），避免把几秒的重扫浪费在没有任何新邮件的重复调用上。
"""
from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from email import message_from_bytes
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path

from app.utils.logger import get_logger

log = get_logger(__name__)

_URL_HOST_RE = re.compile(r"^[a-z]+://([^/:?#]+)")


def _header(raw: bytes, name: str) -> str:
    try:
        return str(message_from_bytes(raw[:65536]).get(name) or "")
    except Exception:  # noqa: BLE001
        return ""


def _addrs(raw: bytes, name: str) -> list[str]:
    return [a.lower() for _, a in getaddresses([_header(raw, name)]) if a]


def _seen_at(raw: bytes) -> str:
    """取 Date 头（UTC ISO）；缺失时用当前时间兜底（宁可计入，不要漏记）。"""
    try:
        dt = parsedate_to_datetime(_header(raw, "Date"))
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:  # noqa: BLE001
        return datetime.now(timezone.utc).isoformat()


def _fingerprint(files: list[Path]) -> str:
    """输入集的指纹：文件数 + 最大 mtime + 总大小 + 路径摘要。

    只 stat 不解析，597 封实测几毫秒；用来判断"这次重建和上次是不是同一批输入"。
    路径摘要**先 `resolve()` 再拼**：同一批文件可能以相对名（`data/mailbox/...`）或绝对名
    传来，原样拼会让两条调用路径的指纹永远对不上——实测 CLI（`dirs[0].parent` 绝对路径）与
    脚本/GUI（`Path("data/mailbox")` 相对路径）就是这样各扫了一遍，跳过逻辑形同虚设。
    """
    count = len(files)
    newest = 0
    total = 0
    for p in files:
        try:
            st = p.stat()
        except OSError:
            continue
        newest = max(newest, st.st_mtime_ns)
        total += st.st_size
    # 路径摘要用 **abspath + normcase**，不用 resolve()：后者对每个路径都要走系统调用
    # （625 封实测 0.27s，而"跳过"这条路径本该只有毫秒级）。对路径我们只要求"同一文件
    # 无论以相对名还是绝对名传来都得到同一串"，abspath 是纯字符串运算就够。
    digest = hashlib.sha1("\n".join(_norm_path(p) for p in files).encode("utf-8", "replace"))
    return f"{count}:{newest}:{total}:{digest.hexdigest()[:12]}"


def _norm_path(p: Path) -> str:
    """路径归一（指纹与台账键共用）：绝对化 + 大小写/分隔符归一，纯字符串运算。"""
    return os.path.normcase(os.path.abspath(str(p)))


def rebuild(root: Path | None = None, clear: bool = True,
            files: list[Path] | None = None, force: bool = False,
            incremental: bool = False) -> dict[str, int]:
    """重建往来历史。

    默认扫描 ``root`` 下的 ``*.eml``；也可用 ``files`` 显式给定文件列表——评测语料里
    有大量**无扩展名**的邮件（如 trec06c 的 ``data/123/456``），只按 ``*.eml`` 扫会
    一封都建不起来（这会静默把该语料的信任测量变成"没测到"）。

    **三种调用形态**（都在 cache.db 里留状态，跨进程有效）：

    ==================  ==========================================================
    形态                行为
    ==================  ==========================================================
    默认               输入指纹没变 → 直接跳过（毫秒级）；变了 → **全量重建**
    ``incremental=True`` 只处理**台账里没有的文件**（新邮件），累加到现有历史上
    ``force=True``     忽略指纹与台账，清空重算（手动「重建历史」按钮）
    ==================  ==========================================================

    为什么要增量（用户提问"为什么每次取信都把全部邮件过一遍"）：取信后指纹必然变化，
    默认形态就会把**整个目录**重扫一遍——625 封已要 2.5s，攒到几千封就是十几秒，而其中
    真正新增的往往只有几封。增量只喂新文件，代价与"新增数"成正比。

    **增量与全量的一致性**：计数靠 ``upsert_sender`` 累加，所以台账保证每封只计一次；
    first_seen/last_seen 取 min/max、replied 取或、link_domains 取并集，都与全量等价
    （回归测试 ``test_incremental_equals_full_rebuild`` 逐步比对）。**唯一已知差异**：
    本地文件被删后增量仍保留其历史（全量会抹掉）——这反而是我们想要的：历史不该因为
    本地清理而消失。

    返回统计：``files``（扫描到的总数）、``processed``（本次真正计入的封数）、
    ``inbound``（本次新增的发件人记录数）、``replied_marks``、``skipped``。
    """
    from app.mailbox.imap_client import is_self_sent, own_addresses
    from app.scoring.features import registrable_domain
    from app.utils.cache import cache

    if files is None:
        files = sorted(root.rglob("*.eml")) if root and root.is_dir() else []
    state_key = str(root.resolve()) if root else "explicit"
    fingerprint = _fingerprint(files)
    if not force:
        prev = cache.get_trust_state(state_key)
        if prev and prev["fingerprint"] == fingerprint:
            log.debug("往来历史输入未变，跳过重建（%d 封）", len(files))
            return {**prev["stats"], "processed": 0, "skipped": True}

    if incremental and not force:
        known = cache.known_trust_files()
        todo = [p for p in files if _norm_path(p) not in known]
        if not todo:
            stats = {"files": len(files), "inbound": 0, "replied_marks": 0, "processed": 0}
            cache.set_trust_state(state_key, fingerprint, stats)
            log.info("往来历史增量：无新增文件（%d 封已在台账里）", len(files))
            return {**stats, "skipped": False}
        todo_paths = [_norm_path(p) for p in todo]
    else:
        todo = files
        todo_paths = [_norm_path(p) for p in files]
        if clear:
            cache.clear_senders()
        cache.clear_trust_files()

    own = own_addresses()
    inbound = replied = 0
    for p in todo:
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        if is_self_sent(raw, own, folder=p.parent.name):
            for h in ("To", "Cc"):
                for a in _addrs(raw, h):
                    if a not in own:
                        cache.mark_replied(a)
                        replied += 1
            continue
        addrs = _addrs(raw, "From")
        if not addrs:
            continue
        seen = _seen_at(raw)
        # 历史链接域（行为一致性判定的基线）
        links: list[str] = []
        for u in re.findall(r"https?://[^\s\"'<>)]+", raw.decode("utf-8", "replace")[:200000]):
            m = _URL_HOST_RE.match(u.lower())
            reg = registrable_domain(m.group(1).strip(".") if m else "")
            if reg and reg not in links:
                links.append(reg)
            if len(links) >= 20:
                break
        for a in addrs[:1]:          # 只记首个 From（多地址 From 本身是可疑形态，另由规则处理）
            if "@" not in a:
                continue
            cache.upsert_sender(a, registrable_domain(a.split("@")[-1]), seen,
                                replied=False, link_domains=tuple(links))
            inbound += 1
    cache.mark_trust_files(todo_paths)
    stats = {"files": len(files), "inbound": inbound, "replied_marks": replied,
             "processed": len(todo)}
    cache.set_trust_state(state_key, fingerprint, stats)
    log.info("往来历史%s完成: %s", "增量" if (incremental and not force) else "重建", stats)
    return {**stats, "skipped": False}
