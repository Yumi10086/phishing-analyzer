"""IMAP 只读取信：把邮箱里的邮件取成本地 .eml，交给现有分析流水线。

设计约束（都是"不要打扰用户邮箱"的具体化）：
  - ``select(folder, readonly=True)`` + ``BODY.PEEK[]``：**绝不改变邮箱状态**——不标已读、
    不打标志位、不删除。readonly 选择下服务端本就拒绝 STORE，PEEK 是第二道保险；
  - 增量：按 UID 取信，记录 ``UIDVALIDITY`` 与已取最大 UID。UIDVALIDITY 变化（服务端
    重建邮箱）时从头重扫，否则只取新邮件——不做增量就只能每次全量重下；
  - 大小门控：先取 ``RFC822.SIZE`` 再决定是否下载正文，避免为一个 50MB 附件白等；
    与分析侧"单附件 5MB / 单封累计 20MB"的上限对齐，超限邮件如实记录跳过原因；
  - 中文文件夹名：IMAP 用改版 UTF-7（RFC 3501 §5.1.3），Python 标准库没有该 codec，
    故自己实现 ``decode_imap_utf7``（QQ 的"其他文件夹"返回 ``&UXZO1mWHTvZZOQ-``）。

只用标准库 ``imaplib``/``ssl``，不新增依赖（与项目"能用标准库就不引依赖"的取向一致）。
"""
from __future__ import annotations

import base64
import imaplib
import re
import ssl
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

from app.config import settings
from app.utils.logger import get_logger

log = get_logger(__name__)

# 单封邮件的下载上限（字节）。超过则跳过正文下载，仅记录 UID/SIZE/主题，
# 与分析侧的附件上限（单附件 5MB、单封累计 20MB）保持同一量级。
DEFAULT_MAX_BYTES = 20 * 1024 * 1024
# 单次取信的 UID 批量（一个 FETCH 命令取多封，减少往返）
FETCH_CHUNK = 50

# 系统文件夹（QQ/通用）：默认跳过草稿与已删除，收件箱/垃圾箱/已发送才有分析价值——
# 钓鱼通常落在垃圾箱或收件箱，"已发送"用于判断是否首次通信
DEFAULT_FOLDERS = ("INBOX", "Junk", "Sent Messages")
SKIP_FOLDERS = ("Drafts", "Deleted Messages", "Trash", "Junk E-mail")

# "已发送"系文件夹（解码后的名字）：其中的邮件全部是本人投递，不参与分析
SENT_FOLDERS = ("sent", "sent messages", "sent items", "已发送", "已发送邮件",
                "已发送的邮件", "outbox", "发件箱")


def own_addresses() -> set[str]:
    """本人地址集合 = IMAP 账号 + ``MAILBOX_OWN_ADDRESSES`` 里显式列出的别名。

    别名必须显式配置：QQ 邮箱同一账号可同时有 ``2893698970@qq.com``（QQ 号）与
    ``Yumi0030@qq.com`` 两个地址，仅凭 From 无法互相推断。
    """
    own = {settings.mailbox_imap_user.strip().lower()} if settings.mailbox_imap_user else set()
    for part in (settings.mailbox_own_addresses or "").split(","):
        addr = part.strip().lower()
        if addr:
            own.add(addr)
    own.discard("")
    return own


def is_self_sent(raw: bytes, own: set[str], folder: str = "") -> bool:
    """判断这封是不是"自己投递的"（本人发出），用于把它们排除出分析范围。

    两条判据，任一成立即是：
      1. 来自"已发送"系文件夹 —— 该文件夹的定义就是本人发出的邮件。这条能覆盖
         别名地址（QQ 号邮箱）的情形，不依赖 From 是否在本人地址清单里；
      2. From / Sender / Return-Path 命中本人地址清单 —— 覆盖收件箱/垃圾箱里的
         自寄副本（自己抄送给自己）。
    只解析头部，不触发完整邮件解析（几十封也是毫秒级）。
    """
    if folder and folder.strip().lower() in SENT_FOLDERS:
        return True
    if not raw:
        return False
    from email import message_from_bytes
    from email.utils import getaddresses

    try:
        msg = message_from_bytes(raw[:65536])
    except Exception:  # noqa: BLE001
        return False
    for header in ("from", "sender", "return-path"):
        value = msg.get(header)
        if not value:
            continue
        for _, addr in getaddresses([value]):
            if addr and addr.lower() in own:
                return True
    return False


def decode_imap_utf7(name: str) -> str:
    """解码 IMAP 改版 UTF-7 文件夹名（``&UXZO1mWHTvZZOQ-`` -> ``其他文件夹``）。

    规则：普通 ASCII 原样；``&...-`` 段是 UTF-16BE 的 base64（逗号代斜杠、无填充）；
    ``&-`` 表示字面量 ``&``。解码失败时返回原串——文件夹名不值得让整个流程失败。
    """
    if "&" not in name:
        return name
    out: list[str] = []
    i = 0
    while i < len(name):
        ch = name[i]
        if ch != "&":
            out.append(ch)
            i += 1
            continue
        end = name.find("-", i)
        if end == -1:                       # 未闭合的 & 段：按字面量处理
            out.append(name[i:])
            break
        chunk = name[i + 1:end]
        i = end + 1
        if not chunk:                       # "&-" -> "&"
            out.append("&")
            continue
        try:
            raw = base64.b64decode(chunk.replace(",", "/") + "=" * (-len(chunk) % 4))
            out.append(raw.decode("utf-16-be"))
        except Exception:  # noqa: BLE001  名字解不出来不影响取信
            out.append(f"&{chunk}-")
    return "".join(out)


def encode_imap_utf7(name: str) -> str:
    """编码为 IMAP 改版 UTF-7（用于按名字选文件夹/搜索）。"""
    out: list[str] = []
    buf: list[str] = []

    def flush() -> None:
        if buf:
            b64 = base64.b64encode("".join(buf).encode("utf-16-be")).decode("ascii")
            out.append("&" + b64.rstrip("=").replace("/", ",") + "-")
            buf.clear()

    for ch in name:
        if ch == "&":
            flush()
            out.append("&-")
        elif 0x20 <= ord(ch) <= 0x7E:
            flush()
            out.append(ch)
        else:
            buf.append(ch)
    flush()
    return "".join(out)


@dataclass
class Folder:
    """邮箱文件夹（raw 为服务端原始名，name 为解码后的可读名）。"""

    raw: str
    name: str
    flags: list[str] = field(default_factory=list)

    @property
    def selectable(self) -> bool:
        return "\\Noselect" not in self.flags and "\\NoSelect" not in self.flags


@dataclass
class FetchedMail:
    """一封取到的邮件；``raw`` 为 None 表示因超限被跳过。"""

    uid: str
    folder: str
    subject: str
    size: int
    raw: bytes | None = None
    skipped_reason: str = ""


def _client() -> imaplib.IMAP4_SSL:
    """建立已登录的 IMAP 连接（QQ 需用授权码而非登录密码）。"""
    cfg = settings
    if not (cfg.mailbox_imap_user and cfg.mailbox_imap_auth_code):
        raise RuntimeError(
            "未配置邮箱凭据：请在 .env 设置 MAILBOX_IMAP_USER 与 MAILBOX_IMAP_AUTH_CODE"
            "（QQ 邮箱为「设置→账户→开启 IMAP/SMTP 服务」后生成的 16 位授权码）"
        )
    conn = imaplib.IMAP4_SSL(cfg.mailbox_imap_host, cfg.mailbox_imap_port,
                             ssl_context=ssl.create_default_context(), timeout=30)
    conn.login(cfg.mailbox_imap_user, cfg.mailbox_imap_auth_code)
    return conn


_LIST_RE = re.compile(r"\((?P<flags>[^)]*)\)\s+\"(?P<delim>[^\"]*)\"\s+(?P<name>.+)$")


def list_folders(conn: imaplib.IMAP4_SSL) -> list[Folder]:
    """列出所有文件夹（含解码后的中文名）。"""
    typ, data = conn.list()
    if typ != "OK":
        return []
    folders: list[Folder] = []
    for raw in data or []:
        line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
        m = _LIST_RE.search(line)
        if not m:
            continue
        name = m.group("name").strip().strip('"')
        folders.append(Folder(raw=name, name=decode_imap_utf7(name),
                              flags=m.group("flags").split()))
    return folders


def folder_status(conn: imaplib.IMAP4_SSL, folder_raw: str) -> dict[str, int]:
    """取 UIDVALIDITY / UIDNEXT / 邮件总数（增量的依据）。"""
    typ, data = conn.status(f'"{folder_raw}"', "(UIDVALIDITY UIDNEXT MESSAGES)")
    if typ != "OK" or not data:
        return {}
    text = data[0].decode("utf-8", "replace") if isinstance(data[0], bytes) else str(data[0])
    out: dict[str, int] = {}
    for key in ("UIDVALIDITY", "UIDNEXT", "MESSAGES"):
        m = re.search(rf"{key}\s+(\d+)", text)
        if m:
            out[key.lower()] = int(m.group(1))
    return out


def to_imap_date(value: date) -> str:
    """Python 日期 -> IMAP 的 ``DD-Mon-YYYY``（如 ``01-Sep-2026``）。"""
    return value.strftime("%d-%b-%Y")


def parse_date_arg(value: str) -> str:
    """把命令行传来的日期统一成 IMAP 格式。

    接受 ``2026-09-15``（ISO，好写好记）与 ``15-Sep-2026``（IMAP 原格式）；
    空串原样返回（表示不设该边界）；其它形状抛 ValueError，交给调用方报错——
    静默忽略会让"填错了日期"变成"取回一堆无关邮件"。
    """
    text = (value or "").strip()
    if not text:
        return ""
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%b-%Y"):
        try:
            return to_imap_date(datetime.strptime(text, fmt).date())
        except ValueError:
            continue
    raise ValueError(f"无法识别的日期 {value!r}（用 2026-09-15 或 15-Sep-2026）")


def search_uids(conn: imaplib.IMAP4_SSL, since_uid: int = 0,
                since_date: str = "", until_date: str = "") -> list[str]:
    """按 UID 范围或日期区间检索，返回升序 UID 列表。

    ``since_date`` / ``until_date`` 用 IMAP 的 ``DD-Mon-YYYY`` 格式（如 ``01-Sep-2026``），
    两者都是**含当天**的闭区间端点，做**服务端**过滤——取历史邮件时先在服务端筛掉
    不要的，比全量下载再筛快得多。

    端点语义在这里一次转换（别在调用方各写一遍）：IMAP 的 ``SINCE`` 本身含当天，
    而 ``BEFORE`` **排他**，所以"取到 X 日为止"要发 ``BEFORE X+1``。此前把排他值直接
    暴露给调用方，CLI（按文档传含当天）与 GUI（自己 +1）语义不一致 → CLI 单日窗口取到 0 封。
    """
    criteria: list[str] = []
    if since_uid > 0:
        criteria += ["UID", f"{since_uid + 1}:*"]
    if since_date:
        criteria += ["SINCE", since_date]
    if until_date:
        end = datetime.strptime(until_date, "%d-%b-%Y").date() + timedelta(days=1)
        criteria += ["BEFORE", to_imap_date(end)]
    if not criteria:
        criteria = ["ALL"]
    typ, data = conn.uid("SEARCH", None, *criteria)
    if typ != "OK" or not data:
        return []
    text = data[0].decode("ascii", "replace") if isinstance(data[0], bytes) else str(data[0])
    uids = [u for u in text.split() if u.isdigit()]
    # "UID n:*" 在 n 超过最大 UID 时仍会返回最后一封，这里由调用方按 last_uid 再过滤
    return uids


def _parse_fetch_item(item: Any) -> tuple[str, bytes] | None:
    """从 imaplib 的 FETCH 响应里取出 (uid, 原始字节)。"""
    if not isinstance(item, tuple) or len(item) < 2:
        return None
    meta, payload = item[0], item[1]
    if not isinstance(payload, (bytes, bytearray)):
        return None
    text = meta.decode("ascii", "replace") if isinstance(meta, bytes) else str(meta)
    m = re.search(r"UID\s+(\d+)", text)
    if not m:
        return None
    return m.group(1), bytes(payload)


def _header_subject(raw: bytes) -> str:
    """从原始邮件里取主题（用于日志与跳过记录，不落盘）。"""
    from email import message_from_bytes
    try:
        msg = message_from_bytes(raw[:65536])
        from email.header import decode_header, make_header
        return str(make_header(decode_header(msg.get("Subject", "") or ""))).strip()
    except Exception:  # noqa: BLE001
        return ""


def fetch_folder(conn: imaplib.IMAP4_SSL, folder_raw: str, since_uid: int = 0,
                 since_date: str = "", until_date: str = "", limit: int = 0, recent: int = 0,
                 max_bytes: int = DEFAULT_MAX_BYTES,
                 with_body: bool = True) -> Iterator[FetchedMail]:
    """只读取信：按 UID 升序产出邮件（超限的只给元数据）。

    ``limit`` 限制**下载**封数（跳过的超限邮件不计入），避免误触服务商频率限制。

    遍历方向刻意是"从旧到新"：这样增量游标每轮向前推进，反复调用不会漏掉中间的
    邮件。``recent`` 是要"先看看最近的有什么"时用的——取最新的 N 封，此时调用方
    不应推进游标（否则中间那段会被永久跳过）。
    """
    typ, _ = conn.select(f'"{folder_raw}"', readonly=True)
    if typ != "OK":
        log.warning("无法打开文件夹 %s", folder_raw)
        return
    uids = [u for u in search_uids(conn, since_uid=since_uid, since_date=since_date,
                                   until_date=until_date)
            if int(u) > since_uid]
    if recent and recent < len(uids):
        uids = uids[-recent:]
    log.info("文件夹 %s: 待取 %d 封（since_uid=%s）", folder_raw, len(uids), since_uid)

    fetched = 0
    for i in range(0, len(uids), FETCH_CHUNK):
        chunk = uids[i:i + FETCH_CHUNK]
        if limit and fetched >= limit:
            break
        # 第一趟只取大小与主题（几乎零成本），据此决定是否下载正文
        typ, data = conn.uid("FETCH", ",".join(chunk),
                            "(RFC822.SIZE BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
        sizes: dict[str, int] = {}
        headers: dict[str, bytes] = {}
        if typ == "OK":
            for item in data or []:
                if not isinstance(item, tuple) or len(item) < 2:
                    continue
                meta = item[0].decode("ascii", "replace") if isinstance(item[0], bytes) else str(item[0])
                m = re.search(r"UID\s+(\d+)", meta)
                if not m:
                    continue
                uid = m.group(1)
                ms = re.search(r"RFC822\.SIZE\s+(\d+)", meta)
                if ms:
                    sizes[uid] = int(ms.group(1))
                if isinstance(item[1], (bytes, bytearray)):
                    headers[uid] = bytes(item[1])
        for uid in chunk:
            size = sizes.get(uid, 0)
            subject = _header_subject(headers.get(uid, b""))
            if with_body and size and size > max_bytes:
                yield FetchedMail(uid=uid, folder=folder_raw, subject=subject, size=size,
                                  skipped_reason=f"超过下载上限 {max_bytes // 1048576}MB")
                continue
            if limit and fetched >= limit:
                continue
            typ2, data2 = conn.uid("FETCH", uid, "(BODY.PEEK[])")
            raw = None
            if typ2 == "OK":
                for item in data2 or []:
                    parsed = _parse_fetch_item(item)
                    if parsed and parsed[0] == uid:
                        raw = parsed[1]
                        break
            if raw is None:
                yield FetchedMail(uid=uid, folder=folder_raw, subject=subject, size=size,
                                  skipped_reason="取信返回空")
                continue
            fetched += 1
            yield FetchedMail(uid=uid, folder=folder_raw, subject=subject,
                              size=len(raw), raw=raw)


def sanitize_filename(name: str, fallback: str = "mail") -> str:
    """生成安全文件名（文件夹名/主题可能含路径分隔符与保留字符）。

    解码失败的主题会整串是替换字符（U+FFFD，GBK 主题在错误字符集下解码的产物），
    此时退回通用名——文件名里塞一串 ``����`` 既无信息量又难在终端里看。
    """
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(" .")
    if cleaned and cleaned.count("\ufffd") / len(cleaned) > 0.3:
        cleaned = ""
    return (cleaned or fallback)[:80]


def save_mail(mail: FetchedMail, out_dir: Path, index: int = 0) -> Path:
    """把一封邮件写成 .eml（文件名带 UID，便于回溯到邮箱原始邮件）。"""
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = sanitize_filename(mail.subject, "mail") if mail.subject else "mail"
    path = out_dir / f"{index:05d}_uid{mail.uid}_{stem}.eml"
    path.write_bytes(mail.raw or b"")
    return path
