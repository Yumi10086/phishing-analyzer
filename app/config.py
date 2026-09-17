"""全局配置：从环境变量 / .env 文件加载，所有密钥缺省为空，系统在离线模式下仍可运行。"""
from __future__ import annotations

import os
from pathlib import Path
from dataclasses import dataclass, field

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
SAMPLES_DIR = DATA_DIR / "samples"
REPORTS_DIR = DATA_DIR / "reports"
CACHE_DB = DATA_DIR / "cache.db"
RULES_DIR = Path(os.getenv("RULES_DIR", str(PROJECT_ROOT / "rules")))


def _load_dotenv(path: Path) -> None:
    """极简 .env 加载器，避免额外依赖；已存在的环境变量优先。"""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv(PROJECT_ROOT / ".env")


@dataclass
class Settings:
    # 威胁情报 API Key（为空时对应情报源自动降级为 no_key，不影响本地分析）
    virustotal_api_key: str = field(default_factory=lambda: os.getenv("VT_API_KEY", ""))
    abuseipdb_api_key: str = field(default_factory=lambda: os.getenv("ABUSEIPDB_API_KEY", ""))
    urlscan_api_key: str = field(default_factory=lambda: os.getenv("URLSCAN_API_KEY", ""))

    # TheHive 工单系统
    thehive_url: str = field(default_factory=lambda: os.getenv("THEHIVE_URL", ""))
    thehive_api_key: str = field(default_factory=lambda: os.getenv("THEHIVE_API_KEY", ""))

    # 情报查询行为
    intel_timeout: float = field(default_factory=lambda: float(os.getenv("INTEL_TIMEOUT", "15")))
    intel_concurrency: int = field(default_factory=lambda: int(os.getenv("INTEL_CONCURRENCY", "8")))
    # VirusTotal 免费版 4 次/分钟
    vt_rate_limit: int = field(default_factory=lambda: int(os.getenv("VT_RATE_LIMIT", "4")))
    cache_ttl_hours: int = field(default_factory=lambda: int(os.getenv("CACHE_TTL_HOURS", "24")))
    # URLScan 默认仅做被动搜索，不主动提交扫描任务
    urlscan_allow_submit: bool = field(
        default_factory=lambda: os.getenv("URLSCAN_ALLOW_SUBMIT", "0") == "1"
    )

    # 评分阈值
    threshold_suspicious: int = field(default_factory=lambda: int(os.getenv("TH_SUSPICIOUS", "30")))
    threshold_malicious: int = field(default_factory=lambda: int(os.getenv("TH_MALICIOUS", "55")))

    # 规则目录（YAML 规则 + 字典）
    rules_dir: Path = field(default_factory=lambda: RULES_DIR)

    # 邮箱接入（IMAP 只读取信）。QQ 邮箱用「设置→账户→开启 IMAP/SMTP 服务」生成的
    # 16 位授权码，不是登录密码；凭据只放 gitignored 的 .env，不进代码与仓库。
    mailbox_imap_host: str = field(default_factory=lambda: os.getenv("MAILBOX_IMAP_HOST", "imap.qq.com"))
    mailbox_imap_port: int = field(default_factory=lambda: int(os.getenv("MAILBOX_IMAP_PORT", "993")))
    mailbox_imap_user: str = field(default_factory=lambda: os.getenv("MAILBOX_IMAP_USER", ""))
    mailbox_imap_auth_code: str = field(default_factory=lambda: os.getenv("MAILBOX_IMAP_AUTH_CODE", ""))
    # 单封邮件下载上限：先取 RFC822.SIZE 再决定是否下正文（与分析侧 20MB 口径一致）
    mailbox_max_bytes: int = field(
        default_factory=lambda: int(os.getenv("MAILBOX_MAX_BYTES", str(20 * 1024 * 1024)))
    )
    # 取信后是否自动分析（默认离线：个人邮箱属未脱敏生产邮件，不外发情报平台）
    mailbox_auto_analyze: bool = field(
        default_factory=lambda: os.getenv("MAILBOX_AUTO_ANALYZE", "1") == "1"
    )
    # 自己投递的信不参与分析：垃圾箱/收件箱里的自寄邮件与整个"已发送"文件夹都不分析
    # （本人发出的信不可能是钓鱼目标，且自寄形态会触发一堆与"伪装"无关的启发式）。
    mailbox_skip_self_sent: bool = field(
        default_factory=lambda: os.getenv("MAILBOX_SKIP_SELF_SENT", "1") == "1"
    )
    # 本人地址清单（逗号分隔，用于识别"自己投递"）。MAILBOX_IMAP_USER 自动计入；
    # 同一账号的别名要显式列出（如 QQ 号邮箱 2893698970@qq.com 与 Yumi0030@qq.com
    # 是同一账号的两个地址，仅凭 From 无法互相推断）。
    mailbox_own_addresses: str = field(
        default_factory=lambda: os.getenv("MAILBOX_OWN_ADDRESSES", "")
    )


settings = Settings()


def analysis_profile() -> str:
    """分析档位：``gateway``（默认，网关/SOC 投递的邮件）或 ``mailbox``（邮箱直读取信）。

    刻意用函数而不是 ``settings`` 字段：取信 CLI/GUI 是**运行时**才把档位设为 mailbox
    （在 spawn 子进程之前写环境变量），而 ``Settings`` 是导入期实例化的单例，字段会读到
    旧值。档位差异体现在评分口径上，见 ``risk_engine._profile_dropped_signals``：

    邮箱直读时服务商不给存储副本加 ``Authentication-Results``，该信号缺失是**渠道形态**
    而非风险证据（与 Enron/trec06c"语料缺头部"同构）。实测个人邮箱 54 封正常邮件：
    33 封命中此信号，是误报的第一大来源。
    """
    return os.environ.get("ANALYSIS_PROFILE", "gateway").strip().lower() or "gateway"

for _d in (DATA_DIR, REPORTS_DIR, SAMPLES_DIR):
    _d.mkdir(parents=True, exist_ok=True)
