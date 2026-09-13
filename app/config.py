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


settings = Settings()

for _d in (DATA_DIR, REPORTS_DIR, SAMPLES_DIR):
    _d.mkdir(parents=True, exist_ok=True)
