from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FILESCAN_", env_file=".env", extra="ignore")

    app_name: str = "FileScan"
    debug: bool = False

    # Upload limits / MIME policy
    max_upload_bytes: int = 32 * 1024 * 1024  # 32 MiB
    upload_dir: Path = Path("/tmp/filescan/uploads")
    results_dir: Path = Path("/tmp/filescan/results")
    # Comma-separated MIME prefixes; empty = allow all (e.g. "application/,text/,image/")
    mime_allowlist: str = ""
    # Comma-separated MIME prefixes always rejected
    mime_denylist: str = "audio/,video/"

    # Path B — pilot API access control (empty api_keys = auth disabled)
    api_keys: str = ""
    rate_limit_per_minute: int = 60

    # ClamAV
    clamav_enabled: bool = True
    clamav_host: str = "clamav"
    clamav_port: int = 3310
    clamav_timeout_seconds: float = 60.0

    # YARA
    yara_enabled: bool = True
    yara_rules_dir: Path = Path("/app/rules/yara")
    yara_timeout_seconds: int = 30
    yara_malicious_tags: str = "malware,malicious,trojan,ransomware,virus"

    # Pre-check heuristics
    precheck_enabled: bool = True
    precheck_high_entropy: float = 7.2
    precheck_entropy_min_size: int = 1024

    # pefile PE structure heuristics (soft)
    pefile_enabled: bool = True
    pefile_overlay_min_bytes: int = 512
    pefile_overlay_min_ratio: float = 0.10
    # Avoid flagging tiny crafted PE stubs with empty import tables
    pefile_no_imports_min_bytes: int = 8192

    # Archive member scanning (depth>=2 expands nested zip/tar)
    archive_scan_enabled: bool = True
    archive_max_depth: int = 2
    archive_max_members: int = 50
    archive_max_total_bytes: int = 64 * 1024 * 1024
    archive_max_member_bytes: int = 32 * 1024 * 1024

    # oletools
    oletools_enabled: bool = True

    # Linux Malware Detect (optional binary)
    lmd_enabled: bool = True
    lmd_bin: str = "maldet"
    lmd_timeout_seconds: float = 120.0

    # CAPA (optional binary / flare-capa)
    capa_enabled: bool = True
    capa_bin: str = "capa"
    # Empty = capa default/embedded rules; set to capa-rules checkout in Docker
    capa_rules_dir: Path = Path("/opt/capa-rules")
    # FLIRT/library signatures (-s); required when capa is installed via pip (flare-capa)
    capa_signatures_dir: Path = Path("/opt/capa-sigs")
    capa_timeout_seconds: float = 120.0

    # FLOSS (optional binary / flare-floss) — obfuscated string extraction
    floss_enabled: bool = True
    floss_bin: str = "floss"
    floss_timeout_seconds: float = 120.0

    # abuse.ch MalwareBazaar hash lookup (no upload)
    abusech_enabled: bool = True
    abusech_auth_key: str = ""
    abusech_api_url: str = "https://mb-api.abuse.ch/api/v1"
    abusech_timeout_seconds: float = 30.0

    # SHA256 result cache + local lists
    cache_enabled: bool = True
    cache_path: Path = Path("/tmp/filescan/hash_cache.json")
    cache_ttl_seconds: int = 7 * 24 * 3600  # 7 days
    allowlist_path: Path = Path("/tmp/filescan/allowlist.json")
    denylist_path: Path = Path("/tmp/filescan/denylist.json")

    # Fuzzy hashing (optional libs) + similarity matching
    fuzzy_hash_enabled: bool = True
    fuzzy_match_enabled: bool = True
    fuzzy_ssdeep_threshold: int = 50  # 0-100; higher = stricter similarity
    fuzzy_tlsh_max_distance: int = 50  # lower distance = more similar

    # YARAify (abuse.ch) — hash lookup only; reuses abusech key if unset
    yaraify_enabled: bool = True
    yaraify_auth_key: str = ""
    yaraify_api_url: str = "https://yaraify-api.abuse.ch/api/v1"
    yaraify_timeout_seconds: float = 30.0


@lru_cache
def get_settings() -> Settings:
    return Settings()
