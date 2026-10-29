from app.config import Settings
from app.engines.abusech import AbuseChEngine
from app.engines.base import ScanEngine
from app.engines.capa_engine import CapaEngine
from app.engines.clamav import ClamAVEngine
from app.engines.floss_engine import FlossEngine
from app.engines.lmd import LMDEngine
from app.engines.oletools_engine import OletoolsEngine
from app.engines.pefile_engine import PefileEngine
from app.engines.precheck import PrecheckEngine
from app.engines.yara_engine import YaraEngine
from app.engines.yaraify import YaraifyEngine


def build_engines(settings: Settings) -> list[ScanEngine]:
    """Construct enabled scan engines for the orchestrator."""
    return [
        PrecheckEngine(settings),
        ClamAVEngine(settings),
        YaraEngine(settings),
        OletoolsEngine(settings),
        LMDEngine(settings),
        CapaEngine(settings),
        FlossEngine(settings),
        PefileEngine(settings),
        AbuseChEngine(settings),
        YaraifyEngine(settings),
    ]


# Local content engines re-run on extracted ZIP/TAR members.
# Remote hash engines (abusech/yaraify) stay outer-file only — deferred for members.
CONTENT_ENGINE_NAMES = frozenset(
    {"precheck", "clamav", "yara", "oletools", "lmd", "capa", "floss", "pefile"}
)

# Hash lookups that contact third parties (never upload file bytes)
REMOTE_ENGINE_NAMES = frozenset({"abusech", "yaraify"})


def build_content_engines(settings: Settings) -> list[ScanEngine]:
    """Engines that should also run on extracted archive members."""
    return [e for e in build_engines(settings) if e.name in CONTENT_ENGINE_NAMES]


__all__ = [
    "ScanEngine",
    "PrecheckEngine",
    "ClamAVEngine",
    "YaraEngine",
    "OletoolsEngine",
    "LMDEngine",
    "CapaEngine",
    "FlossEngine",
    "PefileEngine",
    "AbuseChEngine",
    "YaraifyEngine",
    "build_engines",
    "build_content_engines",
    "CONTENT_ENGINE_NAMES",
    "REMOTE_ENGINE_NAMES",
]
