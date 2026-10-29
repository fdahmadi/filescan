from pathlib import Path

from app.config import Settings
from app.engines.base import ScanEngine
from app.models.schemas import EngineResult, EngineStatus, Sensitivity
from app.services.orchestrator import ScanOrchestrator


class _FakeEngine(ScanEngine):
    def __init__(self, name: str, status: EngineStatus = EngineStatus.clean) -> None:
        self.name = name
        self._status = status

    @property
    def enabled(self) -> bool:
        return True

    def healthcheck(self) -> tuple[bool, str]:
        return True, "ok"

    def scan(self, file_path: Path) -> EngineResult:
        return EngineResult(name=self.name, status=self._status, details="fake")


def test_use_remote_intel_false_skips_abuse_engines(tmp_path: Path):
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"hello-filescan")
    settings = Settings(
        clamav_enabled=False,
        yara_enabled=False,
        oletools_enabled=False,
        lmd_enabled=False,
        capa_enabled=False,
        floss_enabled=False,
        abusech_enabled=True,
        yaraify_enabled=True,
        precheck_enabled=True,
        cache_enabled=False,
        archive_scan_enabled=False,
        fuzzy_hash_enabled=False,
        fuzzy_match_enabled=False,
        upload_dir=tmp_path / "up",
        results_dir=tmp_path / "res",
        allowlist_path=tmp_path / "allow.json",
        denylist_path=tmp_path / "deny.json",
    )
    orch = ScanOrchestrator(settings)
    orch.engines = [
        _FakeEngine("precheck"),
        _FakeEngine("abusech", EngineStatus.matched),
        _FakeEngine("yaraify", EngineStatus.matched),
    ]

    result = orch.scan_file(
        sample,
        "a.bin",
        sensitivity=Sensitivity.balanced,
        use_remote_intel=False,
    )

    by_name = {e.name: e for e in result.engines}
    assert result.use_remote_intel is False
    assert by_name["abusech"].status == EngineStatus.skipped
    assert by_name["yaraify"].status == EngineStatus.skipped
    assert "use_remote_intel=false" in (by_name["abusech"].details or "")
