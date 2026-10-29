from pathlib import Path

from app.config import Settings
from app.engines.oletools_engine import OletoolsEngine
from app.models.schemas import EngineStatus


def test_oletools_skips_exe(tmp_path: Path):
    sample = tmp_path / "windows_tiny_pe.exe"
    sample.write_bytes(b"MZ\x90\x00")
    engine = OletoolsEngine(Settings(oletools_enabled=True))
    result = engine.scan(sample)
    assert result.status == EngineStatus.skipped
    assert result.details == "skipped non-office suffix .exe"


def test_oletools_skips_png(tmp_path: Path):
    sample = tmp_path / "logo.png"
    sample.write_bytes(b"\x89PNG\r\n\x1a\n")
    engine = OletoolsEngine(Settings(oletools_enabled=True))
    result = engine.scan(sample)
    assert result.status == EngineStatus.skipped
    assert "non-office" in (result.details or "")
