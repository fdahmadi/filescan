import shutil
from pathlib import Path

from app.config import Settings
from app.engines import CONTENT_ENGINE_NAMES
from app.engines.pefile_engine import PefileEngine
from app.models.schemas import EngineStatus
from app.services.verdict import SOFT_ENGINES

REPO_TINY_PE = Path(__file__).resolve().parents[1] / "testdata/manual_check/clean/windows_tiny_pe.exe"


def test_pefile_in_content_and_soft_engines():
    assert "pefile" in CONTENT_ENGINE_NAMES
    assert "pefile" in SOFT_ENGINES


def test_pefile_skips_non_pe(tmp_path: Path):
    sample = tmp_path / "note.txt"
    sample.write_text("hello", encoding="utf-8")
    engine = PefileEngine(Settings(pefile_enabled=True, yara_rules_dir=tmp_path))
    result = engine.scan(sample)
    assert result.status == EngineStatus.clean
    assert result.details == "not a PE file"


def test_pefile_clean_tiny_pe(tmp_path: Path):
    assert REPO_TINY_PE.is_file()
    sample = tmp_path / "tiny.exe"
    shutil.copy(REPO_TINY_PE, sample)
    engine = PefileEngine(Settings(pefile_enabled=True, yara_rules_dir=tmp_path))
    result = engine.scan(sample)
    assert result.status == EngineStatus.clean


def test_pefile_flags_large_overlay(tmp_path: Path):
    assert REPO_TINY_PE.is_file()
    sample = tmp_path / "padded.exe"
    data = REPO_TINY_PE.read_bytes() + (b"A" * 2048)
    sample.write_bytes(data)
    engine = PefileEngine(
        Settings(
            pefile_enabled=True,
            yara_rules_dir=tmp_path,
            pefile_overlay_min_bytes=512,
            pefile_overlay_min_ratio=0.05,
        )
    )
    result = engine.scan(sample)
    assert result.status == EngineStatus.suspicious
    assert any("pe_large_overlay" in t for t in result.threats)


def test_pefile_healthcheck_ok():
    ok, detail = PefileEngine(Settings(pefile_enabled=True)).healthcheck()
    assert ok is True
    assert "pefile" in detail.lower()
