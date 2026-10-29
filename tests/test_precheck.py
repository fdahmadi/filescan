import shutil
from pathlib import Path

from app.config import Settings
from app.engines import CONTENT_ENGINE_NAMES, REMOTE_ENGINE_NAMES
from app.engines.precheck import PrecheckEngine
from app.models.schemas import EngineStatus

REPO_TINY_PE = Path(__file__).resolve().parents[1] / "testdata/manual_check/clean/windows_tiny_pe.exe"


def test_precheck_flags_dangerous_extension(tmp_path: Path):
    sample = tmp_path / "dropper.ps1"
    sample.write_text("Write-Host hi", encoding="utf-8")
    engine = PrecheckEngine(Settings(precheck_enabled=True, yara_rules_dir=tmp_path))
    result = engine.scan(sample)
    assert result.status == EngineStatus.suspicious
    assert any("dangerous_extension" in t for t in result.threats)


def test_precheck_honest_pe_exe_not_threat_alone():
    assert REPO_TINY_PE.is_file()
    engine = PrecheckEngine(Settings(precheck_enabled=True, yara_rules_dir=REPO_TINY_PE.parent))
    result = engine.scan(REPO_TINY_PE)
    assert result.status == EngineStatus.clean
    assert not any("dangerous_extension" in t for t in result.threats)
    assert result.details and "dangerous_extension:.exe" in result.details


def test_precheck_clean_text(tmp_path: Path):
    sample = tmp_path / "note.txt"
    sample.write_text("hello world", encoding="utf-8")
    engine = PrecheckEngine(Settings(precheck_enabled=True, yara_rules_dir=tmp_path))
    result = engine.scan(sample)
    assert result.status == EngineStatus.clean


def test_precheck_runs_on_archive_members_remote_does_not():
    assert "precheck" in CONTENT_ENGINE_NAMES
    assert REMOTE_ENGINE_NAMES.isdisjoint(CONTENT_ENGINE_NAMES)


def test_precheck_flags_png_that_is_pe(tmp_path: Path):
    assert REPO_TINY_PE.is_file()
    sample = tmp_path / "vacation.png"
    shutil.copy(REPO_TINY_PE, sample)
    engine = PrecheckEngine(Settings(precheck_enabled=True, yara_rules_dir=tmp_path))
    result = engine.scan(sample)
    assert result.status == EngineStatus.suspicious
    assert any("mismatch" in t for t in result.threats)


def test_precheck_flags_double_extension_disguise(tmp_path: Path):
    sample = tmp_path / "invoice.pdf.exe"
    sample.write_bytes(b"MZ\x90\x00not-a-full-pe")
    engine = PrecheckEngine(Settings(precheck_enabled=True, yara_rules_dir=tmp_path))
    result = engine.scan(sample)
    assert result.status == EngineStatus.suspicious
    assert any("double_extension_disguise" in t for t in result.threats)


def test_precheck_clean_real_png(tmp_path: Path):
    # Minimal valid-looking PNG header + IHDR-ish bytes; magic usually reports image/png
    png = (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
        b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    sample = tmp_path / "logo.png"
    sample.write_bytes(png)
    engine = PrecheckEngine(Settings(precheck_enabled=True, yara_rules_dir=tmp_path))
    result = engine.scan(sample)
    assert result.status == EngineStatus.clean
