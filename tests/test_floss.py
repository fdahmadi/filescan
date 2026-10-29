from pathlib import Path
from unittest.mock import patch

from app.config import Settings
from app.engines.floss_engine import FlossEngine
from app.models.schemas import EngineStatus


def test_floss_skips_non_binary(tmp_path: Path):
    sample = tmp_path / "note.txt"
    sample.write_text("hello", encoding="utf-8")
    engine = FlossEngine(Settings(floss_enabled=True, floss_bin="floss"))
    with patch("app.engines.floss_engine.shutil.which", return_value="/usr/bin/floss"):
        result = engine.scan(sample)
    assert result.status == EngineStatus.skipped


def test_floss_unavailable_without_binary(tmp_path: Path):
    sample = tmp_path / "a.exe"
    sample.write_bytes(b"MZ\x90\x00")
    engine = FlossEngine(Settings(floss_enabled=True, floss_bin="floss-missing"))
    with patch("app.engines.floss_engine.shutil.which", return_value=None):
        result = engine.scan(sample)
    assert result.status == EngineStatus.unavailable


def test_floss_parses_risk_tokens(tmp_path: Path):
    sample = tmp_path / "a.exe"
    sample.write_bytes(b"MZ\x90\x00")
    engine = FlossEngine(Settings(floss_enabled=True, floss_bin="floss"))
    payload = {
        "strings": {
            "decoded_strings": [{"string": "powershell -enc AAAA"}],
            "stack_strings": [{"string": "VirtualAllocEx"}],
            "tight_strings": [],
            "static_strings": [{"string": "kernel32.dll"}],
        }
    }

    class Proc:
        returncode = 0
        stdout = __import__("json").dumps(payload)
        stderr = ""

    with (
        patch("app.engines.floss_engine.shutil.which", return_value="/usr/bin/floss"),
        patch("app.engines.floss_engine.subprocess.run", return_value=Proc()),
    ):
        result = engine.scan(sample)

    assert result.status == EngineStatus.matched
    assert any("powershell" in t for t in result.threats)
