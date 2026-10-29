from pathlib import Path
from unittest.mock import patch

from app.config import Settings
from app.engines.capa_engine import CapaEngine
from app.engines.lmd import LMDEngine
from app.models.schemas import EngineStatus


def test_lmd_unavailable_without_binary(tmp_path: Path):
    sample = tmp_path / "x.php"
    sample.write_text("<?php echo 1;", encoding="utf-8")
    engine = LMDEngine(Settings(lmd_enabled=True, lmd_bin="maldet-not-installed-xyz"))
    with patch("app.engines.lmd.shutil.which", return_value=None):
        result = engine.scan(sample)
    assert result.status == EngineStatus.unavailable


def test_lmd_parses_hit(tmp_path: Path):
    sample = tmp_path / "x.php"
    sample.write_text("<?php eval($_GET['a']);", encoding="utf-8")
    engine = LMDEngine(Settings(lmd_enabled=True, lmd_bin="maldet"))

    class Proc:
        returncode = 0
        stdout = "{/tmp/x.php}: {php.malware.base64_eval}\n"
        stderr = ""

    with (
        patch("app.engines.lmd.shutil.which", return_value="/usr/bin/maldet"),
        patch("app.engines.lmd.subprocess.run", return_value=Proc()),
    ):
        result = engine.scan(sample)

    assert result.status == EngineStatus.infected
    assert result.threats


def test_lmd_clean_details_not_banner(tmp_path: Path):
    sample = tmp_path / "ok.txt"
    sample.write_text("hello", encoding="utf-8")
    engine = LMDEngine(Settings(lmd_enabled=True, lmd_bin="maldet"))

    class Proc:
        returncode = 0
        stdout = (
            "Linux Malware Detect v1.6.6 (C) 2002-2023, R-fx Networks "
            "<proj@rfxn.com> (C)\nno malware found\n"
        )
        stderr = ""

    with (
        patch("app.engines.lmd.shutil.which", return_value="/usr/bin/maldet"),
        patch("app.engines.lmd.subprocess.run", return_value=Proc()),
    ):
        result = engine.scan(sample)

    assert result.status == EngineStatus.clean
    assert result.details == "no malware detected"


def test_capa_skips_non_binary(tmp_path: Path):
    sample = tmp_path / "photo.png"
    sample.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
    engine = CapaEngine(Settings(capa_enabled=True, capa_bin="capa"))
    with patch("app.engines.capa_engine.shutil.which", return_value="/usr/bin/capa"):
        result = engine.scan(sample)
    assert result.status == EngineStatus.skipped
    assert result.details == "skipped non-binary (PE/ELF)"
    assert "ERROR" not in (result.details or "")


def test_capa_skips_unsupported_format_without_raw_error(tmp_path: Path):
    sample = tmp_path / "a.exe"
    sample.write_bytes(b"MZ\x90\x00fake")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "dummy.yml").write_text("rule: x\n", encoding="utf-8")
    engine = CapaEngine(
        Settings(capa_enabled=True, capa_bin="capa", capa_rules_dir=rules)
    )

    class Proc:
        returncode = 1
        stdout = ""
        stderr = "ERROR capa: helpers.py:271 ----------\nUnsupported file format: unknown"

    with (
        patch("app.engines.capa_engine.shutil.which", return_value="/usr/bin/capa"),
        patch("app.engines.capa_engine.subprocess.run", return_value=Proc()),
    ):
        result = engine.scan(sample)

    assert result.status == EngineStatus.skipped
    assert result.details == "skipped unsupported file format"
    assert "ERROR" not in (result.details or "")


def test_capa_missing_signatures_is_unavailable(tmp_path: Path):
    sample = tmp_path / "a.exe"
    sample.write_bytes(b"MZ\x90\x00fake")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "dummy.yml").write_text("rule: x\n", encoding="utf-8")
    engine = CapaEngine(
        Settings(
            capa_enabled=True,
            capa_bin="capa",
            capa_rules_dir=rules,
            capa_signatures_dir=tmp_path / "missing-sigs",
        )
    )

    class Proc:
        returncode = 1
        stdout = ""
        stderr = (
            "ERROR capa: Using default signature path, but it doesn't exist. "
            "Please install the signatures first"
        )

    with (
        patch("app.engines.capa_engine.shutil.which", return_value="/usr/bin/capa"),
        patch("app.engines.capa_engine.subprocess.run", return_value=Proc()) as run,
    ):
        result = engine.scan(sample)

    assert result.status == EngineStatus.unavailable
    assert "signatures missing" in (result.details or "")
    assert "ERROR" not in (result.details or "")
    # Without a sigs dir on disk, CLI should not get -s
    cmd = run.call_args.args[0]
    assert "-s" not in cmd


def test_capa_unavailable_without_binary(tmp_path: Path):
    sample = tmp_path / "a.exe"
    sample.write_bytes(b"MZ")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "dummy.yml").write_text("rule: x\n", encoding="utf-8")
    engine = CapaEngine(
        Settings(capa_enabled=True, capa_bin="capa-missing", capa_rules_dir=rules)
    )
    with patch("app.engines.capa_engine.shutil.which", return_value=None):
        result = engine.scan(sample)
    assert result.status == EngineStatus.unavailable


def test_capa_unavailable_without_rules(tmp_path: Path):
    sample = tmp_path / "a.exe"
    sample.write_bytes(b"MZ")
    empty = tmp_path / "empty_rules"
    empty.mkdir()
    engine = CapaEngine(
        Settings(capa_enabled=True, capa_bin="capa", capa_rules_dir=empty)
    )
    with patch("app.engines.capa_engine.shutil.which", return_value="/usr/bin/capa"):
        result = engine.scan(sample)
    assert result.status == EngineStatus.unavailable


def test_capa_parses_rules_json(tmp_path: Path):
    sample = tmp_path / "a.exe"
    sample.write_bytes(b"MZ")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "dummy.yml").write_text("rule: x\n", encoding="utf-8")
    engine = CapaEngine(
        Settings(capa_enabled=True, capa_bin="capa", capa_rules_dir=rules)
    )
    payload = {
        "rules": {
            "inject thread": {"meta": {"namespace": "defense-evasion/manipulate-memory"}},
            "create process": {"meta": {"namespace": "execution/process"}},
        }
    }

    class Proc:
        returncode = 0
        stdout = __import__("json").dumps(payload)
        stderr = ""

    with (
        patch("app.engines.capa_engine.shutil.which", return_value="/usr/bin/capa"),
        patch("app.engines.capa_engine.subprocess.run", return_value=Proc()),
    ):
        result = engine.scan(sample)

    assert result.status == EngineStatus.matched
    assert len(result.threats) == 2
