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
