from pathlib import Path
from unittest.mock import MagicMock, patch

from app.config import Settings
from app.engines.abusech import AbuseChEngine
from app.models.schemas import EngineStatus


def test_abusech_skipped_without_key(tmp_path: Path):
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"abc")
    engine = AbuseChEngine(Settings(abusech_enabled=True, abusech_auth_key=""))
    result = engine.scan(sample)
    assert result.status == EngineStatus.skipped


def test_abusech_hash_not_found(tmp_path: Path):
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"clean-sample")
    engine = AbuseChEngine(Settings(abusech_enabled=True, abusech_auth_key="test-key"))

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_error = False
    mock_resp.json.return_value = {"query_status": "hash_not_found"}

    with patch("app.engines.abusech.httpx.post", return_value=mock_resp) as post:
        result = engine.scan(sample)

    assert result.status == EngineStatus.clean
    assert post.called
    kwargs = post.call_args.kwargs
    assert kwargs["headers"]["Auth-Key"] == "test-key"
    assert kwargs["data"]["query"] == "get_info"


def test_abusech_known_malware(tmp_path: Path):
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"evil")
    engine = AbuseChEngine(Settings(abusech_enabled=True, abusech_auth_key="test-key"))

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_error = False
    mock_resp.json.return_value = {
        "query_status": "ok",
        "data": [{"signature": "Emotet", "tags": ["exe", "banker"], "file_type": "exe"}],
    }

    with patch("app.engines.abusech.httpx.post", return_value=mock_resp):
        result = engine.scan(sample)

    assert result.status == EngineStatus.infected
    assert any("Emotet" in t for t in result.threats)


def test_abusech_unknown_auth_key(tmp_path: Path):
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"x")
    engine = AbuseChEngine(Settings(abusech_enabled=True, abusech_auth_key="dead-key"))

    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.is_error = True
    mock_resp.json.return_value = {"query_status": "unknown_auth_key"}

    with patch("app.engines.abusech.httpx.post", return_value=mock_resp):
        result = engine.scan(sample)

    assert result.status == EngineStatus.unavailable
    assert "Auth-Key" in (result.details or "")
    assert "ERROR" not in (result.details or "")
