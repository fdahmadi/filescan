from pathlib import Path
from unittest.mock import MagicMock, patch

from app.config import Settings
from app.engines.yaraify import YaraifyEngine
from app.models.schemas import EngineStatus


def test_yaraify_skipped_without_key(tmp_path: Path):
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"abc")
    engine = YaraifyEngine(Settings(yaraify_enabled=True, yaraify_auth_key="", abusech_auth_key=""))
    result = engine.scan(sample)
    assert result.status == EngineStatus.skipped


def test_yaraify_hash_not_found(tmp_path: Path):
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"clean")
    engine = YaraifyEngine(Settings(yaraify_enabled=True, yaraify_auth_key="k", abusech_auth_key=""))

    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"query_status": "no_results"}

    with patch("app.engines.yaraify.httpx.post", return_value=mock_resp) as post:
        result = engine.scan(sample)

    assert result.status == EngineStatus.clean
    body = post.call_args.kwargs["content"]
    assert "lookup_hash" in body


def test_yaraify_known_hit(tmp_path: Path):
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"evil")
    engine = YaraifyEngine(Settings(yaraify_enabled=True, abusech_auth_key="shared-key"))

    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {
        "query_status": "ok",
        "data": {
            "metadata": {"sha256_hash": "abc"},
            "tasks": [
                {
                    "clamav_results": ["Win.Trojan.X"],
                    "static_results": [{"rule_name": "mal_rule"}],
                }
            ],
        },
    }

    with patch("app.engines.yaraify.httpx.post", return_value=mock_resp):
        result = engine.scan(sample)

    assert result.status == EngineStatus.infected
    assert any("mal_rule" in t for t in result.threats)
