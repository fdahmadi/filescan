from pathlib import Path
from unittest.mock import patch

from app.services.fuzzy_match import match_fuzzy


def test_fuzzy_match_ssdeep_from_denylist(tmp_path: Path):
    deny = tmp_path / "deny.json"
    deny.write_text('{"hashes": [], "ssdeep": ["refhash"], "tlsh": []}', encoding="utf-8")

    with patch("app.services.fuzzy_match.ssdeep_score", return_value=90):
        result = match_fuzzy(
            ssdeep_hash="probe",
            tlsh_hash=None,
            denylist_path=deny,
            cache=None,
            ssdeep_threshold=50,
            tlsh_max_distance=50,
        )

    assert result.matched
    assert result.hits[0].kind == "ssdeep"
    assert result.hits[0].source == "denylist"
