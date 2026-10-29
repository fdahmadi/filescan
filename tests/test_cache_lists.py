from pathlib import Path

from app.config import Settings
from app.models.schemas import Verdict
from app.services.hash_lists import HashListStore
from app.services.orchestrator import ScanOrchestrator
from app.services.scan_cache import ScanResultCache


def test_hash_lists_allow_deny(tmp_path: Path):
    allow = tmp_path / "allow.json"
    deny = tmp_path / "deny.json"
    allow.write_text('{"hashes": ["aaa"]}', encoding="utf-8")
    deny.write_text('{"hashes": ["bbb"]}', encoding="utf-8")
    store = HashListStore(allow, deny)
    assert store.check("AAA") == "allow"
    assert store.check("bbb") == "deny"
    assert store.check("ccc") is None


def test_denylist_short_circuits_scan(tmp_path: Path):
    sample = tmp_path / "x.bin"
    sample.write_bytes(b"denylisted-bytes")
    # pre-compute will happen inside orchestrator; put digest in deny after first hash
    from app.services.hashing import sha256_file

    digest = sha256_file(sample)
    deny = tmp_path / "deny.json"
    deny.write_text('{"hashes": ["' + digest + '"]}', encoding="utf-8")
    allow = tmp_path / "allow.json"
    allow.write_text('{"hashes": []}', encoding="utf-8")

    settings = Settings(
        clamav_enabled=False,
        yara_enabled=False,
        oletools_enabled=False,
        lmd_enabled=False,
        capa_enabled=False,
        abusech_enabled=False,
        precheck_enabled=False,
        archive_scan_enabled=False,
        cache_enabled=False,
        upload_dir=tmp_path / "up",
        results_dir=tmp_path / "res",
        allowlist_path=allow,
        denylist_path=deny,
        yara_rules_dir=tmp_path,
    )
    orch = ScanOrchestrator(settings)
    result = orch.scan_file(sample, "x.bin")
    assert result.verdict == Verdict.malicious
    assert result.list_hit == "deny"


def test_scan_cache_roundtrip(tmp_path: Path):
    cache_path = tmp_path / "cache.json"
    cache = ScanResultCache(cache_path, ttl_seconds=3600)
    sample = tmp_path / "a.txt"
    sample.write_text("hello cache", encoding="utf-8")

    settings = Settings(
        clamav_enabled=False,
        yara_enabled=True,
        oletools_enabled=False,
        lmd_enabled=False,
        capa_enabled=False,
        abusech_enabled=False,
        precheck_enabled=True,
        archive_scan_enabled=False,
        cache_enabled=True,
        cache_path=cache_path,
        cache_ttl_seconds=3600,
        upload_dir=tmp_path / "up",
        results_dir=tmp_path / "res",
        allowlist_path=tmp_path / "allow.json",
        denylist_path=tmp_path / "deny.json",
        yara_rules_dir=Path(__file__).resolve().parents[1] / "rules" / "yara",
    )
    (tmp_path / "allow.json").write_text('{"hashes":[]}', encoding="utf-8")
    (tmp_path / "deny.json").write_text('{"hashes":[]}', encoding="utf-8")

    orch = ScanOrchestrator(settings)
    first = orch.scan_file(sample, "a.txt")
    assert first.cache_hit is False
    second = orch.scan_file(sample, "a.txt")
    assert second.cache_hit is True
    assert second.verdict == first.verdict
