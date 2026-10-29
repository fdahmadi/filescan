from pathlib import Path

from app.services.mime_policy import check_mime_policy


def test_denylist_blocks_video(tmp_path: Path, monkeypatch):
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"x")

    def fake_mime(_path):
        return "video/mp4"

    monkeypatch.setattr("app.services.mime_policy.detect_mime", fake_mime)
    ok, mime, reason = check_mime_policy(sample, allowlist="", denylist="video/,audio/")
    assert not ok
    assert mime == "video/mp4"
    assert reason


def test_allowlist_requires_prefix(tmp_path: Path, monkeypatch):
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"x")
    monkeypatch.setattr("app.services.mime_policy.detect_mime", lambda _p: "application/pdf")
    ok, _, _ = check_mime_policy(sample, allowlist="application/,text/", denylist="")
    assert ok
    ok2, _, reason = check_mime_policy(sample, allowlist="image/", denylist="")
    assert not ok2
    assert reason
