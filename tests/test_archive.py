import zipfile
from pathlib import Path

from app.services.archive import extract_archive


def test_extract_zip_flags_dangerous_member(tmp_path: Path):
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("readme.txt", "hello")
        zf.writestr("payload/shell.php", "<?php eval($_GET['x']); ?>")

    out = tmp_path / "out"
    result = extract_archive(
        archive,
        out,
        max_members=50,
        max_total_bytes=10_000_000,
        max_member_bytes=1_000_000,
        max_depth=1,
    )

    assert result.is_archive
    assert result.archive_type == "zip"
    assert len(result.members) == 2
    assert any(p.endswith("shell.php") for p in result.dangerous_paths)


def test_extract_skips_path_traversal(tmp_path: Path):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../escape.txt", "nope")
        zf.writestr("ok.txt", "yes")

    out = tmp_path / "out"
    result = extract_archive(
        archive,
        out,
        max_members=50,
        max_total_bytes=10_000_000,
        max_member_bytes=1_000_000,
        max_depth=1,
    )

    assert len(result.members) == 1
    assert result.members[0].relative_path.endswith("ok.txt")
    assert any("unsafe" in w for w in result.warnings)
