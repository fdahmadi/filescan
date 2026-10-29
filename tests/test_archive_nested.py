import zipfile
from pathlib import Path

from app.services.archive import extract_archive


def test_nested_zip_expanded_when_depth_allows(tmp_path: Path):
    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("payload.php", "<?php eval($_GET['x']); ?>")

    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.write(inner, arcname="nested/inner.zip")
        zf.writestr("readme.txt", "ok")

    out = tmp_path / "out"
    result = extract_archive(
        outer,
        out,
        max_members=50,
        max_total_bytes=10_000_000,
        max_member_bytes=1_000_000,
        max_depth=2,
    )

    assert result.is_archive
    paths = [m.relative_path for m in result.members]
    assert any(p.endswith("readme.txt") for p in paths)
    assert any("payload.php" in p for p in paths)
    assert any(p.endswith("payload.php") for p in result.dangerous_paths)


def test_nested_zip_not_expanded_at_depth_one(tmp_path: Path):
    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("payload.php", "<?php eval($_GET['x']); ?>")

    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.write(inner, arcname="inner.zip")

    out = tmp_path / "out"
    result = extract_archive(
        outer,
        out,
        max_members=50,
        max_total_bytes=10_000_000,
        max_member_bytes=1_000_000,
        max_depth=1,
    )

    assert any("not expanded" in w for w in result.warnings)
    assert not any(m.relative_path.endswith("payload.php") for m in result.members)
