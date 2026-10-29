import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path


# High-risk when found inside archives or as upload extensions for policy checks
DANGEROUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jse",
    ".wsf",
    ".scr",
    ".msi",
    ".com",
    ".pif",
    ".jar",
    ".php",
    ".phtml",
    ".jsp",
    ".jspx",
    ".asp",
    ".aspx",
    ".cgi",
    ".pl",
}


@dataclass
class ArchiveMember:
    relative_path: str
    extracted_path: Path
    size: int
    depth: int = 1


@dataclass
class ArchiveExtractResult:
    is_archive: bool = False
    archive_type: str | None = None
    members: list[ArchiveMember] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    dangerous_paths: list[str] = field(default_factory=list)


def detect_archive_type(path: Path) -> str | None:
    if zipfile.is_zipfile(path):
        return "zip"
    if tarfile.is_tarfile(path):
        return "tar"
    return None


def _is_unsafe_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("../") or "/../" in f"/{normalized}/":
        return True
    parts = Path(normalized).parts
    return any(part == ".." for part in parts)


def _dangerous_extension(name: str) -> bool:
    return Path(name).suffix.lower() in DANGEROUS_EXTENSIONS


def extract_archive(
    path: Path,
    dest_dir: Path,
    *,
    max_members: int,
    max_total_bytes: int,
    max_member_bytes: int,
    max_depth: int,
) -> ArchiveExtractResult:
    """
    Safely extract zip/tar for member scanning.
    Nested archives are expanded up to max_depth (1 = top level only).
    """
    result = ArchiveExtractResult()
    archive_type = detect_archive_type(path)
    if not archive_type:
        return result

    result.is_archive = True
    result.archive_type = archive_type
    dest_dir.mkdir(parents=True, exist_ok=True)

    budgets = {"members": 0, "bytes": 0}
    try:
        _extract_recursive(
            path,
            dest_dir,
            result,
            prefix="",
            depth=1,
            max_depth=max_depth,
            max_members=max_members,
            max_total_bytes=max_total_bytes,
            max_member_bytes=max_member_bytes,
            budgets=budgets,
        )
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"extract failed: {exc}")

    return result


def _extract_recursive(
    path: Path,
    dest_dir: Path,
    result: ArchiveExtractResult,
    *,
    prefix: str,
    depth: int,
    max_depth: int,
    max_members: int,
    max_total_bytes: int,
    max_member_bytes: int,
    budgets: dict[str, int],
) -> None:
    archive_type = detect_archive_type(path)
    if not archive_type:
        return

    level = ArchiveExtractResult()
    if archive_type == "zip":
        _extract_zip(
            path,
            dest_dir,
            level,
            prefix=prefix,
            depth=depth,
            max_members=max_members,
            max_total_bytes=max_total_bytes,
            max_member_bytes=max_member_bytes,
            budgets=budgets,
        )
    else:
        _extract_tar(
            path,
            dest_dir,
            level,
            prefix=prefix,
            depth=depth,
            max_members=max_members,
            max_total_bytes=max_total_bytes,
            max_member_bytes=max_member_bytes,
            budgets=budgets,
        )

    result.warnings.extend(level.warnings)
    result.errors.extend(level.errors)
    result.dangerous_paths.extend(level.dangerous_paths)

    for member in level.members:
        result.members.append(member)
        nested = detect_archive_type(member.extracted_path)
        if not nested:
            continue
        if depth >= max_depth:
            result.warnings.append(
                f"nested archive not expanded (max_depth={max_depth}): {member.relative_path}"
            )
            continue
        nested_dir = dest_dir / f".nested_{budgets['members']}_{depth}"
        nested_dir.mkdir(parents=True, exist_ok=True)
        _extract_recursive(
            member.extracted_path,
            nested_dir,
            result,
            prefix=f"{member.relative_path}/",
            depth=depth + 1,
            max_depth=max_depth,
            max_members=max_members,
            max_total_bytes=max_total_bytes,
            max_member_bytes=max_member_bytes,
            budgets=budgets,
        )


def _extract_zip(
    path: Path,
    dest_dir: Path,
    result: ArchiveExtractResult,
    *,
    prefix: str,
    depth: int,
    max_members: int,
    max_total_bytes: int,
    max_member_bytes: int,
    budgets: dict[str, int],
) -> None:
    with zipfile.ZipFile(path, "r") as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        for info in infos:
            if budgets["members"] >= max_members:
                result.warnings.append(f"member budget reached ({max_members})")
                return
            name = info.filename
            if _is_unsafe_name(name):
                result.warnings.append(f"skipped unsafe path: {prefix}{name}")
                continue
            if info.file_size > max_member_bytes:
                result.warnings.append(f"member too large ({info.file_size} bytes): {prefix}{name}")
                continue
            if budgets["bytes"] + info.file_size > max_total_bytes:
                result.warnings.append("uncompressed size budget exceeded; stopping extract")
                return
            if info.compress_size and info.file_size > max(info.compress_size * 100, max_member_bytes):
                result.warnings.append(f"possible zip bomb skipped: {prefix}{name}")
                continue

            target = dest_dir / Path(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, target.open("wb") as out:
                remaining = info.file_size
                while remaining > 0:
                    chunk = src.read(min(65536, remaining))
                    if not chunk:
                        break
                    out.write(chunk)
                    remaining -= len(chunk)

            size = target.stat().st_size
            budgets["bytes"] += size
            budgets["members"] += 1
            rel = f"{prefix}{Path(name)}"
            result.members.append(
                ArchiveMember(relative_path=rel, extracted_path=target, size=size, depth=depth)
            )
            if _dangerous_extension(name):
                result.dangerous_paths.append(rel)


def _extract_tar(
    path: Path,
    dest_dir: Path,
    result: ArchiveExtractResult,
    *,
    prefix: str,
    depth: int,
    max_members: int,
    max_total_bytes: int,
    max_member_bytes: int,
    budgets: dict[str, int],
) -> None:
    with tarfile.open(path, "r:*") as tf:
        members = [m for m in tf.getmembers() if m.isfile()]
        for member in members:
            if budgets["members"] >= max_members:
                result.warnings.append(f"member budget reached ({max_members})")
                return
            name = member.name
            if _is_unsafe_name(name):
                result.warnings.append(f"skipped unsafe path: {prefix}{name}")
                continue
            if member.size > max_member_bytes:
                result.warnings.append(f"member too large ({member.size} bytes): {prefix}{name}")
                continue
            if budgets["bytes"] + member.size > max_total_bytes:
                result.warnings.append("uncompressed size budget exceeded; stopping extract")
                return

            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            target = dest_dir / Path(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            with extracted, target.open("wb") as out:
                remaining = member.size
                while remaining > 0:
                    chunk = extracted.read(min(65536, remaining))
                    if not chunk:
                        break
                    out.write(chunk)
                    remaining -= len(chunk)

            size = target.stat().st_size
            budgets["bytes"] += size
            budgets["members"] += 1
            rel = f"{prefix}{Path(name)}"
            result.members.append(
                ArchiveMember(relative_path=rel, extracted_path=target, size=size, depth=depth)
            )
            if _dangerous_extension(name):
                result.dangerous_paths.append(rel)
