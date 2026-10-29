from pathlib import Path

try:
    import magic
except ImportError:  # pragma: no cover
    magic = None


def detect_mime(path: Path) -> str | None:
    if magic is None:
        return None
    try:
        return magic.from_file(str(path), mime=True)
    except Exception:  # noqa: BLE001
        return None
