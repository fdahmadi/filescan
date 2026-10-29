from pathlib import Path

try:
    import ssdeep
except ImportError:  # pragma: no cover
    ssdeep = None

try:
    import tlsh
except ImportError:  # pragma: no cover
    tlsh = None


def compute_ssdeep(path: Path) -> str | None:
    if ssdeep is None:
        return None
    try:
        return ssdeep.hash_from_file(str(path))
    except Exception:  # noqa: BLE001
        return None


def compute_tlsh(path: Path) -> str | None:
    if tlsh is None:
        return None
    try:
        digest = tlsh.hash(path.read_bytes())
        if not digest or digest == "TNULL":
            return None
        return digest
    except Exception:  # noqa: BLE001
        return None


def ssdeep_score(a: str, b: str) -> int | None:
    if ssdeep is None or not a or not b:
        return None
    try:
        return int(ssdeep.compare(a, b))
    except Exception:  # noqa: BLE001
        return None


def tlsh_distance(a: str, b: str) -> int | None:
    if tlsh is None or not a or not b:
        return None
    try:
        # pytlsh / tlsh: diff(a,b) — lower means more similar
        return int(tlsh.diff(a, b))
    except Exception:  # noqa: BLE001
        return None
