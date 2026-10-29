import json
from pathlib import Path


def _load_hash_set(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()

    values: list[str] = []
    if isinstance(raw, list):
        values = [str(x) for x in raw]
    elif isinstance(raw, dict):
        # {"hashes": [...]} or {"sha256": "note"}
        if "hashes" in raw and isinstance(raw["hashes"], list):
            values = [str(x) for x in raw["hashes"]]
        else:
            values = [str(k) for k in raw.keys()]
    return {v.strip().lower() for v in values if v and v.strip()}


class HashListStore:
    """Local allowlist / denylist of SHA256 digests (JSON files)."""

    def __init__(self, allowlist_path: Path, denylist_path: Path) -> None:
        self.allowlist_path = allowlist_path
        self.denylist_path = denylist_path
        self.reload()

    def reload(self) -> None:
        self.allow = _load_hash_set(self.allowlist_path)
        self.deny = _load_hash_set(self.denylist_path)

    def check(self, sha256: str) -> str | None:
        digest = sha256.lower().strip()
        if digest in self.deny:
            return "deny"
        if digest in self.allow:
            return "allow"
        return None
