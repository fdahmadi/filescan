import json
import time
from pathlib import Path
from typing import Any

from app.models.schemas import ScanResult


class ScanResultCache:
    """Simple JSON file cache keyed by SHA256."""

    def __init__(self, path: Path, ttl_seconds: int) -> None:
        self.path = path
        self.ttl_seconds = ttl_seconds
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._data: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            self._data = {}
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            self._data = raw if isinstance(raw, dict) else {}
        except (OSError, json.JSONDecodeError):
            self._data = {}

    def _save(self) -> None:
        self.path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")

    @staticmethod
    def _key(sha256: str, sensitivity: str = "balanced", use_remote_intel: bool = True) -> str:
        remote = "remote" if use_remote_intel else "local"
        return f"{sha256.lower()}::{sensitivity}::{remote}"

    def get(
        self,
        sha256: str,
        sensitivity: str = "balanced",
        use_remote_intel: bool = True,
    ) -> ScanResult | None:
        entry = self._data.get(self._key(sha256, sensitivity, use_remote_intel))
        # Backward-compat: older caches keyed only by sha256 or sha+sensitivity
        if entry is None and sensitivity == "balanced" and use_remote_intel:
            entry = self._data.get(sha256.lower())
            if entry is None:
                entry = self._data.get(f"{sha256.lower()}::{sensitivity}")
        if not entry or not isinstance(entry, dict):
            return None
        cached_at = float(entry.get("cached_at", 0))
        if self.ttl_seconds > 0 and (time.time() - cached_at) > self.ttl_seconds:
            return None
        payload = entry.get("result")
        if not payload:
            return None
        try:
            return ScanResult.model_validate(payload)
        except Exception:  # noqa: BLE001
            return None

    def put(
        self,
        sha256: str,
        result: ScanResult,
        sensitivity: str = "balanced",
        use_remote_intel: bool = True,
    ) -> None:
        # Store without binding to a single scan id reuse semantics; caller may clone
        self._data[self._key(sha256, sensitivity, use_remote_intel)] = {
            "cached_at": time.time(),
            "result": json.loads(result.model_dump_json()),
        }
        self._save()

    def items(self) -> list[tuple[str, dict]]:
        """Return (sha256, cache_entry) pairs for fuzzy similarity scans."""
        out: list[tuple[str, dict]] = []
        now = time.time()
        for sha, entry in self._data.items():
            if not isinstance(entry, dict):
                continue
            cached_at = float(entry.get("cached_at", 0))
            if self.ttl_seconds > 0 and (now - cached_at) > self.ttl_seconds:
                continue
            out.append((sha, entry))
        return out
