import json
import time
from pathlib import Path

import httpx

from app.config import Settings
from app.engines.base import ScanEngine
from app.models.schemas import EngineResult, EngineStatus
from app.services.hashing import sha256_file


class YaraifyEngine(ScanEngine):
    """
    abuse.ch YARAify hash lookup (no file upload by default).

    POST https://yaraify-api.abuse.ch/api/v1/
    JSON: {"query": "lookup_hash", "search_term": "<hash>"}
    Header: Auth-Key (same free key family as MalwareBazaar)
    """

    name = "yaraify"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._url = settings.yaraify_api_url.rstrip("/") + "/"
        self._key = (settings.yaraify_auth_key or settings.abusech_auth_key).strip()
        self._timeout = settings.yaraify_timeout_seconds

    @property
    def enabled(self) -> bool:
        return self._settings.yaraify_enabled

    def healthcheck(self) -> tuple[bool, str]:
        if not self.enabled:
            return False, "disabled"
        if not self._key:
            return False, "Auth-Key not set (FILESCAN_YARAIFY_AUTH_KEY or FILESCAN_ABUSECH_AUTH_KEY)"
        return True, "Auth-Key configured (hash lookup only, no upload)"

    def scan(self, file_path: Path) -> EngineResult:
        started = time.perf_counter()
        if not self.enabled:
            return EngineResult(name=self.name, status=EngineStatus.skipped, details="YARAify disabled")
        if not self._key:
            return EngineResult(
                name=self.name,
                status=EngineStatus.skipped,
                details="no Auth-Key configured",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        digest = sha256_file(file_path)
        try:
            response = httpx.post(
                self._url,
                content=json.dumps({"query": "lookup_hash", "search_term": digest}),
                headers={
                    "Auth-Key": self._key,
                    "Content-Type": "application/json",
                },
                timeout=self._timeout,
            )
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPError as exc:
            return EngineResult(
                name=self.name,
                status=EngineStatus.error,
                details=f"HTTP error: {exc}",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        except ValueError as exc:
            return EngineResult(
                name=self.name,
                status=EngineStatus.error,
                details=f"invalid JSON: {exc}",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        duration_ms = int((time.perf_counter() - started) * 1000)
        status_code = str(payload.get("query_status", ""))

        if status_code in {"no_results", "hash_not_found", "not_found", "no_hash_found"}:
            return EngineResult(
                name=self.name,
                status=EngineStatus.clean,
                details=f"hash_not_found sha256={digest}",
                duration_ms=duration_ms,
            )

        if status_code != "ok":
            return EngineResult(
                name=self.name,
                status=EngineStatus.error,
                details=f"query_status={status_code}",
                duration_ms=duration_ms,
            )

        data = payload.get("data") or {}
        threats: list[str] = []

        # Collect YARA / ClamAV hits from task history when present
        tasks = data.get("tasks") if isinstance(data, dict) else None
        if isinstance(tasks, list):
            for task in tasks[:5]:
                if not isinstance(task, dict):
                    continue
                for hit in task.get("clamav_results") or []:
                    threats.append(f"clamav:{hit}")
                for hit in task.get("static_results") or []:
                    if isinstance(hit, dict) and hit.get("rule_name"):
                        threats.append(f"yara:{hit['rule_name']}")
                    elif isinstance(hit, str):
                        threats.append(f"yara:{hit}")

        metadata = data.get("metadata") if isinstance(data, dict) else None
        if isinstance(metadata, dict) and metadata.get("sha256_hash"):
            threats.append(f"known_sample:{metadata.get('sha256_hash')}")

        if not threats:
            # Known to YARAify but no rule names in payload
            if metadata or tasks:
                threats.append("known_in_yaraify")
            else:
                return EngineResult(
                    name=self.name,
                    status=EngineStatus.clean,
                    details="ok but empty data",
                    duration_ms=duration_ms,
                )

        # Deduplicate
        seen: set[str] = set()
        unique = []
        for t in threats:
            if t not in seen:
                seen.add(t)
                unique.append(t)

        return EngineResult(
            name=self.name,
            status=EngineStatus.infected,
            threats=unique[:40],
            details=f"YARAify hit sha256={digest}",
            duration_ms=duration_ms,
        )
