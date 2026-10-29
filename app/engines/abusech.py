import time
from pathlib import Path

import httpx

from app.config import Settings
from app.engines.base import ScanEngine
from app.models.schemas import EngineResult, EngineStatus
from app.services.hashing import sha256_file


class AbuseChEngine(ScanEngine):
    """
    abuse.ch MalwareBazaar hash lookup (no file upload).

    Free Auth-Key from https://auth.abuse.ch/
    API: POST https://mb-api.abuse.ch/api/v1/  query=get_info&hash=...
    """

    name = "abusech"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._url = settings.abusech_api_url.rstrip("/") + "/"
        self._key = settings.abusech_auth_key.strip()
        self._timeout = settings.abusech_timeout_seconds

    @property
    def enabled(self) -> bool:
        return self._settings.abusech_enabled

    def healthcheck(self) -> tuple[bool, str]:
        if not self.enabled:
            return False, "disabled"
        if not self._key:
            return False, "FILESCAN_ABUSECH_AUTH_KEY not set (free key at https://auth.abuse.ch/)"
        return True, "Auth-Key configured (hash lookup only, no upload)"

    def scan(self, file_path: Path) -> EngineResult:
        started = time.perf_counter()
        if not self.enabled:
            return EngineResult(name=self.name, status=EngineStatus.skipped, details="abuse.ch disabled")
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
                data={"query": "get_info", "hash": digest},
                headers={"Auth-Key": self._key},
                timeout=self._timeout,
            )
            try:
                payload = response.json()
            except ValueError:
                payload = {}
            # MalwareBazaar returns JSON body even on 401/403 (e.g. unknown_auth_key)
            query_status = str(payload.get("query_status", "")) if isinstance(payload, dict) else ""
            if response.status_code in {401, 403} or query_status in {
                "unknown_auth_key",
                "auth_key_invalid",
                "unauthorized",
            }:
                return EngineResult(
                    name=self.name,
                    status=EngineStatus.unavailable,
                    details=(
                        f"invalid Auth-Key ({query_status or response.status_code}) — "
                        "recreate at https://auth.abuse.ch/ and Save profile"
                    ),
                    duration_ms=int((time.perf_counter() - started) * 1000),
                )
            if response.is_error:
                return EngineResult(
                    name=self.name,
                    status=EngineStatus.error,
                    details=f"HTTP {response.status_code}: {(response.text or '')[:200]}",
                    duration_ms=int((time.perf_counter() - started) * 1000),
                )
            if not isinstance(payload, dict):
                return EngineResult(
                    name=self.name,
                    status=EngineStatus.error,
                    details="invalid JSON from MalwareBazaar",
                    duration_ms=int((time.perf_counter() - started) * 1000),
                )
        except httpx.HTTPError as exc:
            return EngineResult(
                name=self.name,
                status=EngineStatus.error,
                details=f"HTTP error: {exc}",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        duration_ms = int((time.perf_counter() - started) * 1000)
        status_code = str(payload.get("query_status", ""))

        if status_code in {"hash_not_found", "no_results", "not_found"}:
            return EngineResult(
                name=self.name,
                status=EngineStatus.clean,
                details=f"hash_not_found sha256={digest}",
                duration_ms=duration_ms,
            )

        if status_code in {"ok", "hash_found", ""} or "data" in payload:
            data = payload.get("data")
            # API may return data as list or dict depending on version
            record = None
            if isinstance(data, list) and data:
                record = data[0]
            elif isinstance(data, dict):
                record = data

            if record is None and status_code not in {"ok", "hash_found"}:
                # Unknown status without data
                if status_code in {"illegal_hash", "no_hash_provided", "http_post_expected"}:
                    return EngineResult(
                        name=self.name,
                        status=EngineStatus.error,
                        details=f"query_status={status_code}",
                        duration_ms=duration_ms,
                    )
                return EngineResult(
                    name=self.name,
                    status=EngineStatus.clean,
                    details=f"query_status={status_code or 'empty'}",
                    duration_ms=duration_ms,
                )

            if record is None:
                return EngineResult(
                    name=self.name,
                    status=EngineStatus.clean,
                    details=f"query_status={status_code}",
                    duration_ms=duration_ms,
                )

            threats: list[str] = []
            signature = record.get("signature") or record.get("malware_family")
            if signature:
                threats.append(f"family:{signature}")
            tags = record.get("tags") or []
            if isinstance(tags, list):
                threats.extend(f"tag:{t}" for t in tags[:15])
            elif isinstance(tags, str) and tags:
                threats.append(f"tag:{tags}")
            file_type = record.get("file_type") or record.get("file_type_mime")
            if file_type:
                threats.append(f"type:{file_type}")
            if not threats:
                threats.append("known_malware_sample")

            return EngineResult(
                name=self.name,
                status=EngineStatus.infected,
                threats=threats,
                details=f"MalwareBazaar hit sha256={digest}",
                duration_ms=duration_ms,
            )

        return EngineResult(
            name=self.name,
            status=EngineStatus.error,
            details=f"unexpected query_status={status_code}",
            duration_ms=duration_ms,
        )
