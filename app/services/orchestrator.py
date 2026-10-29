import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from app.config import Settings
from app.engines import CONTENT_ENGINE_NAMES, REMOTE_ENGINE_NAMES, ScanEngine, build_engines
from app.engines.clamav import ClamAVEngine
from app.models.schemas import (
    EngineResult,
    EngineStatus,
    FileInfo,
    HealthEngine,
    ScanResult,
    ScanStatus,
    Sensitivity,
    Verdict,
)
from app.services.archive import extract_archive
from app.services.fuzzy import compute_ssdeep, compute_tlsh
from app.services.fuzzy_match import match_fuzzy
from app.services.hash_lists import HashListStore
from app.services.hashing import sha256_file
from app.services.mime import detect_mime
from app.services.scan_cache import ScanResultCache
from app.services.verdict import aggregate_verdict as compute_verdict


class ScanOrchestrator:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.engines: list[ScanEngine] = build_engines(settings)
        self.settings.upload_dir.mkdir(parents=True, exist_ok=True)
        self.settings.results_dir.mkdir(parents=True, exist_ok=True)
        self.hash_lists = HashListStore(settings.allowlist_path, settings.denylist_path)
        self.cache = (
            ScanResultCache(settings.cache_path, settings.cache_ttl_seconds)
            if settings.cache_enabled
            else None
        )

    def health_engines(self) -> list[HealthEngine]:
        items: list[HealthEngine] = []
        for engine in self.engines:
            healthy, detail = engine.healthcheck()
            items.append(
                HealthEngine(
                    name=engine.name,
                    enabled=engine.enabled,
                    healthy=healthy if engine.enabled else False,
                    detail=detail,
                )
            )
        return items

    def clamav_version_info(self) -> tuple[str | None, str | None]:
        for engine in self.engines:
            if isinstance(engine, ClamAVEngine) and engine.enabled:
                version = engine.version_info()
                if not version:
                    return None, None
                # Typical: ClamAV 1.4.1/27485/Mon Jan  6 10:00:00 2025
                parts = version.split("/")
                age_hint = parts[2].strip() if len(parts) >= 3 else None
                return version, age_hint
        return None, None

    def scan_file(
        self,
        source_path: Path,
        original_name: str,
        sensitivity: Sensitivity = Sensitivity.balanced,
        use_remote_intel: bool = True,
    ) -> ScanResult:
        scan_id = uuid4()
        dest = self.settings.upload_dir / f"{scan_id}_{original_name}"
        if source_path.resolve() != dest.resolve():
            dest.write_bytes(source_path.read_bytes())

        digest = sha256_file(dest)
        ssdeep = compute_ssdeep(dest) if self.settings.fuzzy_hash_enabled else None
        tlsh_hash = compute_tlsh(dest) if self.settings.fuzzy_hash_enabled else None
        file_info = FileInfo(
            name=original_name,
            size=dest.stat().st_size,
            sha256=digest,
            mime=detect_mime(dest),
            ssdeep=ssdeep,
            tlsh=tlsh_hash,
        )

        list_hit = self.hash_lists.check(digest)
        if list_hit == "deny":
            result = ScanResult(
                id=scan_id,
                status=ScanStatus.completed,
                verdict=Verdict.malicious,
                sensitivity=sensitivity,
                use_remote_intel=use_remote_intel,
                file=file_info,
                engines=[
                    EngineResult(
                        name="hashlist",
                        status=EngineStatus.infected,
                        threats=["denylist"],
                        details=f"sha256 in denylist ({self.settings.denylist_path})",
                    )
                ],
                list_hit="deny",
                completed_at=datetime.now(timezone.utc),
            )
            self._persist(result)
            return result

        if list_hit == "allow":
            result = ScanResult(
                id=scan_id,
                status=ScanStatus.completed,
                verdict=Verdict.clean,
                sensitivity=sensitivity,
                use_remote_intel=use_remote_intel,
                file=file_info,
                engines=[
                    EngineResult(
                        name="hashlist",
                        status=EngineStatus.clean,
                        details=f"sha256 in allowlist ({self.settings.allowlist_path})",
                    )
                ],
                list_hit="allow",
                completed_at=datetime.now(timezone.utc),
            )
            self._persist(result)
            return result

        if self.cache is not None:
            cached = self.cache.get(
                digest,
                sensitivity=sensitivity.value,
                use_remote_intel=use_remote_intel,
            )
            if cached is not None:
                result = cached.model_copy(
                    update={
                        "id": scan_id,
                        "file": file_info,
                        "sensitivity": sensitivity,
                        "use_remote_intel": use_remote_intel,
                        "cache_hit": True,
                        "created_at": datetime.now(timezone.utc),
                        "completed_at": datetime.now(timezone.utc),
                    }
                )
                self._persist(result)
                return result

        engine_results: list[EngineResult] = []
        fuzzy_result = self._fuzzy_engine_result(ssdeep, tlsh_hash)
        if fuzzy_result is not None:
            engine_results.append(fuzzy_result)
            # High-confidence fuzzy hit can short-circuit like denylist
            if fuzzy_result.status in {EngineStatus.infected, EngineStatus.matched}:
                verdict = compute_verdict(engine_results, sensitivity)
                result = ScanResult(
                    id=scan_id,
                    status=ScanStatus.completed,
                    verdict=verdict,
                    sensitivity=sensitivity,
                    use_remote_intel=use_remote_intel,
                    file=file_info,
                    engines=engine_results,
                    completed_at=datetime.now(timezone.utc),
                )
                self._persist(result)
                if self.cache is not None:
                    self.cache.put(
                        digest,
                        result,
                        sensitivity=sensitivity.value,
                        use_remote_intel=use_remote_intel,
                    )
                return result

        for engine in self.engines:
            if engine.name in REMOTE_ENGINE_NAMES and not use_remote_intel:
                engine_results.append(
                    EngineResult(
                        name=engine.name,
                        status=EngineStatus.skipped,
                        details="skipped: use_remote_intel=false (local-only scan)",
                    )
                )
                continue
            engine_results.append(engine.scan(dest))

        extract_dir = self.settings.upload_dir / f"{scan_id}_extract"
        try:
            engine_results.extend(self._scan_archive_members(dest, extract_dir))
        finally:
            if extract_dir.exists():
                shutil.rmtree(extract_dir, ignore_errors=True)

        verdict = compute_verdict(engine_results, sensitivity)
        result = ScanResult(
            id=scan_id,
            status=ScanStatus.completed,
            verdict=verdict,
            sensitivity=sensitivity,
            use_remote_intel=use_remote_intel,
            file=file_info,
            engines=engine_results,
            cache_hit=False,
            completed_at=datetime.now(timezone.utc),
        )
        self._persist(result)
        if self.cache is not None and verdict not in {Verdict.error, Verdict.unknown}:
            self.cache.put(
                digest,
                result,
                sensitivity=sensitivity.value,
                use_remote_intel=use_remote_intel,
            )
        return result

    def _scan_archive_members(self, archive_path: Path, extract_dir: Path) -> list[EngineResult]:
        if not self.settings.archive_scan_enabled:
            return []

        started = time.perf_counter()
        extracted = extract_archive(
            archive_path,
            extract_dir,
            max_members=self.settings.archive_max_members,
            max_total_bytes=self.settings.archive_max_total_bytes,
            max_member_bytes=self.settings.archive_max_member_bytes,
            max_depth=self.settings.archive_max_depth,
        )
        if not extracted.is_archive:
            return []

        results: list[EngineResult] = []
        threats: list[str] = []
        threats.extend(f"dangerous_member:{p}" for p in extracted.dangerous_paths)
        threats.extend(extracted.warnings)

        status = EngineStatus.clean
        if extracted.errors:
            status = EngineStatus.error
            threats.extend(extracted.errors)
        elif extracted.dangerous_paths or extracted.warnings:
            status = EngineStatus.suspicious

        results.append(
            EngineResult(
                name="archive",
                status=status,
                threats=threats,
                details=(
                    f"type={extracted.archive_type} members={len(extracted.members)} "
                    f"dangerous={len(extracted.dangerous_paths)}"
                ),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        )

        content_engines = [e for e in self.engines if e.name in CONTENT_ENGINE_NAMES]
        for member in extracted.members:
            for engine in content_engines:
                raw = engine.scan(member.extracted_path)
                if raw.status in {
                    EngineStatus.clean,
                    EngineStatus.skipped,
                    EngineStatus.unavailable,
                }:
                    continue
                prefixed = [
                    f"{member.relative_path}: {threat}" for threat in (raw.threats or [raw.status.value])
                ]
                results.append(
                    EngineResult(
                        name=f"{engine.name}@{member.relative_path}",
                        status=raw.status,
                        threats=prefixed,
                        details=raw.details,
                        duration_ms=raw.duration_ms,
                    )
                )
        return results

    def _fuzzy_engine_result(
        self, ssdeep_hash: str | None, tlsh_hash: str | None
    ) -> EngineResult | None:
        if not self.settings.fuzzy_match_enabled or not self.settings.fuzzy_hash_enabled:
            return None
        if not ssdeep_hash and not tlsh_hash:
            return None

        matched = match_fuzzy(
            ssdeep_hash=ssdeep_hash,
            tlsh_hash=tlsh_hash,
            denylist_path=self.settings.denylist_path,
            cache=self.cache,
            ssdeep_threshold=self.settings.fuzzy_ssdeep_threshold,
            tlsh_max_distance=self.settings.fuzzy_tlsh_max_distance,
        )
        if not matched.matched:
            return None

        threats = [f"{h.kind}:{h.source}:{h.reference}:score={h.score}" for h in matched.hits]
        high = any(
            (h.kind == "ssdeep" and h.score >= max(80, self.settings.fuzzy_ssdeep_threshold))
            or (h.kind == "tlsh" and h.score <= min(20, self.settings.fuzzy_tlsh_max_distance))
            for h in matched.hits
        )
        return EngineResult(
            name="fuzzy",
            status=EngineStatus.matched if high else EngineStatus.suspicious,
            threats=threats,
            details=f"{len(matched.hits)} fuzzy similarity hit(s)",
        )

    def get_result(self, scan_id: UUID) -> ScanResult | None:
        path = self.settings.results_dir / f"{scan_id}.json"
        if not path.exists():
            return None
        return ScanResult.model_validate_json(path.read_text(encoding="utf-8"))

    def _persist(self, result: ScanResult) -> None:
        path = self.settings.results_dir / f"{result.id}.json"
        path.write_text(result.model_dump_json(indent=2), encoding="utf-8")

    @staticmethod
    def aggregate_verdict(
        results: list[EngineResult],
        sensitivity: Sensitivity = Sensitivity.balanced,
    ) -> Verdict:
        return compute_verdict(results, sensitivity)
