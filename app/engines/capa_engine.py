import json
import shutil
import subprocess
import time
from pathlib import Path

from app.config import Settings
from app.engines.base import ScanEngine
from app.models.schemas import EngineResult, EngineStatus

# CAPA namespaces that usually indicate more serious behavior
HIGH_RISK_NS = {
    "anti-analysis",
    "anti-virus",
    "collection",
    "communication",
    "data-manipulation",
    "defense-evasion",
    "execution",
    "exfiltration",
    "impact",
    "persistence",
    "privilege-escalation",
}


class CapaEngine(ScanEngine):
    """
    Mandiant CAPA adapter (static capability analysis, mainly PE).

    Requires `capa` CLI from flare-capa (pip install flare-capa) or a capa binary.
    """

    name = "capa"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._bin = settings.capa_bin.strip() or "capa"
        self._rules_dir = Path(settings.capa_rules_dir) if settings.capa_rules_dir else None
        self._sigs_dir = Path(settings.capa_signatures_dir) if settings.capa_signatures_dir else None
        self._timeout = settings.capa_timeout_seconds

    @property
    def enabled(self) -> bool:
        return self._settings.capa_enabled

    def _resolve_bin(self) -> str | None:
        if "/" in self._bin or self._bin.startswith("."):
            return self._bin if Path(self._bin).exists() else None
        return shutil.which(self._bin)

    def _rules_args(self) -> list[str]:
        if self._rules_dir and self._rules_dir.is_dir() and any(self._rules_dir.rglob("*.yml")):
            return ["-r", str(self._rules_dir)]
        return []

    def _signatures_args(self) -> list[str]:
        """Pass -s when a signatures dir exists (required for pip/flare-capa installs)."""
        if self._sigs_dir and self._sigs_dir.is_dir():
            return ["-s", str(self._sigs_dir)]
        return []

    @staticmethod
    def _looks_like_binary(path: Path) -> bool:
        """CAPA targets PE/ELF/.NET — skip images, docs, and plain text early."""
        try:
            head = path.read_bytes()[:8]
        except OSError:
            return False
        if head.startswith(b"MZ") or head.startswith(b"\x7fELF"):
            return True
        # Mach-O thin / fat (capa may still reject; treat as candidate)
        if head[:4] in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"}:
            return True
        return False

    @staticmethod
    def _is_unsupported_format(stderr: str) -> bool:
        lower = stderr.lower()
        return any(
            tok in lower
            for tok in (
                "not a pe",
                "unsupported",
                "no matching",
                "file format",
                "unknown file type",
                "not a supported",
                "failed to extract",
            )
        )

    @staticmethod
    def _is_missing_resources(stderr: str) -> bool:
        lower = stderr.lower()
        return any(
            tok in lower
            for tok in (
                "signature path",
                "signatures path",
                "default signature",
                "embedded rules not found",
                "default embedded rules",
                "install the signatures",
            )
        )

    def healthcheck(self) -> tuple[bool, str]:
        if not self.enabled:
            return False, "disabled"
        resolved = self._resolve_bin()
        if not resolved:
            return False, "capa not found (pip install flare-capa or set FILESCAN_CAPA_BIN)"
        rules = self._rules_args()
        if not rules:
            return False, "capa rules missing (set FILESCAN_CAPA_RULES_DIR to capa-rules)"
        try:
            proc = subprocess.run(
                [resolved, "--version"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            detail = (proc.stdout or proc.stderr or "").strip().splitlines()[:1]
            base = detail[0] if detail else f"capa ready ({resolved})"
            sigs = f"; sigs={self._sigs_dir}" if self._signatures_args() else "; sigs=default"
            return True, f"{base}; rules={self._rules_dir}{sigs}"
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, str(exc)

    def scan(self, file_path: Path) -> EngineResult:
        started = time.perf_counter()
        if not self.enabled:
            return EngineResult(name=self.name, status=EngineStatus.skipped, details="CAPA disabled")

        if not self._looks_like_binary(file_path):
            return EngineResult(
                name=self.name,
                status=EngineStatus.skipped,
                details="skipped non-binary (PE/ELF)",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        resolved = self._resolve_bin()
        if not resolved:
            return EngineResult(
                name=self.name,
                status=EngineStatus.unavailable,
                details="capa binary not installed",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        rules = self._rules_args()
        if not rules:
            return EngineResult(
                name=self.name,
                status=EngineStatus.unavailable,
                details="capa rules not found (FILESCAN_CAPA_RULES_DIR)",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        sigs = self._signatures_args()
        try:
            proc = subprocess.run(
                [resolved, *rules, *sigs, "-j", "-q", str(file_path)],
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return EngineResult(
                name=self.name,
                status=EngineStatus.error,
                details=f"timeout after {self._timeout}s",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        except OSError as exc:
            return EngineResult(
                name=self.name,
                status=EngineStatus.error,
                details=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        duration_ms = int((time.perf_counter() - started) * 1000)
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()

        # Unsupported format after binary magic check — skipped, not engine failure
        if proc.returncode != 0 and not stdout:
            if self._is_unsupported_format(stderr):
                return EngineResult(
                    name=self.name,
                    status=EngineStatus.skipped,
                    details="skipped unsupported file format",
                    duration_ms=duration_ms,
                )
            if self._is_missing_resources(stderr):
                return EngineResult(
                    name=self.name,
                    status=EngineStatus.unavailable,
                    details="capa signatures missing (set FILESCAN_CAPA_SIGNATURES_DIR)",
                    duration_ms=duration_ms,
                )
            return EngineResult(
                name=self.name,
                status=EngineStatus.error,
                details=stderr[:500] or f"capa rc={proc.returncode}",
                duration_ms=duration_ms,
            )

        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return EngineResult(
                name=self.name,
                status=EngineStatus.error,
                details="invalid JSON from capa",
                duration_ms=duration_ms,
            )

        rules = payload.get("rules") or {}
        if not rules:
            return EngineResult(
                name=self.name,
                status=EngineStatus.clean,
                details="no capa rules matched",
                duration_ms=duration_ms,
            )

        threats: list[str] = []
        high = False
        for rule_name, meta in rules.items():
            meta_obj = meta if isinstance(meta, dict) else {}
            namespace = ""
            # capa JSON shapes differ slightly by version
            if "meta" in meta_obj and isinstance(meta_obj["meta"], dict):
                namespace = str(meta_obj["meta"].get("namespace", ""))
            else:
                namespace = str(meta_obj.get("namespace", ""))
            ns_root = namespace.split("/")[0].lower() if namespace else ""
            label = f"{namespace}:{rule_name}" if namespace else rule_name
            threats.append(label)
            if ns_root in HIGH_RISK_NS:
                high = True

        # CAPA is capability analysis — usually suspicious; escalate when high-risk namespaces hit
        status = EngineStatus.matched if high and len(threats) >= 2 else EngineStatus.suspicious
        return EngineResult(
            name=self.name,
            status=status,
            threats=threats[:40],
            details=f"{len(threats)} capability rule(s)",
            duration_ms=duration_ms,
        )
