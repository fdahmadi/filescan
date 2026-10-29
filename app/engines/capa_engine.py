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
            return True, f"{base}; rules={self._rules_dir}"
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, str(exc)

    def scan(self, file_path: Path) -> EngineResult:
        started = time.perf_counter()
        if not self.enabled:
            return EngineResult(name=self.name, status=EngineStatus.skipped, details="CAPA disabled")

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

        try:
            proc = subprocess.run(
                [resolved, *rules, "-j", "-q", str(file_path)],
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

        # Non-PE / unsupported format is common — treat as skipped, not error
        if proc.returncode != 0 and not stdout:
            lower = stderr.lower()
            if any(tok in lower for tok in ("not a pe", "unsupported", "no matching", "format")):
                return EngineResult(
                    name=self.name,
                    status=EngineStatus.skipped,
                    details=stderr[:500] or "unsupported file format",
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
