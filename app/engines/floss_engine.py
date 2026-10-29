import json
import shutil
import subprocess
import time
from pathlib import Path

from app.config import Settings
from app.engines.base import ScanEngine
from app.models.schemas import EngineResult, EngineStatus

# High-signal substrings often recovered from obfuscated malware
RISK_TOKENS = (
    "powershell",
    "cmd.exe",
    "wscript",
    "mshta",
    "frombase64string",
    "invoke-expression",
    "virtualallocex",
    "writeprocessmemory",
    "createremotethread",
    "urlmon",
    "urldownloadtofile",
    "/bin/bash -i",
    "/dev/tcp/",
    "nc -e",
    "wget http",
    "curl http",
    "certutil",
    "bitsadmin",
)


class FlossEngine(ScanEngine):
    """
    Mandiant FLOSS adapter — extract obfuscated / decoded strings from binaries.

    Requires `floss` CLI (`pip install flare-floss`) or FILESCAN_FLOSS_BIN.
    """

    name = "floss"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._bin = settings.floss_bin.strip() or "floss"
        self._timeout = settings.floss_timeout_seconds

    @property
    def enabled(self) -> bool:
        return self._settings.floss_enabled

    def _resolve_bin(self) -> str | None:
        if "/" in self._bin or self._bin.startswith("."):
            return self._bin if Path(self._bin).exists() else None
        return shutil.which(self._bin)

    def healthcheck(self) -> tuple[bool, str]:
        if not self.enabled:
            return False, "disabled"
        resolved = self._resolve_bin()
        if not resolved:
            return False, "floss not found (pip install flare-floss or set FILESCAN_FLOSS_BIN)"
        try:
            proc = subprocess.run(
                [resolved, "--version"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            detail = (proc.stdout or proc.stderr or "").strip().splitlines()[:1]
            return True, detail[0] if detail else f"floss ready ({resolved})"
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, str(exc)

    @staticmethod
    def _looks_like_binary(path: Path) -> bool:
        try:
            head = path.read_bytes()[:8]
        except OSError:
            return False
        if head.startswith(b"MZ") or head.startswith(b"\x7fELF"):
            return True
        # Mach-O thin / fat
        if head[:4] in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"}:
            return True
        return False

    @staticmethod
    def _collect_strings(payload: dict) -> tuple[list[str], list[str]]:
        """Return (interesting_runtime, static) string values from FLOSS JSON."""
        block = payload.get("strings") if isinstance(payload, dict) else None
        if not isinstance(block, dict):
            return [], []

        def values(key: str) -> list[str]:
            items = block.get(key) or []
            out: list[str] = []
            for item in items:
                if isinstance(item, str):
                    out.append(item)
                elif isinstance(item, dict):
                    val = item.get("string") or item.get("value") or ""
                    if val:
                        out.append(str(val))
            return out

        runtime = values("decoded_strings") + values("stack_strings") + values("tight_strings")
        static = values("static_strings")
        return runtime, static

    def scan(self, file_path: Path) -> EngineResult:
        started = time.perf_counter()
        if not self.enabled:
            return EngineResult(name=self.name, status=EngineStatus.skipped, details="FLOSS disabled")

        if not self._looks_like_binary(file_path):
            return EngineResult(
                name=self.name,
                status=EngineStatus.skipped,
                details="skipped non-binary (PE/ELF/Mach-O)",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        resolved = self._resolve_bin()
        if not resolved:
            return EngineResult(
                name=self.name,
                status=EngineStatus.unavailable,
                details="floss binary not installed",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        try:
            proc = subprocess.run(
                [resolved, "-q", "-j", str(file_path)],
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
        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        if not stdout:
            lower = stderr.lower()
            if any(tok in lower for tok in ("not a pe", "unsupported", "failed to load", "no matching")):
                return EngineResult(
                    name=self.name,
                    status=EngineStatus.skipped,
                    details=stderr[:500] or "unsupported file",
                    duration_ms=duration_ms,
                )
            return EngineResult(
                name=self.name,
                status=EngineStatus.error,
                details=stderr[:500] or f"floss rc={proc.returncode}",
                duration_ms=duration_ms,
            )

        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return EngineResult(
                name=self.name,
                status=EngineStatus.error,
                details="invalid JSON from floss",
                duration_ms=duration_ms,
            )

        runtime, static = self._collect_strings(payload)
        threats: list[str] = []
        runtime_hits = 0
        for s in runtime:
            low = s.lower()
            for tok in RISK_TOKENS:
                if tok in low:
                    threats.append(f"decoded:{tok}")
                    runtime_hits += 1
                    break
        static_hits = 0
        for s in static:
            low = s.lower()
            for tok in RISK_TOKENS:
                if tok in low:
                    # Static alone is weaker signal
                    threats.append(f"static:{tok}")
                    static_hits += 1
                    break

        # Deduplicate while preserving order
        seen: set[str] = set()
        uniq: list[str] = []
        for t in threats:
            if t not in seen:
                seen.add(t)
                uniq.append(t)

        if not uniq:
            return EngineResult(
                name=self.name,
                status=EngineStatus.clean,
                details=f"no risky strings (runtime={len(runtime)} static={len(static)})",
                duration_ms=duration_ms,
            )

        if runtime_hits >= 1 or static_hits >= 3:
            status = EngineStatus.matched if runtime_hits >= 2 or static_hits >= 4 else EngineStatus.suspicious
        else:
            status = EngineStatus.suspicious

        return EngineResult(
            name=self.name,
            status=status,
            threats=uniq[:40],
            details=f"{len(uniq)} risk token(s); runtime_hits={runtime_hits} static_hits={static_hits}",
            duration_ms=duration_ms,
        )
