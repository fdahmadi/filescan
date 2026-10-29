import re
import shutil
import subprocess
import time
from pathlib import Path

from app.config import Settings
from app.engines.base import ScanEngine
from app.models.schemas import EngineResult, EngineStatus


class LMDEngine(ScanEngine):
    """
    Linux Malware Detect (maldet) adapter.

    Requires `maldet` on PATH (or FILESCAN_LMD_BIN). If not installed, reports unavailable.
    Docs: https://github.com/rfxn/linux-malware-detect
    """

    name = "lmd"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._bin = settings.lmd_bin.strip() or "maldet"
        self._timeout = settings.lmd_timeout_seconds

    @property
    def enabled(self) -> bool:
        return self._settings.lmd_enabled

    def _resolve_bin(self) -> str | None:
        path = shutil.which(self._bin) if "/" not in self._bin else self._bin
        if path and Path(path).exists():
            return path
        if Path(self._bin).exists():
            return self._bin
        return shutil.which("maldet")

    def healthcheck(self) -> tuple[bool, str]:
        if not self.enabled:
            return False, "disabled"
        resolved = self._resolve_bin()
        if not resolved:
            return False, "maldet not found (install LMD or set FILESCAN_LMD_BIN)"
        try:
            proc = subprocess.run(
                [resolved, "--help"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if proc.returncode not in {0, 1} and not (proc.stdout or proc.stderr):
                return False, f"maldet help failed (rc={proc.returncode})"
            return True, f"maldet ready ({resolved})"
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, str(exc)

    def scan(self, file_path: Path) -> EngineResult:
        started = time.perf_counter()
        if not self.enabled:
            return EngineResult(name=self.name, status=EngineStatus.skipped, details="LMD disabled")

        resolved = self._resolve_bin()
        if not resolved:
            return EngineResult(
                name=self.name,
                status=EngineStatus.unavailable,
                details="maldet binary not installed",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        try:
            # --scan-all / -a works for a file or directory
            proc = subprocess.run(
                [resolved, "--scan-all", str(file_path)],
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

        output = f"{proc.stdout or ''}\n{proc.stderr or ''}"
        duration_ms = int((time.perf_counter() - started) * 1000)
        threats = self._parse_threats(output, file_path.name)

        if threats:
            return EngineResult(
                name=self.name,
                status=EngineStatus.infected,
                threats=threats,
                details=output.strip()[:1000] or None,
                duration_ms=duration_ms,
            )

        # maldet sometimes returns non-zero even on clean; treat as clean if no hit patterns
        if proc.returncode not in {0, 1, 2} and "error" in output.lower():
            return EngineResult(
                name=self.name,
                status=EngineStatus.error,
                details=output.strip()[:1000] or f"rc={proc.returncode}",
                duration_ms=duration_ms,
            )

        return EngineResult(
            name=self.name,
            status=EngineStatus.clean,
            details="no malware detected",
            duration_ms=duration_ms,
        )

    @staticmethod
    def _parse_threats(output: str, filename: str) -> list[str]:
        threats: list[str] = []
        # Common maldet lines: "{file} : {signature}" or "malware hits {n}"
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            lower = line.lower()
            if "no malware" in lower or "clean" == lower:
                continue
            match = re.search(r"\{?\s*([^\}]+)\s*\}?\s*:\s*([A-Za-z0-9._\-]+)", line)
            if match and ("hit" in lower or "found" in lower or filename in line or "/" in match.group(1)):
                sig = match.group(2).strip()
                if sig and sig.lower() not in {"ok", "clean"}:
                    threats.append(sig)
            elif re.search(r"\b(malware|signature|hit[s]?)\b", lower) and ":" in line:
                threats.append(line[:200])
        # Deduplicate preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for item in threats:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        return unique[:30]
