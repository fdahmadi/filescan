import time
from pathlib import Path

from app.config import Settings
from app.engines.base import ScanEngine
from app.models.schemas import EngineResult, EngineStatus

try:
    from oletools.olevba import VBA_Parser
except ImportError:  # pragma: no cover
    VBA_Parser = None


OFFICE_SUFFIXES = {
    ".doc",
    ".docm",
    ".docx",
    ".dot",
    ".dotm",
    ".xls",
    ".xlsm",
    ".xlsx",
    ".xlt",
    ".xltm",
    ".ppt",
    ".pptm",
    ".pptx",
    ".pps",
    ".ppsm",
}


class OletoolsEngine(ScanEngine):
    """Detect suspicious/auto-exec macros in Office documents via oletools."""

    name = "oletools"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    @property
    def enabled(self) -> bool:
        return self._settings.oletools_enabled

    def healthcheck(self) -> tuple[bool, str]:
        if not self.enabled:
            return False, "disabled"
        if VBA_Parser is None:
            return False, "oletools not installed"
        return True, "oletools available"

    def scan(self, file_path: Path) -> EngineResult:
        started = time.perf_counter()
        if not self.enabled:
            return EngineResult(
                name=self.name,
                status=EngineStatus.skipped,
                details="oletools disabled",
            )
        if VBA_Parser is None:
            return EngineResult(
                name=self.name,
                status=EngineStatus.unavailable,
                details="oletools not installed",
            )

        suffix = file_path.suffix.lower()
        # Skip obvious non-office quickly; olevba can still try OLE containers
        if suffix and suffix not in OFFICE_SUFFIXES and suffix not in {".bin", ".ole"}:
            # Still try: some samples use wrong extensions; only skip clear text/archives handled elsewhere
            if suffix in {".txt", ".png", ".jpg", ".jpeg", ".gif", ".zip", ".gz", ".tar"}:
                return EngineResult(
                    name=self.name,
                    status=EngineStatus.skipped,
                    details=f"skipped non-office suffix {suffix}",
                    duration_ms=int((time.perf_counter() - started) * 1000),
                )

        try:
            parser = VBA_Parser(str(file_path))
        except Exception as exc:  # noqa: BLE001
            return EngineResult(
                name=self.name,
                status=EngineStatus.error,
                details=f"open failed: {exc}",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        try:
            if not parser.detect_vba_macros():
                return EngineResult(
                    name=self.name,
                    status=EngineStatus.clean,
                    details="no VBA macros",
                    duration_ms=int((time.perf_counter() - started) * 1000),
                )

            threats: list[str] = []
            autoexec = False
            suspicious = False
            for result in parser.analyze_macros():
                # tuple: (filename, stream_path, vba_filename, code) in older; analyze_macros yields keywords
                # olevba analyze_macros yields list of (type, keyword, description)
                if not result:
                    continue
                kind = str(result[0]).lower() if isinstance(result, (list, tuple)) else str(result).lower()
                label = "|".join(str(x) for x in result[:3]) if isinstance(result, (list, tuple)) else str(result)
                if "autoexec" in kind:
                    autoexec = True
                    threats.append(f"autoexec:{label}")
                elif "suspicious" in kind:
                    suspicious = True
                    threats.append(f"suspicious:{label}")
                elif "ioc" in kind:
                    suspicious = True
                    threats.append(f"ioc:{label}")
                elif "hex" in kind or "base64" in kind:
                    suspicious = True
                    threats.append(f"obfuscation:{label}")

            duration_ms = int((time.perf_counter() - started) * 1000)
            if not threats:
                return EngineResult(
                    name=self.name,
                    status=EngineStatus.suspicious,
                    threats=["vba_macros_present"],
                    details="macros present without coded keyword hits",
                    duration_ms=duration_ms,
                )

            # AutoExec + suspicious keywords => treat as matched (feeds malicious verdict)
            if autoexec and suspicious:
                status = EngineStatus.matched
            elif autoexec or suspicious:
                status = EngineStatus.suspicious
            else:
                status = EngineStatus.suspicious

            return EngineResult(
                name=self.name,
                status=status,
                threats=threats[:50],
                details=f"autoexec={autoexec} suspicious={suspicious}",
                duration_ms=duration_ms,
            )
        except Exception as exc:  # noqa: BLE001
            return EngineResult(
                name=self.name,
                status=EngineStatus.error,
                details=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        finally:
            try:
                parser.close()
            except Exception:  # noqa: BLE001
                pass
