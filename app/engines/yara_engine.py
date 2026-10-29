import time
from pathlib import Path

from app.config import Settings
from app.engines.base import ScanEngine
from app.models.schemas import EngineResult, EngineStatus

try:
    import yara
except ImportError:  # pragma: no cover
    yara = None


class YaraEngine(ScanEngine):
    """Scan files with compiled YARA rules from a rules directory."""

    name = "yara"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._rules_dir = settings.yara_rules_dir
        self._timeout = settings.yara_timeout_seconds
        self._malicious_tags = {
            tag.strip().lower()
            for tag in settings.yara_malicious_tags.split(",")
            if tag.strip()
        }
        self._rules = None
        self._load_error: str | None = None
        self._compile_rules()

    @property
    def enabled(self) -> bool:
        return self._settings.yara_enabled

    def healthcheck(self) -> tuple[bool, str]:
        if not self.enabled:
            return False, "disabled"
        if yara is None:
            return False, "yara-python not installed"
        if self._load_error:
            return False, self._load_error
        if self._rules is None:
            return False, "no YARA rules loaded"
        return True, f"rules loaded from {self._rules_dir}"

    def scan(self, file_path: Path) -> EngineResult:
        started = time.perf_counter()
        if not self.enabled:
            return EngineResult(
                name=self.name,
                status=EngineStatus.skipped,
                details="YARA disabled by configuration",
            )
        if yara is None:
            return EngineResult(
                name=self.name,
                status=EngineStatus.unavailable,
                details="yara-python not installed",
            )
        if self._rules is None:
            return EngineResult(
                name=self.name,
                status=EngineStatus.error,
                details=self._load_error or "YARA rules not available",
            )

        try:
            matches = self._rules.match(str(file_path), timeout=self._timeout)
            duration_ms = int((time.perf_counter() - started) * 1000)
            if not matches:
                return EngineResult(
                    name=self.name,
                    status=EngineStatus.clean,
                    duration_ms=duration_ms,
                )

            threats: list[str] = []
            high_severity = False
            for match in matches:
                tags = [t.lower() for t in (match.tags or [])]
                meta_sev = str(match.meta.get("severity", "")).lower() if match.meta else ""
                label = match.rule
                if tags:
                    label = f"{match.rule} [{','.join(match.tags)}]"
                threats.append(label)
                if meta_sev in {"high", "critical"} or self._malicious_tags.intersection(tags):
                    high_severity = True

            # matched = high severity (feeds malicious verdict); suspicious = soft hit
            status = EngineStatus.matched if high_severity else EngineStatus.suspicious

            return EngineResult(
                name=self.name,
                status=status,
                threats=threats,
                details=f"{len(matches)} rule(s) matched",
                duration_ms=duration_ms,
            )
        except Exception as exc:  # noqa: BLE001 — surface engine errors cleanly
            duration_ms = int((time.perf_counter() - started) * 1000)
            return EngineResult(
                name=self.name,
                status=EngineStatus.error,
                details=str(exc),
                duration_ms=duration_ms,
            )

    def _compile_rules(self) -> None:
        if yara is None:
            self._load_error = "yara-python not installed"
            return
        if not self._rules_dir.exists():
            self._load_error = f"rules directory missing: {self._rules_dir}"
            return

        sources: dict[str, str] = {}
        compile_errors: list[str] = []
        for path in sorted(self._rules_dir.rglob("*")):
            if path.suffix.lower() not in {".yar", ".yara"} or not path.is_file():
                continue
            namespace = str(path.relative_to(self._rules_dir)).replace("/", "_").replace(".", "_")
            try:
                # Validate each file alone so one bad community rule does not kill the pack
                yara.compile(filepath=str(path))
                sources[namespace] = path.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:  # noqa: BLE001
                compile_errors.append(f"{path.name}: {exc}")

        if not sources:
            self._rules = None
            self._load_error = (
                f"no usable YARA rules in {self._rules_dir}"
                + (f" ({'; '.join(compile_errors)})" if compile_errors else "")
            )
            return

        try:
            self._rules = yara.compile(sources=sources)
            self._load_error = "; ".join(compile_errors) if compile_errors else None
        except Exception as exc:  # noqa: BLE001
            self._rules = None
            self._load_error = f"compile failed: {exc}"
