import time
from pathlib import Path

from app.config import Settings
from app.engines.base import ScanEngine
from app.models.schemas import EngineResult, EngineStatus
from app.services.archive import DANGEROUS_EXTENSIONS, detect_archive_type
from app.services.entropy import shannon_entropy
from app.services.mime import detect_mime


# Extensions that strongly imply binary executables / scripts
EXECUTABLE_LIKE = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".scr",
    ".msi",
    ".com",
    ".js",
}

# Benign-looking names often used to disguise executables
IMAGE_LIKE = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".webp",
    ".ico",
    ".svg",
    ".tif",
    ".tiff",
}
DOCUMENT_LIKE = {
    ".txt",
    ".csv",
    ".md",
    ".pdf",
    ".rtf",
}
BENIGN_LOOKING = IMAGE_LIKE | DOCUMENT_LIKE

# Inner tokens for names like invoice.pdf.exe / photo.png.exe
DOUBLE_EXTENSION_TOKENS = (
    ".png.",
    ".jpg.",
    ".jpeg.",
    ".gif.",
    ".bmp.",
    ".pdf.",
    ".doc.",
    ".docx.",
    ".xls.",
    ".xlsx.",
    ".txt.",
)

EXECUTABLE_MIME_HINTS = (
    "executable",
    "dosexec",
    "x-sharedlib",
    "x-elf",
    "x-mach-binary",
    "vnd.microsoft.portable-executable",
    "x-msdownload",
    "x-dosexec",
    "application/x-executable",
    "application/x-msdos-program",
)


def _looks_like_binary_executable(path: Path) -> bool:
    try:
        head = path.read_bytes()[:4]
    except OSError:
        return False
    return head.startswith(b"MZ") or head.startswith(b"\x7fELF")


class PrecheckEngine(ScanEngine):
    """Policy / heuristic checks that do not require ClamAV or YARA."""

    name = "precheck"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    @property
    def enabled(self) -> bool:
        return self._settings.precheck_enabled

    def healthcheck(self) -> tuple[bool, str]:
        if not self.enabled:
            return False, "disabled"
        return True, "policy heuristics ready"

    def scan(self, file_path: Path) -> EngineResult:
        started = time.perf_counter()
        if not self.enabled:
            return EngineResult(
                name=self.name,
                status=EngineStatus.skipped,
                details="precheck disabled",
            )

        threats: list[str] = []
        details: list[str] = []
        name = file_path.name
        name_l = name.lower()
        suffix = file_path.suffix.lower()
        size = file_path.stat().st_size
        mime = detect_mime(file_path)
        entropy = shannon_entropy(file_path)
        binary_exec = _looks_like_binary_executable(file_path)

        if size == 0:
            threats.append("empty_file")
            details.append("file size is 0")

        if suffix in DANGEROUS_EXTENSIONS:
            details.append(f"dangerous_extension:{suffix}")
            # Honest PE/ELF named .exe/.dll/.scr/… — extension matches content; note only.
            # Scripts / webshells (.ps1, .php, …) stay soft threats for policy.
            honest_native = suffix in {
                ".exe",
                ".dll",
                ".scr",
                ".com",
                ".msi",
            } and (
                binary_exec
                or (mime is not None and any(tok in mime.lower() for tok in EXECUTABLE_MIME_HINTS))
            )
            if not honest_native:
                threats.append(f"dangerous_extension:{suffix}")

        if suffix in EXECUTABLE_LIKE and any(tok in name_l for tok in DOUBLE_EXTENSION_TOKENS):
            threats.append(f"double_extension_disguise:{name}")

        if entropy is not None:
            details.append(f"entropy={entropy:.2f}")
            if size >= self._settings.precheck_entropy_min_size and entropy >= self._settings.precheck_high_entropy:
                threats.append(f"high_entropy:{entropy:.2f}")

        if mime and suffix in EXECUTABLE_LIKE and not any(
            token in mime for token in ("executable", "dosexec", "octet-stream", "msdownload", "javascript")
        ):
            if mime.startswith("text/") or mime in {"inode/x-empty", "application/json"}:
                threats.append(f"extension_mime_mismatch:{suffix}->{mime}")

        if mime and suffix in BENIGN_LOOKING:
            mime_l = mime.lower()
            executable_mime = any(token in mime_l for token in EXECUTABLE_MIME_HINTS)
            # octet-stream alone is noisy for images; require MZ/ELF magic
            if executable_mime or (mime_l == "application/octet-stream" and binary_exec):
                threats.append(f"extension_mime_mismatch:{suffix}->{mime}")
            elif binary_exec and not mime_l.startswith("image/"):
                # Magic says PE/ELF but extension looks benign (libmagic may vary by host)
                threats.append(f"extension_content_mismatch:{suffix}->binary_executable")

        if not mime and suffix in BENIGN_LOOKING and binary_exec:
            threats.append(f"extension_content_mismatch:{suffix}->binary_executable")

        archive_type = detect_archive_type(file_path)
        if archive_type:
            details.append(f"archive_type={archive_type}")

        duration_ms = int((time.perf_counter() - started) * 1000)
        if not threats:
            return EngineResult(
                name=self.name,
                status=EngineStatus.clean,
                details="; ".join(details) if details else None,
                duration_ms=duration_ms,
            )

        # Precheck findings are soft by default (suspicious), not automatic malware
        return EngineResult(
            name=self.name,
            status=EngineStatus.suspicious,
            threats=threats,
            details="; ".join(details) if details else None,
            duration_ms=duration_ms,
        )
