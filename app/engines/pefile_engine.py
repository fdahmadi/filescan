import time
from pathlib import Path

from app.config import Settings
from app.engines.base import ScanEngine
from app.models.schemas import EngineResult, EngineStatus

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None

# IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE
_SECTION_WX = 0x20000000 | 0x80000000
_MZ = b"MZ"
_PNG = b"\x89PNG\r\n\x1a\n"


class PefileEngine(ScanEngine):
    """
    Soft PE structure heuristics via pefile (overlay, W+X sections, embedded payloads).

    Does not claim a malware family — raises suspicious for structural anomalies.
    """

    name = "pefile"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    @property
    def enabled(self) -> bool:
        return self._settings.pefile_enabled

    def healthcheck(self) -> tuple[bool, str]:
        if not self.enabled:
            return False, "disabled"
        if pefile is None:
            return False, "pefile not installed (pip install pefile)"
        return True, f"pefile {getattr(pefile, '__version__', 'available')}"

    @staticmethod
    def _is_pe(path: Path) -> bool:
        try:
            return path.read_bytes()[:2] == _MZ
        except OSError:
            return False

    def scan(self, file_path: Path) -> EngineResult:
        started = time.perf_counter()
        if not self.enabled:
            return EngineResult(
                name=self.name,
                status=EngineStatus.skipped,
                details="pefile disabled",
            )
        if pefile is None:
            return EngineResult(
                name=self.name,
                status=EngineStatus.unavailable,
                details="pefile not installed",
            )
        if not self._is_pe(file_path):
            return EngineResult(
                name=self.name,
                status=EngineStatus.clean,
                details="not a PE file",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        threats: list[str] = []
        details: list[str] = []
        try:
            pe = pefile.PE(str(file_path), fast_load=True)
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
                ]
            )
        except Exception as exc:  # noqa: BLE001 — malformed PE is a soft signal
            return EngineResult(
                name=self.name,
                status=EngineStatus.suspicious,
                threats=[f"pe_parse_error:{type(exc).__name__}"],
                details=str(exc)[:200],
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        try:
            size = file_path.stat().st_size
            details.append(f"sections={len(pe.sections)}")

            overlay = pe.get_overlay()
            if overlay:
                overlay_len = len(overlay)
                ratio = overlay_len / size if size else 0.0
                details.append(f"overlay_bytes={overlay_len}")
                min_bytes = self._settings.pefile_overlay_min_bytes
                min_ratio = self._settings.pefile_overlay_min_ratio
                if overlay_len >= min_bytes and ratio >= min_ratio:
                    threats.append(f"pe_large_overlay:{overlay_len}")

            wx_sections: list[str] = []
            for section in pe.sections:
                chars = int(getattr(section, "Characteristics", 0) or 0)
                if chars & _SECTION_WX == _SECTION_WX:
                    name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
                    wx_sections.append(name or "unnamed")
            if wx_sections:
                threats.append(f"pe_writable_executable_section:{','.join(wx_sections[:5])}")

            if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS is not None:
                threats.append("pe_tls_callbacks")

            import_count = 0
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") and pe.DIRECTORY_ENTRY_IMPORT:
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    import_count += len(entry.imports or [])
            details.append(f"imports={import_count}")
            if import_count == 0 and size >= self._settings.pefile_no_imports_min_bytes:
                threats.append("pe_no_imports")

            icon_resources = 0
            png_in_resources = 0
            embedded_mz = 0
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE") and pe.DIRECTORY_ENTRY_RESOURCE:
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    for leaf in self._resource_leaves(entry):
                        data = self._resource_bytes(pe, leaf)
                        if data is None:
                            continue
                        type_id = self._resource_type_id(entry)
                        # RT_ICON=3, RT_GROUP_ICON=14, RT_BITMAP=2
                        if type_id in {2, 3, 14}:
                            icon_resources += 1
                            if data.startswith(_PNG) or _PNG in data[:64]:
                                png_in_resources += 1
                        # Skip the PE's own DOS stub at file start; look for nested MZ in resource body
                        if len(data) >= 64 and data.startswith(_MZ):
                            embedded_mz += 1
                        elif _MZ in data[64:]:
                            # Possible embedded PE deeper in resource blob
                            embedded_mz += 1

            if icon_resources:
                details.append(f"icon_resources={icon_resources}")
            if png_in_resources:
                # Common for legitimate Vista+ icons — enrichment only, not a verdict signal.
                details.append(f"png_icon_resources={png_in_resources}")
            if embedded_mz:
                threats.append(f"pe_resource_embedded_mz:{embedded_mz}")
        finally:
            pe.close()

        duration_ms = int((time.perf_counter() - started) * 1000)
        if not threats:
            return EngineResult(
                name=self.name,
                status=EngineStatus.clean,
                details="; ".join(details) if details else None,
                duration_ms=duration_ms,
            )
        return EngineResult(
            name=self.name,
            status=EngineStatus.suspicious,
            threats=threats,
            details="; ".join(details) if details else None,
            duration_ms=duration_ms,
        )

    @staticmethod
    def _resource_type_id(entry) -> int | None:  # noqa: ANN001
        try:
            if entry.id is not None:
                return int(entry.id)
        except (TypeError, ValueError):
            return None
        return None

    @classmethod
    def _resource_leaves(cls, entry):  # noqa: ANN001, ANN206
        if hasattr(entry, "directory") and entry.directory is not None:
            for child in entry.directory.entries:
                yield from cls._resource_leaves(child)
        else:
            yield entry

    @staticmethod
    def _resource_bytes(pe, entry) -> bytes | None:  # noqa: ANN001
        try:
            rva = entry.data.struct.OffsetToData
            size = entry.data.struct.Size
            if size <= 0 or size > 16 * 1024 * 1024:
                return None
            return pe.get_data(rva, size)
        except Exception:  # noqa: BLE001
            return None
