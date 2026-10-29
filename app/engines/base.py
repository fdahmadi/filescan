from abc import ABC, abstractmethod
from pathlib import Path

from app.models.schemas import EngineResult


class ScanEngine(ABC):
    """Common interface for all malware scan backends."""

    name: str

    @abstractmethod
    def scan(self, file_path: Path) -> EngineResult:
        raise NotImplementedError

    @abstractmethod
    def healthcheck(self) -> tuple[bool, str]:
        """Return (healthy, detail message)."""
        raise NotImplementedError

    @property
    def enabled(self) -> bool:
        return True
