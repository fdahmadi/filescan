from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class Verdict(str, Enum):
    clean = "clean"
    suspicious = "suspicious"
    malicious = "malicious"
    error = "error"
    unknown = "unknown"


class Sensitivity(str, Enum):
    """How aggressively soft engine hits escalate the final verdict."""

    lenient = "lenient"  # soft (CAPA/FLOSS/precheck/pefile) alone → suspicious max
    balanced = "balanced"  # default legacy-like aggregation
    strict = "strict"  # any suspicious/soft hit → malicious


class EngineStatus(str, Enum):
    clean = "clean"
    matched = "matched"
    infected = "infected"
    suspicious = "suspicious"
    error = "error"
    skipped = "skipped"
    unavailable = "unavailable"


class FileInfo(BaseModel):
    name: str
    size: int
    sha256: str
    mime: Optional[str] = None
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None


class EngineResult(BaseModel):
    name: str
    status: EngineStatus
    threats: list[str] = Field(default_factory=list)
    details: Optional[str] = None
    duration_ms: int = 0


class ScanResult(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    status: ScanStatus = ScanStatus.completed
    verdict: Verdict = Verdict.unknown
    sensitivity: Sensitivity = Sensitivity.balanced
    # When false, abuse.ch / YARAify are skipped (local-only scan)
    use_remote_intel: bool = True
    file: FileInfo
    engines: list[EngineResult] = Field(default_factory=list)
    cache_hit: bool = False
    list_hit: Optional[str] = None  # "allow" | "deny" | None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None


class HealthEngine(BaseModel):
    name: str
    enabled: bool
    healthy: bool
    detail: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    version: str
    engines: list[HealthEngine]
    clamav_version: Optional[str] = None
    clamav_sigs_age_hint: Optional[str] = None
