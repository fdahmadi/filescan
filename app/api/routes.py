import tempfile
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile, status

from app import __version__
from app.api.security import RateLimiter, require_api_key
from app.models.schemas import HealthResponse, ScanResult, Sensitivity
from app.services.mime_policy import check_mime_policy
from app.services.orchestrator import ScanOrchestrator

router = APIRouter()
_limiter = RateLimiter()


def _orchestrator(request: Request) -> ScanOrchestrator:
    return request.app.state.orchestrator


def _enforce_access(request: Request) -> None:
    settings = request.app.state.settings
    key = require_api_key(request, settings)
    bucket = key or (request.client.host if request.client else "anonymous")
    _limiter.check(bucket, settings.rate_limit_per_minute)


@router.get("/health", response_model=HealthResponse)
def health(request: Request) -> HealthResponse:
    orchestrator = _orchestrator(request)
    engines = orchestrator.health_engines()
    enabled = [e for e in engines if e.enabled]
    healthy_enabled = [e for e in enabled if e.healthy]
    if enabled and len(healthy_enabled) == len(enabled):
        overall = "ok"
    elif healthy_enabled:
        overall = "degraded"
    else:
        overall = "unavailable"
    clamav_version, sigs_age = orchestrator.clamav_version_info()
    return HealthResponse(
        status=overall,
        version=__version__,
        engines=engines,
        clamav_version=clamav_version,
        clamav_sigs_age_hint=sigs_age,
    )


def _parse_bool_form(value: str, *, field: str) -> bool:
    normalized = (value or "").strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise HTTPException(
        status_code=400,
        detail=f"{field} must be true or false",
    )


@router.post("/scan", response_model=ScanResult, status_code=status.HTTP_200_OK)
async def scan_file(
    request: Request,
    file: UploadFile = File(...),
    sensitivity: str = Form(
        default=Sensitivity.balanced.value,
        description="lenient | balanced | strict — how soft engine hits escalate",
    ),
    use_remote_intel: str = Form(
        default="true",
        description=(
            "true|false — when false, skip abuse.ch/YARAify (hash lookups only; "
            "FileScan never uploads file bytes remotely)"
        ),
    ),
) -> ScanResult:
    _enforce_access(request)
    settings = request.app.state.settings
    orchestrator = _orchestrator(request)

    try:
        sens = Sensitivity(sensitivity.strip().lower())
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="sensitivity must be one of: lenient, balanced, strict",
        ) from exc
    remote = _parse_bool_form(use_remote_intel, field="use_remote_intel")

    if not file.filename:
        raise HTTPException(status_code=400, detail="filename is required")

    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="empty file")
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"file exceeds max size of {settings.max_upload_bytes} bytes",
        )

    suffix = Path(file.filename).suffix
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(data)
        tmp_path = Path(tmp.name)

    try:
        allowed, _mime, reason = check_mime_policy(
            tmp_path,
            allowlist=settings.mime_allowlist,
            denylist=settings.mime_denylist,
            content_type_hint=file.content_type,
        )
        if not allowed:
            raise HTTPException(status_code=415, detail=reason or "MIME type not allowed")
        return orchestrator.scan_file(
            tmp_path,
            file.filename,
            sensitivity=sens,
            use_remote_intel=remote,
        )
    finally:
        tmp_path.unlink(missing_ok=True)


@router.get("/scan/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: UUID, request: Request) -> ScanResult:
    _enforce_access(request)
    result = _orchestrator(request).get_result(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return result
