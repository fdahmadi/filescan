import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status

from app.config import Settings


def _configured_keys(settings: Settings) -> set[str]:
    return {k.strip() for k in settings.api_keys.split(",") if k.strip()}


def require_api_key(request: Request, settings: Settings) -> str | None:
    """
    If FILESCAN_API_KEYS is empty, auth is disabled (dev mode).
    Otherwise require header X-API-Key matching one of the keys.
    Returns the key used (or None when auth disabled).
    """
    keys = _configured_keys(settings)
    if not keys:
        return None

    provided = request.headers.get("X-API-Key") or request.headers.get("x-api-key")
    if not provided or provided not in keys:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing X-API-Key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return provided


class RateLimiter:
    """Simple sliding-window rate limiter (per key / IP)."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, bucket: str, limit_per_minute: int) -> None:
        if limit_per_minute <= 0:
            return
        now = time.time()
        window = self._hits[bucket]
        while window and now - window[0] > 60.0:
            window.popleft()
        if len(window) >= limit_per_minute:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"rate limit exceeded ({limit_per_minute}/minute)",
            )
        window.append(now)
