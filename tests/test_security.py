from fastapi import HTTPException

from app.api.security import RateLimiter, require_api_key
from app.config import Settings


class _Req:
    def __init__(self, headers: dict):
        self.headers = headers
        self.client = None


def test_api_key_optional_when_unset():
    settings = Settings(api_keys="")
    assert require_api_key(_Req({}), settings) is None


def test_api_key_required_when_configured():
    settings = Settings(api_keys="secret")
    try:
        require_api_key(_Req({}), settings)
        assert False, "expected HTTPException"
    except HTTPException as exc:
        assert exc.status_code == 401
    assert require_api_key(_Req({"X-API-Key": "secret"}), settings) == "secret"


def test_rate_limiter_trips():
    limiter = RateLimiter()
    for _ in range(3):
        limiter.check("k", 3)
    try:
        limiter.check("k", 3)
        assert False, "expected 429"
    except HTTPException as exc:
        assert exc.status_code == 429
