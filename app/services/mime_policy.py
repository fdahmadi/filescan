from pathlib import Path

from app.services.mime import detect_mime


def _split_prefixes(raw: str) -> list[str]:
    return [p.strip().lower() for p in raw.split(",") if p.strip()]


def check_mime_policy(
    path: Path,
    *,
    allowlist: str,
    denylist: str,
    content_type_hint: str | None = None,
) -> tuple[bool, str | None, str | None]:
    """
    Return (allowed, mime, reason_if_blocked).
    Empty allowlist means allow any MIME not on the denylist.
    """
    mime = detect_mime(path) or (content_type_hint or "").split(";")[0].strip().lower() or None
    if not mime:
        # Unknown type: allow unless allowlist is strict
        if allowlist.strip():
            return False, mime, "unknown MIME type rejected by allowlist policy"
        return True, mime, None

    mime_l = mime.lower()
    for prefix in _split_prefixes(denylist):
        if mime_l.startswith(prefix):
            return False, mime, f"MIME denied by policy: {mime}"

    allowed_prefixes = _split_prefixes(allowlist)
    if allowed_prefixes and not any(mime_l.startswith(p) for p in allowed_prefixes):
        return False, mime, f"MIME not in allowlist: {mime}"

    return True, mime, None
