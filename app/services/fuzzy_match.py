"""Compare fuzzy hashes against local denylist / cached malicious samples."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from app.models.schemas import Verdict
from app.services.fuzzy import ssdeep_score, tlsh_distance
from app.services.scan_cache import ScanResultCache


@dataclass
class FuzzyHit:
    kind: str  # ssdeep | tlsh
    score: int
    reference: str
    source: str  # denylist | cache


@dataclass
class FuzzyMatchResult:
    hits: list[FuzzyHit]

    @property
    def matched(self) -> bool:
        return bool(self.hits)


def _load_fuzzy_refs(denylist_path: Path) -> tuple[list[str], list[str]]:
    if not denylist_path.exists():
        return [], []
    try:
        raw = json.loads(denylist_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [], []
    if not isinstance(raw, dict):
        return [], []
    ss = [str(x) for x in (raw.get("ssdeep") or []) if x]
    tl = [str(x) for x in (raw.get("tlsh") or []) if x]
    return ss, tl


def match_fuzzy(
    *,
    ssdeep_hash: str | None,
    tlsh_hash: str | None,
    denylist_path: Path,
    cache: ScanResultCache | None,
    ssdeep_threshold: int,
    tlsh_max_distance: int,
) -> FuzzyMatchResult:
    hits: list[FuzzyHit] = []

    deny_ssdeep, deny_tlsh = _load_fuzzy_refs(denylist_path)

    if ssdeep_hash:
        for ref in deny_ssdeep:
            score = ssdeep_score(ssdeep_hash, ref)
            if score is not None and score >= ssdeep_threshold:
                hits.append(
                    FuzzyHit(kind="ssdeep", score=score, reference=ref[:48], source="denylist")
                )

    if tlsh_hash:
        for ref in deny_tlsh:
            dist = tlsh_distance(tlsh_hash, ref)
            if dist is not None and dist <= tlsh_max_distance:
                hits.append(
                    FuzzyHit(kind="tlsh", score=dist, reference=ref[:48], source="denylist")
                )

    if cache is not None:
        for sha, entry in cache.items():
            result = entry.get("result") if isinstance(entry, dict) else None
            if not isinstance(result, dict):
                continue
            if result.get("verdict") != Verdict.malicious.value:
                continue
            file_info = result.get("file") or {}
            ref_ss = file_info.get("ssdeep")
            ref_tl = file_info.get("tlsh")
            if ssdeep_hash and ref_ss:
                score = ssdeep_score(ssdeep_hash, ref_ss)
                if score is not None and score >= ssdeep_threshold:
                    hits.append(
                        FuzzyHit(
                            kind="ssdeep",
                            score=score,
                            reference=f"cache:{sha[:12]}",
                            source="cache",
                        )
                    )
            if tlsh_hash and ref_tl:
                dist = tlsh_distance(tlsh_hash, ref_tl)
                if dist is not None and dist <= tlsh_max_distance:
                    hits.append(
                        FuzzyHit(
                            kind="tlsh",
                            score=dist,
                            reference=f"cache:{sha[:12]}",
                            source="cache",
                        )
                    )

    # Keep strongest few hits
    hits.sort(key=lambda h: (-h.score if h.kind == "ssdeep" else h.score))
    return FuzzyMatchResult(hits=hits[:10])
