"""Verdict aggregation with optional sensitivity (strict / balanced / lenient)."""

from __future__ import annotations

from app.models.schemas import EngineResult, EngineStatus, Sensitivity, Verdict

# Engines whose hits are high-confidence for malware labeling
HARD_ENGINES = frozenset(
    {
        "clamav",
        "yara",
        "lmd",
        "oletools",
        "abusech",
        "yaraify",
        "hashlist",
        "fuzzy",
    }
)

# Heuristic / capability engines — noisy alone; sensitivity changes their weight
SOFT_ENGINES = frozenset({"precheck", "capa", "floss", "archive", "pefile"})


def _base_name(engine_name: str) -> str:
    return engine_name.split("@", 1)[0].lower()


def _is_hard(name: str) -> bool:
    return _base_name(name) in HARD_ENGINES


def _is_soft(name: str) -> bool:
    return _base_name(name) in SOFT_ENGINES


def aggregate_verdict(
    results: list[EngineResult],
    sensitivity: Sensitivity = Sensitivity.balanced,
) -> Verdict:
    if not results:
        return Verdict.error

    hard_infected = False
    hard_matched = False
    hard_suspicious = False
    soft_matched = False
    soft_suspicious = False
    other_matched = False
    other_suspicious = False

    for r in results:
        if r.status == EngineStatus.infected:
            if _is_hard(r.name) or not _is_soft(r.name):
                hard_infected = True
            else:
                soft_matched = True
        elif r.status == EngineStatus.matched:
            if _is_hard(r.name):
                hard_matched = True
            elif _is_soft(r.name):
                soft_matched = True
            else:
                other_matched = True
        elif r.status == EngineStatus.suspicious:
            if _is_hard(r.name):
                hard_suspicious = True
            elif _is_soft(r.name):
                soft_suspicious = True
            else:
                other_suspicious = True

    if hard_infected or hard_matched:
        return Verdict.malicious

    if sensitivity == Sensitivity.strict:
        if hard_suspicious or soft_matched or soft_suspicious or other_matched or other_suspicious:
            return Verdict.malicious
        # fall through to clean check

    if sensitivity == Sensitivity.lenient:
        # Soft signals alone never raise above suspicious; soft matched → suspicious
        if hard_suspicious or other_matched:
            return Verdict.suspicious
        if soft_matched or soft_suspicious or other_suspicious:
            return Verdict.suspicious
    else:
        # balanced (default): matched (non-hard already handled) / suspicious → as today
        if other_matched:
            return Verdict.malicious
        if soft_matched:
            # CAPA/FLOSS "matched" stays suspicious in balanced (not AV-grade)
            return Verdict.suspicious
        if hard_suspicious or soft_suspicious or other_suspicious:
            return Verdict.suspicious

    statuses = [r.status for r in results]
    actionable = [
        s
        for s in statuses
        if s
        not in {
            EngineStatus.skipped,
            EngineStatus.unavailable,
            EngineStatus.error,
        }
    ]
    if not actionable:
        return Verdict.error
    if all(s == EngineStatus.clean for s in actionable):
        return Verdict.clean
    return Verdict.unknown
