from app.models.schemas import EngineResult, EngineStatus, Sensitivity, Verdict
from app.services.orchestrator import ScanOrchestrator
from app.services.verdict import aggregate_verdict


def test_aggregate_malicious_on_clamav_infected():
    results = [
        EngineResult(name="clamav", status=EngineStatus.infected, threats=["Eicar-Test-Signature"]),
        EngineResult(name="yara", status=EngineStatus.clean),
    ]
    assert ScanOrchestrator.aggregate_verdict(results) == Verdict.malicious


def test_aggregate_suspicious_on_soft_yara():
    results = [
        EngineResult(name="clamav", status=EngineStatus.clean),
        EngineResult(name="yara", status=EngineStatus.suspicious, threats=["suspicious_powershell_download"]),
    ]
    assert ScanOrchestrator.aggregate_verdict(results) == Verdict.suspicious


def test_aggregate_clean():
    results = [
        EngineResult(name="clamav", status=EngineStatus.clean),
        EngineResult(name="yara", status=EngineStatus.clean),
    ]
    assert ScanOrchestrator.aggregate_verdict(results) == Verdict.clean


def test_aggregate_error_when_all_failed():
    results = [
        EngineResult(name="clamav", status=EngineStatus.error, details="down"),
        EngineResult(name="yara", status=EngineStatus.unavailable),
    ]
    assert ScanOrchestrator.aggregate_verdict(results) == Verdict.error


def test_capa_matched_is_suspicious_in_balanced():
    results = [
        EngineResult(name="clamav", status=EngineStatus.clean),
        EngineResult(name="capa", status=EngineStatus.matched, threats=["execution:x"]),
    ]
    assert aggregate_verdict(results, Sensitivity.balanced) == Verdict.suspicious


def test_capa_matched_is_malicious_in_strict():
    results = [
        EngineResult(name="clamav", status=EngineStatus.clean),
        EngineResult(name="capa", status=EngineStatus.matched, threats=["execution:x"]),
    ]
    assert aggregate_verdict(results, Sensitivity.strict) == Verdict.malicious


def test_precheck_suspicious_stays_suspicious_in_lenient():
    results = [
        EngineResult(name="clamav", status=EngineStatus.clean),
        EngineResult(name="precheck", status=EngineStatus.suspicious, threats=["high_entropy"]),
    ]
    assert aggregate_verdict(results, Sensitivity.lenient) == Verdict.suspicious
    assert aggregate_verdict(results, Sensitivity.strict) == Verdict.malicious
