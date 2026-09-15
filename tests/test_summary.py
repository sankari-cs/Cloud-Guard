"""Tests for scan summary aggregation."""
from dataclasses import dataclass

from app.services.summary import SEVERITY_ORDER, summarize


@dataclass
class F:
    secret_type: str
    severity: str
    risk_score: float
    fingerprint: str
    file_path: str


def _f(**kwargs):
    base = dict(
        secret_type="Password",
        severity="medium",
        risk_score=60.0,
        fingerprint="fp-1",
        file_path="app.py",
    )
    base.update(kwargs)
    return F(**base)


def test_empty_findings():
    s = summarize([])
    assert s.total == 0
    assert s.average_risk == 0.0
    assert s.max_risk == 0.0
    for sev in SEVERITY_ORDER:
        assert s.by_severity[sev] == 0


def test_total_counts():
    s = summarize([_f(), _f(), _f()])
    assert s.total == 3


def test_by_severity():
    s = summarize([
        _f(severity="critical"),
        _f(severity="critical"),
        _f(severity="low"),
    ])
    assert s.by_severity["critical"] == 2
    assert s.by_severity["low"] == 1
    assert s.by_severity["high"] == 0


def test_by_type():
    s = summarize([
        _f(secret_type="AWS Access Key"),
        _f(secret_type="AWS Access Key"),
        _f(secret_type="Password"),
    ])
    assert s.by_type["AWS Access Key"] == 2
    assert s.by_type["Password"] == 1


def test_average_and_max_risk():
    s = summarize([
        _f(risk_score=50.0),
        _f(risk_score=90.0),
        _f(risk_score=70.0),
    ])
    assert s.average_risk == 70.0
    assert s.max_risk == 90.0


def test_top_files():
    s = summarize([
        _f(file_path="a.py"),
        _f(file_path="a.py"),
        _f(file_path="b.py"),
        _f(file_path="c.py"),
    ])
    assert s.top_files[0] == ("a.py", 2)


def test_recurring_fingerprints_only_counts_repeats():
    s = summarize([
        _f(fingerprint="reused"),
        _f(fingerprint="reused"),
        _f(fingerprint="unique"),
    ])
    fps = [fp for fp, _count in s.recurring_fingerprints]
    assert "reused" in fps
    assert "unique" not in fps


def test_recurring_fingerprints_limit():
    findings = [_f(fingerprint=f"fp{i}") for i in range(10) for _ in range(2)]
    s = summarize(findings, recurring_limit=3)
    assert len(s.recurring_fingerprints) <= 3


def test_risk_distribution_buckets():
    s = summarize([
        _f(risk_score=10),   # informational
        _f(risk_score=30),   # low
        _f(risk_score=60),   # medium
        _f(risk_score=75),   # high
        _f(risk_score=95),   # critical
    ])
    assert s.risk_distribution["informational"] == 1
    assert s.risk_distribution["low"] == 1
    assert s.risk_distribution["medium"] == 1
    assert s.risk_distribution["high"] == 1
    assert s.risk_distribution["critical"] == 1


def test_severity_keys_always_present():
    s = summarize([_f()])
    for sev in SEVERITY_ORDER:
        assert sev in s.by_severity
        assert sev in s.risk_distribution


def test_unknown_severity_defaults_to_informational_in_distribution():
    s = summarize([_f(severity="", risk_score=10)])
    assert s.by_severity["informational"] == 1