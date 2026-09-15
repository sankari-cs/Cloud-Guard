"""Aggregate findings into scan-level statistics.

Input:  iterable of objects with these attributes:
          - secret_type: str
          - severity:    str
          - risk_score:  float
          - fingerprint: str
          - file_path:   str

Output: Summary dataclass used by the dashboard, reports, and API.

This module never touches the DB. The orchestrator fetches findings and
passes them here.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Protocol


class _FindingLike(Protocol):
    secret_type: str
    severity: str
    risk_score: float
    fingerprint: str
    file_path: str


SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")


@dataclass
class Summary:
    total: int
    by_severity: dict[str, int]
    by_type: dict[str, int]
    average_risk: float
    max_risk: float
    top_files: list[tuple[str, int]]
    recurring_fingerprints: list[tuple[str, int]]
    risk_distribution: dict[str, int] = field(default_factory=dict)


def _severity_bucket(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 50:
        return "medium"
    if score >= 25:
        return "low"
    return "informational"


def summarize(
    findings: Iterable[_FindingLike],
    *,
    top_files_limit: int = 5,
    recurring_limit: int = 5,
) -> Summary:
    """Compute Summary from an iterable of finding-like objects."""
    findings = list(findings)
    total = len(findings)

    by_severity: Counter[str] = Counter()
    by_type: Counter[str] = Counter()
    by_file: Counter[str] = Counter()
    by_fp: Counter[str] = Counter()
    risk_distribution: Counter[str] = Counter()

    total_risk = 0.0
    max_risk = 0.0

    for f in findings:
        sev = (f.severity or "").lower() or "informational"
        by_severity[sev] += 1
        by_type[f.secret_type] += 1
        by_file[f.file_path] += 1
        if f.fingerprint:
            by_fp[f.fingerprint] += 1

        score = float(f.risk_score or 0.0)
        total_risk += score
        if score > max_risk:
            max_risk = score
        risk_distribution[_severity_bucket(score)] += 1

    average_risk = round(total_risk / total, 2) if total else 0.0

    # Ensure every severity key exists so UI never has to special-case.
    for sev in SEVERITY_ORDER:
        by_severity.setdefault(sev, 0)
        risk_distribution.setdefault(sev, 0)

    top_files = [
        (path, count)
        for path, count in by_file.most_common(top_files_limit)
    ]
    recurring = [
        (fp, count)
        for fp, count in by_fp.most_common(recurring_limit)
        if count > 1
    ]

    return Summary(
        total=total,
        by_severity=dict(by_severity),
        by_type=dict(by_type),
        average_risk=average_risk,
        max_risk=round(max_risk, 2),
        top_files=top_files,
        recurring_fingerprints=recurring,
        risk_distribution=dict(risk_distribution),
    )


__all__ = ["Summary", "summarize", "SEVERITY_ORDER"]