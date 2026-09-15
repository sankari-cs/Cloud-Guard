"""Build the canonical report dict from a Scan and its Findings.

This is the single source of truth for every report format. It reads from
models, never from raw files, and never touches plaintext secrets —
findings already store redacted_value + fingerprint only.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Iterable


def _iso(dt) -> str | None:
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _severity_rank(label: str) -> int:
    order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "informational": 4,
    }
    return order.get((label or "").lower(), 5)


def build_report_data(scan, findings: Iterable) -> dict:
    """Return a dict suitable for JSON, HTML, or PDF rendering."""
    findings = list(findings)

    by_severity: Counter[str] = Counter()
    by_type: Counter[str] = Counter()
    for f in findings:
        by_severity[(f.severity or "informational").lower()] += 1
        by_type[f.secret_type] += 1

    for sev in ("critical", "high", "medium", "low", "informational"):
        by_severity.setdefault(sev, 0)

    sorted_findings = sorted(
        findings,
        key=lambda f: (_severity_rank(f.severity), -float(f.risk_score or 0.0)),
    )

    finding_rows = [
        {
            "id": f.id,
            "severity": f.severity,
            "risk_score": float(f.risk_score or 0.0),
            "secret_type": f.secret_type,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "column_number": f.column_number,
            "redacted_value": f.redacted_value,
            "fingerprint": f.fingerprint,
            "confidence": float(f.confidence or 0.0),
            "validation_status": f.validation_status,
            "detection_reason": f.detection_reason,
            "triage_status": f.triage_status,
            "created_at": _iso(f.created_at),
        }
        for f in sorted_findings
    ]

    total = len(findings)
    average_risk = (
        round(sum(float(f.risk_score or 0.0) for f in findings) / total, 2)
        if total
        else 0.0
    )
    max_risk = max((float(f.risk_score or 0.0) for f in findings), default=0.0)

    return {
        "report": {
            "product": "CloudGuard",
            "version": "1.0",
            "generated_at": _iso(datetime.now(timezone.utc)),
            "format_version": 1,
        },
        "scan": {
            "id": scan.id,
            "name": scan.scan_name,
            "source_type": scan.source_type,
            "source_path": scan.source_path,
            "status": scan.status,
            "started_at": _iso(scan.started_at),
            "completed_at": _iso(scan.completed_at),
            "files_scanned": scan.files_scanned,
            "risk_score": float(scan.risk_score or 0.0),
            "error_message": scan.error_message,
        },
        "summary": {
            "total": total,
            "average_risk": average_risk,
            "max_risk": round(max_risk, 2),
            "by_severity": dict(by_severity),
            "by_type": dict(by_type),
            "critical_count": by_severity.get("critical", 0),
            "high_count": by_severity.get("high", 0),
            "medium_count": by_severity.get("medium", 0),
            "low_count": by_severity.get("low", 0),
            "info_count": by_severity.get("informational", 0),
        },
        "findings": finding_rows,
    }


__all__ = ["build_report_data"]