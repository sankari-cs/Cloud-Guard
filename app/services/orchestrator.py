"""Scan orchestrator.

Ties the pipeline together:
    scanner → detector → validator → risk → remediation → redactor → DB

Design:
  - The orchestrator is the ONLY place that writes Scan / Finding / Alert.
  - It never stores plaintext secrets. It uses redactor + fingerprint.
  - It runs inside a Flask app context so SQLAlchemy sessions work.
  - It fails loudly with Scan.status = "failed" and an error_message,
    so the UI can surface the reason without leaking stack traces.
"""
from __future__ import annotations

import logging
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from app.extensions import db
from app.models.alert import Alert
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.archive_handler import ArchiveError, safe_extract_zip
from app.services.detector import Detection, detect_in_file
from app.services.file_scanner import scan_directory
from app.services.fingerprint import fingerprint_secret
from app.services.redactor import REDACTED, redact_secret, safe_context_snippet
from app.services.remediation import remediation_text
from app.services.risk_engine import score_detection
from app.services.summary import summarize
from app.services.validator import validate_detection

logger = logging.getLogger(__name__)


# ---------- limits ----------

MAX_FILES_TO_SCAN = 5000
MAX_FINDINGS_PER_SCAN = 2000
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB per file

# Alert trigger thresholds
ALERT_CRITICAL_THRESHOLD = 1
ALERT_PRIVATE_KEY_THRESHOLD = 1
ALERT_FINDINGS_VOLUME = 100
ALERT_REUSE_THRESHOLD = 2


@dataclass
class ScanResult:
    """Immutable result of a single scan run."""
    scan_id: int
    scan_name: str
    status: str
    files_scanned: int
    findings_count: int
    findings_created: int
    alerts_created: int
    summary: dict
    error_message: str | None = None
    errors: list[str] = field(default_factory=list)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------- helpers ----------

def _severity_alerts_for_finding(finding: Finding) -> list[Alert]:
    """Produce alerts based on a single finding."""
    alerts: list[Alert] = []
    if finding.severity == "critical":
        alerts.append(Alert(
            finding_id=finding.id,
            alert_type="critical_secret",
            severity="critical",
            status="open",
        ))
    if finding.secret_type == "Private Key":
        alerts.append(Alert(
            finding_id=finding.id,
            alert_type="private_key_detected",
            severity="critical",
            status="open",
        ))
    return alerts


def _persist_finding(
    scan: Scan,
    detection: Detection,
    *,
    file_path: str,
    source_text: str,
    extra_secrets_in_file: list[str],
    seen_fingerprints: set[str],
) -> Finding | None:
    """Validate, score, redact, fingerprint, and insert a single Finding.

    `extra_secrets_in_file` is every secret value detected in the same file,
    so the snippet window cannot leak an adjacent credential.
    """
    validation = validate_detection(detection)
    risk = score_detection(
        detection,
        validation,
        file_path=file_path,
        is_reused=False,  # updated after all findings are in
    )

    fp = fingerprint_secret(detection.matched_value)
    if not fp:
        return None

    is_reused = fp in seen_fingerprints
    seen_fingerprints.add(fp)

    redacted = redact_secret(detection.matched_value)

    # Redact EVERY secret detected in this file so adjacent credentials
    # cannot leak via the context snippet.
    all_secrets = [detection.matched_value] + [
        s for s in extra_secrets_in_file if s and s != detection.matched_value
    ]
    snippet = safe_context_snippet(
        source_text,
        line_number=detection.line_number,
        secrets=all_secrets,
        radius=2,
    )

    remediation_block = remediation_text(detection.secret_type)

    finding = Finding(
        scan_id=scan.id,
        secret_type=detection.secret_type,
        file_path=file_path,
        line_number=detection.line_number,
        column_number=detection.column_number,
        redacted_value=redacted if redacted else REDACTED,
        fingerprint=fp,
        confidence=detection.confidence,
        validation_status=validation.status,
        risk_score=risk.score,
        severity=risk.severity,
        remediation=remediation_block,
        detection_reason=detection.detection_reason,
        context_snippet=snippet,
        triage_status="open",
    )
    db.session.add(finding)
    return finding


def _apply_reuse_penalty(scan_id: int) -> None:
    """Bump risk for fingerprints that appear more than once in the scan."""
    from sqlalchemy import func, select

    stmt = (
        select(Finding.fingerprint, func.count(Finding.id))
        .where(Finding.scan_id == scan_id)
        .group_by(Finding.fingerprint)
        .having(func.count(Finding.id) > 1)
    )
    reused = {fp for fp, _count in db.session.execute(stmt).all()}
    if not reused:
        return

    stmt2 = select(Finding).where(
        Finding.scan_id == scan_id,
        Finding.fingerprint.in_(reused),
    )
    for finding in db.session.execute(stmt2).scalars():
        finding.risk_score = min(100.0, float(finding.risk_score or 0.0) + 5.0)
        if finding.risk_score >= 85:
            finding.severity = "critical"
        elif finding.risk_score >= 70:
            finding.severity = "high"


def _finalize_scan(scan: Scan, findings: list[Finding]) -> None:
    """Fill counts and risk fields on the Scan row."""
    scan.findings_count = len(findings)
    scan.critical_count = sum(1 for f in findings if f.severity == "critical")
    scan.high_count = sum(1 for f in findings if f.severity == "high")
    scan.medium_count = sum(1 for f in findings if f.severity == "medium")
    scan.low_count = sum(1 for f in findings if f.severity == "low")
    scan.info_count = sum(1 for f in findings if f.severity == "informational")
    if findings:
        scan.risk_score = max(float(f.risk_score or 0.0) for f in findings)
    else:
        scan.risk_score = 0.0


def _volume_alerts(scan: Scan, findings: list[Finding]) -> list[Alert]:
    """Scan-level alerts that depend on the whole set."""
    alerts: list[Alert] = []

    if len(findings) > ALERT_FINDINGS_VOLUME and findings:
        alerts.append(Alert(
            finding_id=findings[0].id,
            alert_type="high_volume",
            severity="high",
            status="open",
        ))

    from collections import Counter
    fps = Counter(f.fingerprint for f in findings if f.fingerprint)
    for fp, count in fps.items():
        if count >= ALERT_REUSE_THRESHOLD:
            example = next(f for f in findings if f.fingerprint == fp)
            alerts.append(Alert(
                finding_id=example.id,
                alert_type="reused_secret",
                severity="high",
                status="open",
            ))
            break

    return alerts


# ---------- public API ----------

def run_scan(
    *,
    scan_name: str,
    source_type: str,
    source_path: str | None,
    created_by: int | None = None,
    zip_path: str | None = None,
) -> ScanResult:
    """Run a scan.

    Either source_path (a directory) or zip_path (a .zip file) must be given.
    """
    scan = Scan(
        scan_name=scan_name,
        source_type=source_type,
        source_path=source_path or zip_path,
        status="running",
        created_by=created_by,
    )
    db.session.add(scan)
    db.session.commit()

    logger.info("scan started id=%s name=%s", scan.id, scan_name)

    errors: list[str] = []
    findings: list[Finding] = []
    files_scanned = 0
    temp_dir: Path | None = None

    try:
        if zip_path:
            temp_dir = Path(tempfile.mkdtemp(prefix="cloudguard_zip_"))
            safe_extract_zip(zip_path, temp_dir)
            root = temp_dir
        elif source_path:
            root = Path(source_path)
            if not root.exists() or not root.is_dir():
                raise FileNotFoundError(f"Directory not found: {source_path}")
        else:
            raise ValueError("Either source_path or zip_path must be provided")

        seen_fingerprints: set[str] = set()
        truncated = False

        for scanned in scan_directory(root, max_file_size=MAX_FILE_SIZE_BYTES):
            if files_scanned >= MAX_FILES_TO_SCAN:
                truncated = True
                errors.append(f"File limit reached ({MAX_FILES_TO_SCAN})")
                break
            files_scanned += 1

            try:
                detections = detect_in_file(scanned)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"Detection error in {scanned.relative_path}: {exc}")
                continue

            # Collect every secret in this file once, so snippets redact
            # the entire window rather than just the primary match.
            all_secrets_in_file = [d.matched_value for d in detections if d.matched_value]

            for det in detections:
                if len(findings) >= MAX_FINDINGS_PER_SCAN:
                    truncated = True
                    errors.append(f"Finding limit reached ({MAX_FINDINGS_PER_SCAN})")
                    break
                finding = _persist_finding(
                    scan,
                    det,
                    file_path=scanned.relative_path,
                    source_text=scanned.content,
                    extra_secrets_in_file=all_secrets_in_file,
                    seen_fingerprints=seen_fingerprints,
                )
                if finding is not None:
                    findings.append(finding)

            if truncated and len(findings) >= MAX_FINDINGS_PER_SCAN:
                break

        db.session.flush()

        _apply_reuse_penalty(scan.id)
        db.session.flush()

        alerts_created = 0
        for f in findings:
            for alert in _severity_alerts_for_finding(f):
                db.session.add(alert)
                alerts_created += 1

        for alert in _volume_alerts(scan, findings):
            db.session.add(alert)
            alerts_created += 1

        _finalize_scan(scan, findings)
        scan.status = "completed"
        scan.completed_at = _utcnow()
        scan.files_scanned = files_scanned

        db.session.commit()
        logger.info(
            "scan completed id=%s files=%s findings=%s alerts=%s",
            scan.id, files_scanned, len(findings), alerts_created,
        )

        summary = summarize(findings)
        return ScanResult(
            scan_id=scan.id,
            scan_name=scan.scan_name,
            status="completed",
            files_scanned=files_scanned,
            findings_count=len(findings),
            findings_created=len(findings),
            alerts_created=alerts_created,
            summary={
                "total": summary.total,
                "by_severity": summary.by_severity,
                "by_type": summary.by_type,
                "average_risk": summary.average_risk,
                "max_risk": summary.max_risk,
                "top_files": summary.top_files,
                "recurring_fingerprints": summary.recurring_fingerprints,
                "risk_distribution": summary.risk_distribution,
            },
            errors=errors,
        )

    except (ArchiveError, FileNotFoundError, ValueError) as exc:
        db.session.rollback()
        scan.status = "failed"
        scan.error_message = str(exc)
        scan.completed_at = _utcnow()
        db.session.commit()
        logger.warning("scan failed id=%s reason=%s", scan.id, exc)
        return ScanResult(
            scan_id=scan.id,
            scan_name=scan.scan_name,
            status="failed",
            files_scanned=files_scanned,
            findings_count=0,
            findings_created=0,
            alerts_created=0,
            summary={},
            error_message=str(exc),
            errors=errors,
        )
    except Exception as exc:  # noqa: BLE001
        db.session.rollback()
        scan.status = "failed"
        scan.error_message = "Internal error while scanning"
        scan.completed_at = _utcnow()
        db.session.commit()
        logger.exception("scan crashed id=%s", scan.id)
        return ScanResult(
            scan_id=scan.id,
            scan_name=scan.scan_name,
            status="failed",
            files_scanned=files_scanned,
            findings_count=0,
            findings_created=0,
            alerts_created=0,
            summary={},
            error_message="Internal error while scanning",
            errors=errors + [str(exc)],
        )
    finally:
        if temp_dir and temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)


__all__ = ["run_scan", "ScanResult"]