"""Public risk engine facade.

Given a Detection and its ValidationResult, produce a risk score and
severity label.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.services.detection.engine import Detection
from app.services.risk.factors import RiskContext
from app.services.risk.scoring import calculate_risk_score
from app.services.risk.severity import severity_for_score
from app.services.validators.base import ValidationResult


@dataclass
class RiskResult:
    score: float
    severity: str
    factors: dict[str, float]
    explanation: str


def _is_config_file(file_path: str) -> bool:
    lowered = file_path.lower().replace("\\", "/")
    name = lowered.rsplit("/", 1)[-1]
    return (
        name.startswith(".env")
        or name in {
            "docker-compose.yml", "docker-compose.yaml", "dockerfile",
            "settings.py", "config.py",
            "application.yml", "application.yaml", "application.properties",
            ".npmrc", ".pypirc", ".netrc",
        }
    )


def _is_test_path(file_path: str) -> bool:
    lowered = file_path.lower().replace("\\", "/")
    return (
        lowered.startswith("tests/")
        or "/tests/" in lowered
        or "/test/" in lowered
        or lowered.rsplit("/", 1)[-1].startswith("test_")
    )


def _is_documentation(file_path: str) -> bool:
    lowered = file_path.lower().replace("\\", "/")
    name = lowered.rsplit("/", 1)[-1]
    return (
        lowered.startswith("docs/")
        or "/docs/" in lowered
        or name.endswith(".md")
    )


def _is_production_path(file_path: str) -> bool:
    lowered = file_path.lower()
    return any(marker in lowered for marker in ("prod", "production", "live"))


def build_context(
    detection: Detection,
    validation: ValidationResult,
    *,
    is_public_repo: bool = False,
    is_reused: bool = False,
) -> RiskContext:
    """Translate Detection + Validation into a RiskContext."""
    return RiskContext(
        secret_type=detection.secret_type,
        confidence=detection.confidence,
        entropy=detection.entropy,
        validation_status=validation.status,
        validation_delta=validation.confidence_delta,
        file_path=detection.detection_reason and "" or "",  # placeholder, replaced below
        line_number=detection.line_number,
        is_config_file=False,
        is_production_path=False,
        is_test_path=False,
        is_documentation=False,
        is_public_repo=is_public_repo,
        is_reused=is_reused,
    )


def score_detection(
    detection: Detection,
    validation: ValidationResult,
    *,
    file_path: str,
    is_public_repo: bool = False,
    is_reused: bool = False,
) -> RiskResult:
    """Score a single detection given its file path and validation result."""
    ctx = RiskContext(
        secret_type=detection.secret_type,
        confidence=detection.confidence,
        entropy=detection.entropy,
        validation_status=validation.status,
        validation_delta=validation.confidence_delta,
        file_path=file_path,
        line_number=detection.line_number,
        is_config_file=_is_config_file(file_path),
        is_test_path=_is_test_path(file_path),
        is_documentation=_is_documentation(file_path),
        is_production_path=_is_production_path(file_path),
        is_public_repo=is_public_repo,
        is_reused=is_reused,
    )
    score, factors = calculate_risk_score(ctx)
    severity = severity_for_score(score)
    explanation = (
        f"type={ctx.secret_type} "
        f"file={file_path} "
        f"confidence={ctx.confidence:.2f} "
        f"validation={ctx.validation_status} "
        f"exposure={factors['exposure_name_code']:.0f}"
    )
    return RiskResult(
        score=score,
        severity=severity,
        factors=factors,
        explanation=explanation,
    )


__all__ = ["RiskResult", "RiskContext", "score_detection", "build_context"]