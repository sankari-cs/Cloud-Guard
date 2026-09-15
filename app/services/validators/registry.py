"""Registry that dispatches a Detection to the right validator."""
from __future__ import annotations
from app.services.detection.engine import Detection
from app.services.validators.aws import AWSValidator
from app.services.validators.base import ValidationResult, Validator
from app.services.validators.generic import GenericValidator
from app.services.validators.github import GitHubValidator
VALIDATORS: tuple[Validator, ...] = (
    AWSValidator(),
    GitHubValidator(),
    GenericValidator(),
)
def _find_validator(secret_type: str) -> Validator | None:
    for v in VALIDATORS:
        if secret_type in v.handles:
            return v
    return None
def validate_detection(detection: Detection) -> ValidationResult:
    """Run the applicable validator for this detection.
    Returns a ValidationResult. Never touches the network.
    """
    validator = _find_validator(detection.secret_type)
    if validator is None:
        return ValidationResult(
            status="unknown",
            reason=f"no validator registered for {detection.secret_type!r}",
            confidence_delta=0.0,
        )
    return validator.validate(detection.secret_type, detection.matched_value)
__all__ = ["ValidationResult", "validate_detection", "VALIDATORS"]
