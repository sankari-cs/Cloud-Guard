"""Validators: separate concern from detection.

Detector answers: "Is this value suspicious?"
Validator answers: "Can we increase confidence this is a real credential?"

Validation is format/structure only by default. Network checks against
providers (AWS STS, GitHub API, etc.) are OPTIONAL and DISABLED.
"""
from .registry import (
    ValidationResult,
    validate_detection,
)

__all__ = ["ValidationResult", "validate_detection"]