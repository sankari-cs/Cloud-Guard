"""Public validator facade.
Thin wrapper so callers import from a single place.
"""
from __future__ import annotations
from app.services.validators.base import ValidationResult
from app.services.validators.registry import validate_detection
__all__ = ["ValidationResult", "validate_detection"]
