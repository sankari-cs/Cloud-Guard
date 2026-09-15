"""Validation result dataclass and base validator protocol."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of validating a single detected value.

    status is one of:
      - "unknown"         no validator was applicable
      - "format_valid"    structure/prefix/length/checksum all pass
      - "format_invalid"  structure/prefix/length/checksum fails
      - "likely_valid"    format valid AND an optional external signal confirmed
      - "likely_invalid"  format valid BUT an optional external signal denied
    """
    status: str
    reason: str
    confidence_delta: float  # additive adjustment for the detector's confidence


@runtime_checkable
class Validator(Protocol):
    """A validator handles one or more secret_type values."""
    name: str
    handles: tuple[str, ...]

    def validate(self, secret_type: str, value: str) -> ValidationResult:
        ...