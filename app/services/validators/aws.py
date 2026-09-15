"""Format-level validation for AWS credential shapes.

We never call AWS. This only checks structural properties.
"""
from __future__ import annotations

import re

from app.services.validators.base import ValidationResult

AWS_ACCESS_KEY_RE = re.compile(r"^AKIA[0-9A-Z]{16}$")
AWS_SECRET_RE = re.compile(r"^[A-Za-z0-9/+=]{40}$")

# AWS's own documented sample. Never a real credential.
KNOWN_DOC_SAMPLES = {
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}


class AWSValidator:
    name = "aws"
    handles = ("AWS Access Key", "AWS Secret Access Key")

    def validate(self, secret_type: str, value: str) -> ValidationResult:
        value = value.strip()

        if secret_type == "AWS Access Key":
            if value in KNOWN_DOC_SAMPLES:
                return ValidationResult(
                    status="format_invalid",
                    reason="value matches AWS documentation sample key",
                    confidence_delta=-0.30,
                )
            if not AWS_ACCESS_KEY_RE.match(value):
                return ValidationResult(
                    status="format_invalid",
                    reason="AWS access key ID must be 'AKIA' + 16 uppercase alnum",
                    confidence_delta=-0.20,
                )
            return ValidationResult(
                status="format_valid",
                reason="matches AKIA + 16 alnum pattern",
                confidence_delta=0.0,
            )

        if secret_type == "AWS Secret Access Key":
            if value in KNOWN_DOC_SAMPLES:
                return ValidationResult(
                    status="format_invalid",
                    reason="value matches AWS documentation sample secret",
                    confidence_delta=-0.30,
                )
            if not AWS_SECRET_RE.match(value):
                return ValidationResult(
                    status="format_invalid",
                    reason="AWS secret access key must be 40 base64 characters",
                    confidence_delta=-0.20,
                )
            return ValidationResult(
                status="format_valid",
                reason="40 base64 characters",
                confidence_delta=0.0,
            )

        return ValidationResult(
            status="unknown",
            reason="AWS validator does not handle this type",
            confidence_delta=0.0,
        )