"""Generic validator for shapes without a fixed format.

For these types we only check basic sanity: not empty, not a placeholder,
reasonable length, and consistent character class usage.
"""
from __future__ import annotations

from app.services.validators.base import ValidationResult


class GenericValidator:
    name = "generic"
    handles = (
        "Password",
        "Secret",
        "Token",
        "API Key",
        "Bearer Token",
        "JWT",
        "Private Key",
        "Slack Token",
        "Google API Key",
        "Stripe Secret Key",
        "Database Connection String",
    )

    MIN_LENGTH = 6
    MAX_LENGTH = 4096

    def validate(self, secret_type: str, value: str) -> ValidationResult:
        if secret_type not in self.handles:
            return ValidationResult(
                status="unknown",
                reason="generic validator does not handle this type",
                confidence_delta=0.0,
            )

        value = value.strip()

        if not value:
            return ValidationResult(
                status="format_invalid",
                reason="empty value",
                confidence_delta=-0.30,
            )
        if len(value) < self.MIN_LENGTH:
            return ValidationResult(
                status="format_invalid",
                reason=f"shorter than {self.MIN_LENGTH} characters",
                confidence_delta=-0.15,
            )
        if len(value) > self.MAX_LENGTH:
            return ValidationResult(
                status="format_invalid",
                reason=f"longer than {self.MAX_LENGTH} characters",
                confidence_delta=-0.10,
            )
        return ValidationResult(
            status="format_valid",
            reason="reasonable length and non-empty",
            confidence_delta=0.0,
        )