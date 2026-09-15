"""Format-level validation for GitHub token shapes."""
from __future__ import annotations

import re

from app.services.validators.base import ValidationResult

GITHUB_CLASSIC = re.compile(r"^ghp_[A-Za-z0-9]{36}$")
GITHUB_OAUTH = re.compile(r"^gho_[A-Za-z0-9]{36}$")
GITHUB_APP = re.compile(r"^ghs_[A-Za-z0-9]{36}$")
GITHUB_FINE = re.compile(r"^github_pat_[A-Za-z0-9_]{82}$")


class GitHubValidator:
    name = "github"
    handles = ("GitHub Token",)

    def validate(self, secret_type: str, value: str) -> ValidationResult:
        if secret_type != "GitHub Token":
            return ValidationResult(
                status="unknown",
                reason="GitHub validator does not handle this type",
                confidence_delta=0.0,
            )

        value = value.strip()

        if GITHUB_CLASSIC.match(value):
            return ValidationResult(
                status="format_valid",
                reason="classic PAT prefix 'ghp_' with 36 alnum",
                confidence_delta=0.0,
            )
        if GITHUB_OAUTH.match(value):
            return ValidationResult(
                status="format_valid",
                reason="OAuth token prefix 'gho_' with 36 alnum",
                confidence_delta=0.0,
            )
        if GITHUB_APP.match(value):
            return ValidationResult(
                status="format_valid",
                reason="App token prefix 'ghs_' with 36 alnum",
                confidence_delta=0.0,
            )
        if GITHUB_FINE.match(value):
            return ValidationResult(
                status="format_valid",
                reason="fine-grained PAT prefix 'github_pat_' with 82 chars",
                confidence_delta=0.0,
            )

        return ValidationResult(
            status="format_invalid",
            reason="does not match any known GitHub token shape",
            confidence_delta=-0.20,
        )