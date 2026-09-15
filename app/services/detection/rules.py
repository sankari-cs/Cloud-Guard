"""Regex rule set for known credential formats and generic assignments."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretRule:
    """A single regex-based detection rule.

    `value_group` selects which capture group holds the secret value.
    0 means the whole match is the value.
    """
    name: str
    secret_type: str
    pattern: re.Pattern[str]
    base_confidence: float
    value_group: int = 1


def _compile(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


SPECIFIC_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        name="aws_access_key_id",
        secret_type="AWS Access Key",
        pattern=_compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        base_confidence=0.95,
    ),
    SecretRule(
        name="aws_secret_access_key",
        secret_type="AWS Secret Access Key",
        pattern=_compile(
            r"""(?ix)
            aws[_\- ]?secret[_\- ]?access[_\- ]?key
            \s*[:=]\s*
            ['"]?([A-Za-z0-9/+=]{40})['"]?
            """
        ),
        base_confidence=0.90,
    ),
    SecretRule(
        name="github_pat_classic",
        secret_type="GitHub Token",
        pattern=_compile(r"\b(ghp_[A-Za-z0-9]{36})\b"),
        base_confidence=0.98,
    ),
    SecretRule(
        name="github_pat_fine_grained",
        secret_type="GitHub Token",
        pattern=_compile(r"\b(github_pat_[A-Za-z0-9_]{82})\b"),
        base_confidence=0.98,
    ),
    SecretRule(
        name="github_oauth",
        secret_type="GitHub Token",
        pattern=_compile(r"\b(gho_[A-Za-z0-9]{36})\b"),
        base_confidence=0.95,
    ),
    SecretRule(
        name="github_app",
        secret_type="GitHub Token",
        pattern=_compile(r"\b(ghs_[A-Za-z0-9]{36})\b"),
        base_confidence=0.95,
    ),
    SecretRule(
        name="slack_token",
        secret_type="Slack Token",
        pattern=_compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
        base_confidence=0.95,
    ),
    SecretRule(
        name="google_api_key",
        secret_type="Google API Key",
        pattern=_compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
        base_confidence=0.95,
    ),
    SecretRule(
        name="stripe_live_secret",
        secret_type="Stripe Secret Key",
        pattern=_compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b"),
        base_confidence=0.98,
    ),
    SecretRule(
        name="jwt",
        secret_type="JWT",
        pattern=_compile(
            r"\b(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)\b"
        ),
        base_confidence=0.85,
        value_group=1,
    ),
    SecretRule(
        name="private_key_header",
        secret_type="Private Key",
        pattern=_compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
        ),
        base_confidence=0.95,
        value_group=0,
    ),
)


GENERIC_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        name="generic_password",
        secret_type="Password",
        pattern=_compile(
            r"""(?ix)
            \b(pass(?:word|wd)?|pwd)
            \s*[:=]\s*
            ['"]([^'"\r\n]{4,})['"]
            """
        ),
        base_confidence=0.55,
        value_group=2,
    ),
    SecretRule(
        name="generic_secret",
        secret_type="Secret",
        pattern=_compile(
            r"""(?ix)
            \b(
                client[_-]?secret
              | app[_-]?secret
              | secret[_-]?key
              | secret
            )
            \s*[:=]\s*
            ['"]([^'"\r\n]{4,})['"]
            """
        ),
        base_confidence=0.55,
        value_group=2,
    ),
    SecretRule(
        name="generic_token",
        secret_type="Token",
        pattern=_compile(
            r"""(?ix)
            \b(
                access[_-]?token
              | auth[_-]?token
              | api[_-]?token
              | bearer[_-]?token
              | token
            )
            \s*[:=]\s*
            ['"]([^'"\r\n]{8,})['"]
            """
        ),
        base_confidence=0.55,
        value_group=2,
    ),
    SecretRule(
        name="generic_api_key",
        secret_type="API Key",
        pattern=_compile(
            r"""(?ix)
            \b(
                api[_-]?key
              | apikey
              | api[_-]?secret
              | access[_-]?key
              | secret[_-]?access[_-]?key
            )
            \s*[:=]\s*
            ['"]([^'"\r\n]{8,})['"]
            """
        ),
        base_confidence=0.55,
        value_group=2,
    ),
    SecretRule(
        name="authorization_bearer",
        secret_type="Bearer Token",
        pattern=_compile(
            r"(?i)\bAuthorization\s*:\s*Bearer\s+([A-Za-z0-9_\-\.=+/]{16,})"
        ),
        base_confidence=0.70,
        value_group=1,
    ),
    SecretRule(
        name="db_connection_string",
        secret_type="Database Connection String",
        pattern=_compile(
            r"""(?ix)
            \b(
                postgres(?:ql)?://[^\s'"]+
              | mysql://[^\s'"]+
              | mongodb(?:\+srv)?://[^\s'"]+
              | redis://[^\s'"]+
              | amqp://[^\s'"]+
            )
            """
        ),
        base_confidence=0.80,
        value_group=1,
    ),
)


ALL_RULES: tuple[SecretRule, ...] = SPECIFIC_RULES + GENERIC_RULES