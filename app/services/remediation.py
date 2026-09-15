"""Remediation facade.

Formats a guide into a plain-text block suitable for storage on a
Finding.remediation field, or for display in the finding detail page.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.services.remediation_guides.guides import (
    DEFAULT_GUIDE,
    GUIDE_BY_TYPE,
    RemediationGuide,
    guide_for,
)


@dataclass(frozen=True)
class RemediationAdvice:
    secret_type: str
    immediate: tuple[str, ...]
    prevention: tuple[str, ...]
    controls: tuple[str, ...]
    references: dict[str, tuple[str, ...]]
    text: str


def _render_text(guide: RemediationGuide) -> str:
    lines: list[str] = []
    lines.append(f"Remediation: {guide.secret_type}")
    lines.append("")
    lines.append("Immediate actions:")
    for item in guide.immediate:
        lines.append(f"  - {item}")
    lines.append("")
    lines.append("Long-term prevention:")
    for item in guide.prevention:
        lines.append(f"  - {item}")
    lines.append("")
    lines.append("Recommended controls:")
    for item in guide.controls:
        lines.append(f"  - {item}")
    if guide.references:
        lines.append("")
        lines.append("References:")
        for framework, items in guide.references.items():
            for item in items:
                lines.append(f"  - {framework}: {item}")
    return "\n".join(lines)


def remediation_for(secret_type: str) -> RemediationAdvice:
    """Return structured remediation advice for a secret type."""
    guide = guide_for(secret_type)
    return RemediationAdvice(
        secret_type=guide.secret_type,
        immediate=guide.immediate,
        prevention=guide.prevention,
        controls=guide.controls,
        references=guide.references,
        text=_render_text(guide),
    )


def remediation_text(secret_type: str) -> str:
    """Return just the plain-text block (for DB storage)."""
    return remediation_for(secret_type).text


__all__ = [
    "RemediationAdvice",
    "remediation_for",
    "remediation_text",
    "RemediationGuide",
    "GUIDE_BY_TYPE",
    "DEFAULT_GUIDE",
]