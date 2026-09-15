"""Severity mapping for 0-100 risk scores.

Thresholds are configurable. Defaults:
  0-24   informational
  25-49  low
  50-69  medium
  70-84  high
  85-100 critical
"""
from __future__ import annotations

SEVERITY_THRESHOLDS: tuple[tuple[int, str], ...] = (
    (85, "critical"),
    (70, "high"),
    (50, "medium"),
    (25, "low"),
    (0, "informational"),
)


def severity_for_score(score: float) -> str:
    """Return the severity label for a 0-100 score."""
    s = max(0.0, min(100.0, float(score)))
    for threshold, label in SEVERITY_THRESHOLDS:
        if s >= threshold:
            return label
    return "informational"


def severity_rank(label: str) -> int:
    """Higher = more severe. Useful for sorting."""
    order = {
        "informational": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    return order.get(label, 0)