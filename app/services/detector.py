"""Public detection facade.

Keep this module thin. All logic lives in app.services.detection.*
so we can grow rules/context/entropy independently.
"""
from __future__ import annotations

from app.services.detection.engine import (
    Detection,
    detect_in_file,
    detect_in_text,
)

__all__ = ["Detection", "detect_in_file", "detect_in_text"]