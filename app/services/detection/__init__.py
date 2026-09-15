"""Detection subpackage: rules, entropy, context, engine."""
from app.services.detection.engine import (
    Detection,
    detect_in_file,
    detect_in_text,
)

__all__ = ["Detection", "detect_in_file", "detect_in_text"]