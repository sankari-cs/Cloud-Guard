"""Shannon entropy for detection signals.

Entropy is a *supporting* signal, never the sole reason to flag a value.
High entropy + credential-shaped assignment = higher confidence.
"""
from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(value: str) -> float:
    """Return Shannon entropy (base 2) of the string, in bits per char."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def is_high_entropy(
    value: str,
    *,
    min_length: int = 16,
    threshold: float = 3.5,
) -> bool:
    """True if value is long enough and random enough to look like a secret."""
    if len(value) < min_length:
        return False
    return shannon_entropy(value) >= threshold