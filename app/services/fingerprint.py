"""Secret fingerprinting.

Goal: identify the SAME secret value across files and scans without ever
storing the plaintext value in the database.

Design:
  - Normalize first (strip, collapse whitespace, lower-case)
    so cosmetic differences do not create new fingerprints.
  - Do NOT apply a secret-specific salt. That would prevent cross-scan
    deduplication, which is the entire point.
  - SHA-256 is appropriate: the fingerprints are only used for equality
    and lookups, not for security boundaries. A brute-forcer with a
    small search space could still recover short secrets from the hash,
    so we ALSO never expose the fingerprint to untrusted users.
"""
from __future__ import annotations

import hashlib


def normalize(value: str) -> str:
    """Normalize a secret value for stable fingerprinting."""
    if not value:
        return ""
    return " ".join(value.strip().split()).lower()


def fingerprint_secret(value: str) -> str:
    """Return a deterministic SHA-256 hex digest of the normalized value.

    Returns "" for an empty or whitespace-only value.
    """
    normalized = normalize(value)
    if not normalized:
        return ""
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def fingerprint_prefix(value: str, length: int = 12) -> str:
    """Short human-readable prefix of the fingerprint for UI grouping."""
    full = fingerprint_secret(value)
    return full[:length] if full else ""


__all__ = ["normalize", "fingerprint_secret", "fingerprint_prefix"]