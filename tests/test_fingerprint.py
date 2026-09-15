"""Tests for secret fingerprinting."""
from app.services.fingerprint import (
    fingerprint_prefix,
    fingerprint_secret,
    normalize,
)


def test_normalize_strips_and_lowercases():
    assert normalize("  ABC  ") == "abc"


def test_normalize_collapses_internal_whitespace():
    assert normalize("a   b\t c") == "a b c"


def test_normalize_empty_returns_empty():
    assert normalize("") == ""
    assert normalize("   ") == ""


def test_fingerprint_is_64_hex_chars():
    fp = fingerprint_secret("AKIAIOSFODNN7EXAMPLE")
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


def test_fingerprint_is_deterministic():
    a = fingerprint_secret("AKIAIOSFODNN7EXAMPLE")
    b = fingerprint_secret("AKIAIOSFODNN7EXAMPLE")
    assert a == b


def test_fingerprint_stable_across_cosmetic_changes():
    assert fingerprint_secret("  ABC123  ") == fingerprint_secret("abc123")
    assert fingerprint_secret("a b") == fingerprint_secret("A\tB")


def test_fingerprint_differs_for_different_values():
    assert fingerprint_secret("secret-one") != fingerprint_secret("secret-two")


def test_fingerprint_empty_returns_empty():
    assert fingerprint_secret("") == ""
    assert fingerprint_secret("   ") == ""


def test_fingerprint_does_not_contain_plaintext():
    secret = "supersecretvalue1234567890"
    fp = fingerprint_secret(secret)
    assert secret not in fp
    assert secret.lower() not in fp


def test_fingerprint_prefix_length():
    fp = fingerprint_secret("hello world")
    assert fingerprint_prefix("hello world", length=8) == fp[:8]


def test_fingerprint_prefix_empty():
    assert fingerprint_prefix("") == ""