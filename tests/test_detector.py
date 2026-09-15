"""Tests for the secret detection engine."""
from pathlib import Path

from app.services.detector import Detection, detect_in_file, detect_in_text
from app.services.file_scanner import ScannedFile


# ---------- specific formats ----------

def test_detects_aws_access_key():
    text = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
    dets = detect_in_text(text)
    types = {d.secret_type for d in dets}
    assert "AWS Access Key" in types
    aws = next(d for d in dets if d.secret_type == "AWS Access Key")
    assert aws.matched_value.startswith("AKIA")
    assert aws.confidence >= 0.9


def test_detects_aws_secret_access_key():
    text = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    dets = detect_in_text(text)
    assert any(d.secret_type == "AWS Secret Access Key" for d in dets)


def test_detects_github_classic_pat():
    text = "token = ghp_" + "a" * 36
    dets = detect_in_text(text)
    assert any(d.secret_type == "GitHub Token" for d in dets)


def test_detects_github_fine_grained_pat():
    text = "gh_token = github_pat_" + "A" * 82
    dets = detect_in_text(text)
    assert any(d.secret_type == "GitHub Token" for d in dets)


def test_detects_slack_token():
    text = "SLACK = 'xoxb-1234567890-abcdefghijkl'"
    dets = detect_in_text(text)
    assert any(d.secret_type == "Slack Token" for d in dets)


def test_detects_google_api_key():
    text = "apiKey: 'AIza" + "a" * 35 + "'"
    dets = detect_in_text(text)
    assert any(d.secret_type == "Google API Key" for d in dets)


def test_detects_stripe_live_secret():
    text = "stripe = 'sk_live_" + "a" * 32 + "'"
    dets = detect_in_text(text)
    assert any(d.secret_type == "Stripe Secret Key" for d in dets)


def test_detects_jwt():
    text = (
        "Authorization = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'"
    )
    dets = detect_in_text(text)
    assert any(d.secret_type == "JWT" for d in dets)


def test_detects_private_key_header():
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA...\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    dets = detect_in_text(text)
    assert any(d.secret_type == "Private Key" for d in dets)


def test_detects_bearer_token():
    text = "Authorization: Bearer abcDEF1234567890abcdefXYZ"
    dets = detect_in_text(text)
    assert any(d.secret_type == "Bearer Token" for d in dets)


def test_detects_db_connection_string():
    text = 'DATABASE_URL="postgresql://user:pass@host:5432/db"'
    dets = detect_in_text(text)
    assert any(d.secret_type == "Database Connection String" for d in dets)


# ---------- generic patterns ----------

def test_detects_generic_password_assignment():
    text = 'password = "S3cr3tP@ssw0rd!12345"'
    dets = detect_in_text(text)
    assert any(d.secret_type == "Password" for d in dets)


def test_detects_generic_api_key_assignment():
    text = 'API_KEY = "abcdef1234567890ABCDEF"'
    dets = detect_in_text(text)
    assert any(d.secret_type == "API Key" for d in dets)


# ---------- false-positive reduction ----------

def test_env_var_reference_low_confidence():
    text = 'password = os.getenv("DATABASE_PASSWORD")'
    dets = detect_in_text(text)
    pwd = [d for d in dets if d.secret_type == "Password"]
    for d in pwd:
        assert d.confidence < 0.3


def test_placeholder_not_high_confidence():
    text = 'api_key = "YOUR_API_KEY_HERE"'
    dets = detect_in_text(text)
    api = [d for d in dets if d.secret_type == "API Key"]
    for d in api:
        assert d.confidence < 0.5


def test_changeme_placeholder():
    text = 'password = "changeme"'
    dets = detect_in_text(text)
    pwd = [d for d in dets if d.secret_type == "Password"]
    for d in pwd:
        assert d.confidence < 0.4


def test_xxxxx_placeholder():
    text = 'token = "xxxxxxxxxxxxx"'
    dets = detect_in_text(text)
    tok = [d for d in dets if d.secret_type == "Token"]
    for d in tok:
        assert d.confidence < 0.4


def test_env_reference_not_flagged_as_aws():
    text = 'AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]'
    dets = detect_in_text(text)
    for d in dets:
        if d.secret_type == "AWS Secret Access Key":
            assert d.confidence < 0.6


# ---------- structure and dedupe ----------

def test_line_and_column_numbers():
    text = "line1\nline2\napi_key = \"abcdef1234567890ABCDEF\"\n"
    dets = detect_in_text(text)
    assert any(d.line_number == 3 for d in dets)


def test_dedupe_prefers_specific_rule():
    text = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
    dets = detect_in_text(text)
    aws = [d for d in dets if d.secret_type == "AWS Access Key"]
    assert len(aws) == 1


def test_empty_text_returns_no_detections():
    assert detect_in_text("") == []


def test_plain_text_returns_no_detections():
    text = "hello world\nthis is just prose\nnothing secret here"
    dets = detect_in_text(text)
    assert dets == []


def test_detect_in_file_uses_relative_path():
    scanned = ScannedFile(
        path=Path("/tmp/x.env"),
        relative_path="config/app.env",
        size=64,
        content='API_KEY = "abcdef1234567890ABCDEF"',
        language="env",
    )
    dets = detect_in_file(scanned)
    assert isinstance(dets, list)
    assert all(isinstance(d, Detection) for d in dets)


def test_test_filename_reduces_confidence():
    text = 'password = "S3cr3tP@ssw0rd!12345"'
    normal = detect_in_text(text, filename="prod/settings.py")
    testy = detect_in_text(text, filename="tests/test_settings.py")
    normal_conf = max((d.confidence for d in normal if d.secret_type == "Password"), default=0.0)
    test_conf = max((d.confidence for d in testy if d.secret_type == "Password"), default=0.0)
    assert test_conf <= normal_conf