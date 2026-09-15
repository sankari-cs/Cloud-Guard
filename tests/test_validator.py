"""Tests for the validator layer."""
from app.services.detector import detect_in_text
from app.services.validator import ValidationResult, validate_detection
from app.services.validators.aws import AWSValidator
from app.services.validators.generic import GenericValidator
from app.services.validators.github import GitHubValidator
from app.services.validators.registry import VALIDATORS
# ---------- AWS format ----------
def test_aws_access_key_format_valid():
    v = AWSValidator()
    result = v.validate("AWS Access Key", "AKIA" + "A" * 16)
    assert isinstance(result, ValidationResult)
    assert result.status == "format_valid"
def test_aws_access_key_lowercase_invalid():
    v = AWSValidator()
    result = v.validate("AWS Access Key", "akia" + "a" * 16)
    assert result.status == "format_invalid"
def test_aws_access_key_wrong_length_invalid():
    v = AWSValidator()
    result = v.validate("AWS Access Key", "AKIA123")
    assert result.status == "format_invalid"
def test_aws_documented_sample_flagged():
    v = AWSValidator()
    result = v.validate("AWS Access Key", "AKIAIOSFODNN7EXAMPLE")
    assert result.status == "format_invalid"
    assert result.confidence_delta < 0
def test_aws_secret_access_key_format_valid():
    v = AWSValidator()
    result = v.validate("AWS Secret Access Key", "a" * 40)
    assert result.status == "format_valid"
def test_aws_secret_access_key_wrong_length_invalid():
    v = AWSValidator()
    result = v.validate("AWS Secret Access Key", "short")
    assert result.status == "format_invalid"
def test_aws_validator_ignores_unrelated_type():
    v = AWSValidator()
    result = v.validate("GitHub Token", "ghp_" + "a" * 36)
    assert result.status == "unknown"
# ---------- GitHub format ----------
def test_github_classic_pat_format_valid():
    v = GitHubValidator()
    result = v.validate("GitHub Token", "ghp_" + "a" * 36)
    assert result.status == "format_valid"
def test_github_fine_grained_pat_format_valid():
    v = GitHubValidator()
    result = v.validate("GitHub Token", "github_pat_" + "A" * 82)
    assert result.status == "format_valid"
def test_github_oauth_format_valid():
    v = GitHubValidator()
    result = v.validate("GitHub Token", "gho_" + "a" * 36)
    assert result.status == "format_valid"
def test_github_wrong_prefix_invalid():
    v = GitHubValidator()
    result = v.validate("GitHub Token", "not_a_github_token")
    assert result.status == "format_invalid"
def test_github_wrong_length_invalid():
    v = GitHubValidator()
    result = v.validate("GitHub Token", "ghp_short")
    assert result.status == "format_invalid"
# ---------- generic ----------
def test_generic_password_too_short_invalid():
    v = GenericValidator()
    result = v.validate("Password", "abc")
    assert result.status == "format_invalid"
def test_generic_password_reasonable_valid():
    v = GenericValidator()
    result = v.validate("Password", "s3cr3t-password")
    assert result.status == "format_valid"
def test_generic_empty_invalid():
    v = GenericValidator()
    result = v.validate("Password", "   ")
    assert result.status == "format_invalid"
# ---------- registry + integration ----------
def test_registry_has_three_validators():
    assert len(VALIDATORS) == 3
def test_validate_detection_aws():
    dets = detect_in_text('AWS_ACCESS_KEY_ID = "AKIA' + "A" * 16 + '"')
    aws = next(d for d in dets if d.secret_type == "AWS Access Key")
    result = validate_detection(aws)
    assert result.status == "format_valid"
def test_validate_detection_github():
    dets = detect_in_text("token = ghp_" + "a" * 36)
    gh = next(d for d in dets if d.secret_type == "GitHub Token")
    result = validate_detection(gh)
    assert result.status == "format_valid"
def test_validate_detection_unknown_type():
    dets = detect_in_text('password = "S3cr3tP@ssw0rd!12345"')
    pwd = next(d for d in dets if d.secret_type == "Password")
    result = validate_detection(pwd)
    assert result.status in {"format_valid", "format_invalid", "unknown"}
def test_validate_returns_dataclass():
    dets = detect_in_text('password = "S3cr3tP@ssw0rd!12345"')
    pwd = dets[0]
    result = validate_detection(pwd)
    assert isinstance(result, ValidationResult)
    assert result.status in {
        "unknown", "format_valid", "format_invalid",
        "likely_valid", "likely_invalid",
    }
