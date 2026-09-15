"""Tests for the risk engine."""
from app.services.detector import detect_in_text
from app.services.risk.factors import RiskContext
from app.services.risk.scoring import calculate_risk_score
from app.services.risk.severity import (
    SEVERITY_THRESHOLDS,
    severity_for_score,
    severity_rank,
)
from app.services.risk_engine import score_detection
from app.services.validators.base import ValidationResult


# ---------- severity thresholds ----------

def test_severity_thresholds_exist():
    assert len(SEVERITY_THRESHOLDS) == 5


def test_severity_0_is_informational():
    assert severity_for_score(0) == "informational"


def test_severity_24_is_informational():
    assert severity_for_score(24) == "informational"


def test_severity_25_is_low():
    assert severity_for_score(25) == "low"


def test_severity_49_is_low():
    assert severity_for_score(49) == "low"


def test_severity_50_is_medium():
    assert severity_for_score(50) == "medium"


def test_severity_69_is_medium():
    assert severity_for_score(69) == "medium"


def test_severity_70_is_high():
    assert severity_for_score(70) == "high"


def test_severity_84_is_high():
    assert severity_for_score(84) == "high"


def test_severity_85_is_critical():
    assert severity_for_score(85) == "critical"


def test_severity_100_is_critical():
    assert severity_for_score(100) == "critical"


def test_severity_clamps_below_zero():
    assert severity_for_score(-10) == "informational"


def test_severity_clamps_above_hundred():
    assert severity_for_score(500) == "critical"


def test_severity_rank_ordering():
    assert severity_rank("critical") > severity_rank("high")
    assert severity_rank("high") > severity_rank("medium")
    assert severity_rank("medium") > severity_rank("low")
    assert severity_rank("low") > severity_rank("informational")


# ---------- score boundaries ----------

def _ctx(**kwargs):
    base = dict(
        secret_type="AWS Access Key",
        confidence=0.95,
        entropy=3.7,
        validation_status="format_valid",
        validation_delta=0.0,
        file_path=".env",
    )
    base.update(kwargs)
    return RiskContext(**base)


def test_score_is_between_zero_and_hundred():
    score, _ = calculate_risk_score(_ctx())
    assert 0.0 <= score <= 100.0


def test_aws_in_env_is_high_or_critical():
    score, _ = calculate_risk_score(_ctx())
    assert score >= 70


def test_documented_sample_lower_score():
    score, _ = calculate_risk_score(_ctx(validation_delta=-0.30))
    # Even valid AWS key gets penalized with negative validation delta
    assert score < 90


def test_test_file_reduces_score():
    prod_score, _ = calculate_risk_score(_ctx(is_test_path=False))
    test_score, _ = calculate_risk_score(_ctx(is_test_path=True))
    assert test_score < prod_score


def test_documentation_reduces_score():
    doc_score, _ = calculate_risk_score(_ctx(is_documentation=True))
    prod_score, _ = calculate_risk_score(_ctx())
    assert doc_score < prod_score


def test_config_file_raises_score():
    env_score, _ = calculate_risk_score(_ctx(file_path=".env"))
    src_score, _ = calculate_risk_score(_ctx(file_path="src/app.py"))
    assert env_score > src_score


def test_public_repo_increases_score():
    private_score, _ = calculate_risk_score(_ctx(is_public_repo=False))
    public_score, _ = calculate_risk_score(_ctx(is_public_repo=True))
    assert public_score >= private_score


def test_reused_secret_increases_score():
    once_score, _ = calculate_risk_score(_ctx(is_reused=False))
    reused_score, _ = calculate_risk_score(_ctx(is_reused=True))
    assert reused_score >= once_score


def test_production_path_increases_score():
    dev_score, _ = calculate_risk_score(_ctx(is_production_path=False))
    prod_score, _ = calculate_risk_score(_ctx(is_production_path=True))
    assert prod_score >= dev_score


def test_low_confidence_reduces_score():
    high, _ = calculate_risk_score(_ctx(confidence=0.95))
    low, _ = calculate_risk_score(_ctx(confidence=0.30))
    assert low < high


def test_unknown_type_gets_default_weight():
    score, factors = calculate_risk_score(_ctx(secret_type="Brand New Thing"))
    assert score > 0
    assert factors["type_weight"] > 0


# ---------- end-to-end scoring ----------

def test_score_detection_returns_risk_result():
    dets = detect_in_text('AWS_ACCESS_KEY_ID = "AKIA' + "A" * 16 + '"')
    aws = next(d for d in dets if d.secret_type == "AWS Access Key")
    validation = ValidationResult(
        status="format_valid",
        reason="ok",
        confidence_delta=0.0,
    )
    result = score_detection(aws, validation, file_path=".env")
    assert 0.0 <= result.score <= 100.0
    assert result.severity in {"informational", "low", "medium", "high", "critical"}


def test_score_detection_env_outranks_test():
    dets = detect_in_text('AWS_ACCESS_KEY_ID = "AKIA' + "A" * 16 + '"')
    aws = next(d for d in dets if d.secret_type == "AWS Access Key")
    validation = ValidationResult(
        status="format_valid",
        reason="ok",
        confidence_delta=0.0,
    )
    env = score_detection(aws, validation, file_path=".env")
    test = score_detection(aws, validation, file_path="tests/test_auth.py")
    assert env.score > test.score


def test_score_detection_negative_delta_drops_severity():
    dets = detect_in_text('AWS_ACCESS_KEY_ID = "AKIA' + "A" * 16 + '"')
    aws = next(d for d in dets if d.secret_type == "AWS Access Key")
    good = ValidationResult(status="format_valid", reason="ok", confidence_delta=0.0)
    bad = ValidationResult(status="format_invalid", reason="sample", confidence_delta=-0.30)
    good_result = score_detection(aws, good, file_path=".env")
    bad_result = score_detection(aws, bad, file_path=".env")
    assert bad_result.score < good_result.score