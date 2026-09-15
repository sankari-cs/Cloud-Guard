"""Tests for remediation guidance."""
from app.services.remediation import (
    remediation_for,
    remediation_text,
)
from app.services.remediation_guides.guides import (
    DEFAULT_GUIDE,
    GUIDE_BY_TYPE,
    guide_for,
)


def test_every_guide_has_immediate_steps():
    for secret_type, guide in GUIDE_BY_TYPE.items():
        assert guide.immediate, f"{secret_type} missing immediate steps"


def test_every_guide_has_prevention():
    for secret_type, guide in GUIDE_BY_TYPE.items():
        assert guide.prevention, f"{secret_type} missing prevention"


def test_every_guide_has_controls():
    for secret_type, guide in GUIDE_BY_TYPE.items():
        assert guide.controls, f"{secret_type} missing controls"


def test_aws_guide_mentions_rotate_and_cloudtrail():
    guide = guide_for("AWS Access Key")
    joined = " ".join(guide.immediate).lower()
    assert "revoke" in joined or "rotate" in joined
    assert "cloudtrail" in joined


def test_github_guide_mentions_revoke():
    guide = guide_for("GitHub Token")
    joined = " ".join(guide.immediate).lower()
    assert "revoke" in joined


def test_private_key_guide_exists():
    guide = guide_for("Private Key")
    assert guide.secret_type == "Private Key"


def test_password_guide_mentions_rotate():
    guide = guide_for("Password")
    joined = " ".join(guide.immediate).lower()
    assert "rotate" in joined


def test_unknown_type_returns_default():
    guide = guide_for("Totally New Thing")
    assert guide is DEFAULT_GUIDE


def test_remediation_for_returns_text():
    advice = remediation_for("AWS Access Key")
    assert advice.secret_type == "AWS Access Key"
    assert "Immediate actions:" in advice.text
    assert "Long-term prevention:" in advice.text
    assert "Recommended controls:" in advice.text


def test_remediation_text_is_string():
    text = remediation_text("GitHub Token")
    assert isinstance(text, str)
    assert "GitHub Token" in text


def test_remediation_references_present_for_aws():
    advice = remediation_for("AWS Access Key")
    assert "OWASP" in advice.references
    assert "CWE" in advice.references
    assert "MITRE" in advice.references


def test_remediation_references_are_tuples():
    advice = remediation_for("Password")
    for framework, items in advice.references.items():
        assert isinstance(items, tuple)
        assert all(isinstance(i, str) for i in items)


def test_default_guide_handles_unknown_type():
    advice = remediation_for("Made Up Type")
    assert advice.secret_type == "Unknown"