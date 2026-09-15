from app.services.detector import detect_in_text
from app.services.risk_engine import score_detection
from app.services.validators.base import ValidationResult
dets = detect_in_text('AWS_ACCESS_KEY_ID = "AKIA' + "A" * 16 + '"')
aws = next(d for d in dets if d.secret_type == "AWS Access Key")
for label, delta, path in [
    ("prod .env", 0.0, ".env"),
    ("prod .env, sample validation", -0.30, ".env"),
    ("tests/", 0.0, "tests/test_auth.py"),
    ("docs/", 0.0, "docs/setup.md"),
]:
    v = ValidationResult(status="format_valid", reason="ok", confidence_delta=delta)
    r = score_detection(aws, v, file_path=path)
    print(f"{label:30} score={r.score:6.2f} severity={r.severity}")
