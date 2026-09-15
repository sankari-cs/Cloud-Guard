from app.services.remediation import remediation_text
from app.services.summary import summarize
from dataclasses import dataclass
print(remediation_text("AWS Access Key")[:300])
print("---")
@dataclass
class F:
    secret_type: str
    severity: str
    risk_score: float
    fingerprint: str
    file_path: str
findings = [
    F("AWS Access Key", "critical", 95.0, "fp1", ".env"),
    F("AWS Access Key", "critical", 92.0, "fp1", "config/prod.env"),
    F("GitHub Token", "high", 78.0, "fp2", "src/ci.py"),
]
s = summarize(findings)
print(s)
