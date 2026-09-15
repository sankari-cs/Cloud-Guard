"""Risk scoring subpackage: factors, scoring, severity."""
from app.services.risk.factors import (
    FILE_SENSITIVITY_WEIGHTS,
    SECRET_TYPE_WEIGHTS,
    RiskContext,
    risk_factors,
)
def calculate_risk_score(*args, **kwargs):
    """Calculate a risk score using the scoring implementation on demand."""
    from importlib import import_module

    scoring = import_module(f"{__name__}.scoring")
    return scoring.calculate_risk_score(*args, **kwargs)
from app.services.risk.severity import SEVERITY_THRESHOLDS, severity_for_score

__all__ = [
    "RiskContext",
    "risk_factors",
    "SECRET_TYPE_WEIGHTS",
    "FILE_SENSITIVITY_WEIGHTS",
    "calculate_risk_score",
    "SEVERITY_THRESHOLDS",
    "severity_for_score",
]