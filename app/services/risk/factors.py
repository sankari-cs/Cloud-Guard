"""Weighted risk factors.

Each factor contributes to a 0-100 risk score. Weights are intentionally
transparent and configurable so a security team can tune them.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# --- secret type weight: how damaging is this credential if real? ---
SECRET_TYPE_WEIGHTS: dict[str, float] = {
    "AWS Access Key": 1.00,
    "AWS Secret Access Key": 1.00,
    "Private Key": 1.00,
    "Stripe Secret Key": 1.00,
    "GitHub Token": 0.95,
    "Slack Token": 0.85,
    "Database Connection String": 0.90,
    "JWT": 0.70,
    "Bearer Token": 0.65,
    "Google API Key": 0.80,
    "API Key": 0.70,
    "Token": 0.60,
    "Secret": 0.65,
    "Password": 0.65,
}
DEFAULT_TYPE_WEIGHT = 0.55

# --- file sensitivity: where the secret is exposed matters ---
FILE_SENSITIVITY_WEIGHTS: dict[str, float] = {
    ".env": 1.00,
    ".env.local": 1.00,
    ".env.production": 1.00,
    "docker-compose.yml": 0.90,
    "docker-compose.yaml": 0.90,
    "Dockerfile": 0.85,
    "settings.py": 0.85,
    "config.py": 0.85,
    "application.yml": 0.85,
    "application.yaml": 0.85,
    "application.properties": 0.85,
    "credentials": 1.00,
    ".npmrc": 0.90,
    ".pypirc": 0.90,
    ".netrc": 0.95,
}
DEFAULT_FILE_WEIGHT = 0.50

# --- exposure location multiplier applied to the base score ---
EXPOSURE_MULTIPLIER = {
    "config": 1.15,
    "source": 1.00,
    "test": 0.60,
    "documentation": 0.50,
    "unknown": 1.00,
}


@dataclass
class RiskContext:
    """All inputs needed to score a single finding."""
    secret_type: str
    confidence: float
    entropy: float
    validation_status: str
    validation_delta: float
    file_path: str
    line_number: int | None = None
    is_config_file: bool = False
    is_production_path: bool = False
    is_test_path: bool = False
    is_documentation: bool = False
    is_public_repo: bool = False
    is_reused: bool = False
    extras: dict[str, float] = field(default_factory=dict)


def _filename_key(file_path: str) -> str:
    if not file_path:
        return ""
    normalized = file_path.replace("\\", "/")
    return normalized.rsplit("/", 1)[-1].lower()


def _type_weight(secret_type: str) -> float:
    return SECRET_TYPE_WEIGHTS.get(secret_type, DEFAULT_TYPE_WEIGHT)


def _file_weight(file_path: str) -> float:
    return FILE_SENSITIVITY_WEIGHTS.get(_filename_key(file_path), DEFAULT_FILE_WEIGHT)


def _exposure_multiplier(ctx: RiskContext) -> tuple[str, float]:
    if ctx.is_documentation:
        return "documentation", EXPOSURE_MULTIPLIER["documentation"]
    if ctx.is_test_path:
        return "test", EXPOSURE_MULTIPLIER["test"]
    if ctx.is_config_file:
        return "config", EXPOSURE_MULTIPLIER["config"]
    return "source", EXPOSURE_MULTIPLIER["source"]


def risk_factors(ctx: RiskContext) -> dict[str, float]:
    """Return the named numeric factors used by scoring.calculate_risk_score."""
    exposure_name, exposure_mult = _exposure_multiplier(ctx)

    factors = {
        "type_weight": _type_weight(ctx.secret_type),
        "file_weight": _file_weight(ctx.file_path),
        "exposure_multiplier": exposure_mult,
        "confidence": max(0.0, min(1.0, ctx.confidence)),
        "entropy_signal": min(1.0, ctx.entropy / 5.0) if ctx.entropy else 0.0,
        "validation_delta": ctx.validation_delta,
        "public_repo_bonus": 0.10 if ctx.is_public_repo else 0.0,
        "reuse_bonus": 0.05 if ctx.is_reused else 0.0,
        "production_bonus": 0.05 if ctx.is_production_path else 0.0,
    }
    factors["exposure_name_code"] = float({"documentation": 0, "test": 1, "source": 2, "config": 3}[exposure_name])
    return factors