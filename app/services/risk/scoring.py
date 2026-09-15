"""Numeric risk scoring.

Inputs come from RiskContext via risk_factors(). Output is a 0-100 float.

Formula (explainable, testable):

  base   = 100 * type_weight * file_weight
  base  += 100 * validation_delta        # can be negative
  base  += 100 * public_repo_bonus
  base  += 100 * reuse_bonus
  base  += 100 * production_bonus
  base  +=  10 * entropy_signal

  # Confidence multiplies the base so low-confidence findings cannot
  # reach critical. Range of the multiplier is 0.30 .. 1.10.
  confidence_multiplier = 0.30 + 0.80 * confidence

  score  = base * confidence_multiplier * exposure_multiplier
  score  = clamp(0, 100, score)

Every factor is a named key so the UI can show "why this score".
"""
from __future__ import annotations

from app.services.risk.factors import RiskContext, risk_factors


def calculate_risk_score(ctx: RiskContext) -> tuple[float, dict[str, float]]:
    """Return (score, factors) where factors explains the calculation."""
    f = risk_factors(ctx)

    base = 100.0 * f["type_weight"] * f["file_weight"]
    base += 100.0 * f["validation_delta"]
    base += 100.0 * f["public_repo_bonus"]
    base += 100.0 * f["reuse_bonus"]
    base += 100.0 * f["production_bonus"]
    base += 10.0 * f["entropy_signal"]

    # Confidence scales everything. This ensures two identical findings
    # with different confidence do NOT collapse to the same clamped value.
    confidence_multiplier = 0.30 + 0.80 * f["confidence"]

    score = base * confidence_multiplier * f["exposure_multiplier"]
    score = max(0.0, min(100.0, score))

    # Expose the multiplier so the UI can explain it.
    f["confidence_multiplier"] = round(confidence_multiplier, 4)
    f["base_before_multipliers"] = round(base, 4)
    return round(score, 2), f