"""Detection engine: run regex rules, apply context, dedupe, score."""
from __future__ import annotations
from dataclasses import dataclass
from app.services.detection.context import ContextInfo, classify
from app.services.detection.entropy import is_high_entropy, shannon_entropy
from app.services.detection.rules import ALL_RULES, SecretRule
from app.services.file_scanner import ScannedFile
@dataclass
class Detection:
    rule_name: str
    secret_type: str
    matched_value: str
    line_number: int
    column_number: int
    start_pos: int
    end_pos: int
    confidence: float
    entropy: float
    detection_reason: str
    context: ContextInfo
def _line_col(text: str, pos: int) -> tuple[int, int]:
    line_number = text.count("\n", 0, pos) + 1
    last_newline = text.rfind("\n", 0, pos)
    column = pos - last_newline if last_newline >= 0 else pos + 1
    return line_number, column
def _line_at(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    if end == -1:
        end = len(text)
    return text[start:end]
def _score(rule: SecretRule, value: str, ctx: ContextInfo) -> tuple[float, str]:
    confidence = rule.base_confidence
    reasons: list[str] = [f"matched rule '{rule.name}'"]
    ent = shannon_entropy(value)
    if is_high_entropy(value):
        confidence += 0.10
        reasons.append(f"high entropy ({ent:.2f})")
    elif len(value) < 8:
        confidence -= 0.15
        reasons.append("very short value")
    is_specific_format = rule.base_confidence >= 0.85
    if ctx.is_env_reference:
        confidence -= 0.45
        reasons.append("reads from environment")
    if ctx.is_placeholder and not is_specific_format:
        confidence -= 0.40
        reasons.append("placeholder-like value")
    if ctx.is_test_value and not is_specific_format:
        confidence -= 0.20
        reasons.append("test/example value")
    confidence = max(0.0, min(1.0, confidence))
    return confidence, "; ".join(reasons)
def _overlaps(a: Detection, b: Detection) -> bool:
    return not (a.end_pos <= b.start_pos or b.end_pos <= a.start_pos)
def _dedupe(detections: list[Detection]) -> list[Detection]:
    ordered = sorted(detections, key=lambda d: (-d.confidence, d.start_pos))
    kept: list[Detection] = []
    for det in ordered:
        if any(_overlaps(det, k) for k in kept):
            continue
        kept.append(det)
    kept.sort(key=lambda d: (d.line_number, d.column_number))
    return kept
def _scan_rule(rule: SecretRule, text: str, filename: str) -> list[Detection]:
    results: list[Detection] = []
    for match in rule.pattern.finditer(text):
        try:
            value = match.group(rule.value_group)
        except IndexError:
            continue
        if value is None:
            continue
        value = value.strip()
        if not value:
            continue
        start = match.start(rule.value_group) if rule.value_group else match.start()
        end = match.end(rule.value_group) if rule.value_group else match.end()
        line_number, column = _line_col(text, start)
        line_text = _line_at(text, start)
        ctx = classify(value, filename, line_text)
        confidence, reason = _score(rule, value, ctx)
        results.append(
            Detection(
                rule_name=rule.name,
                secret_type=rule.secret_type,
                matched_value=value,
                line_number=line_number,
                column_number=column,
                start_pos=start,
                end_pos=end,
                confidence=round(confidence, 3),
                entropy=round(shannon_entropy(value), 3),
                detection_reason=reason,
                context=ctx,
            )
        )
    return results
def detect_in_text(text: str, filename: str = "<memory>") -> list[Detection]:
    """Detect secrets in a text blob. Returns deduped detections."""
    if not text:
        return []
    detections: list[Detection] = []
    for rule in ALL_RULES:
        detections.extend(_scan_rule(rule, text, filename))
    detections = _dedupe(detections)
    return [d for d in detections if d.confidence >= 0.20]
def detect_in_file(scanned: ScannedFile) -> list[Detection]:
    """Detect secrets in a ScannedFile."""
    return detect_in_text(scanned.content, filename=scanned.relative_path)
__all__ = ["Detection", "detect_in_text", "detect_in_file"]