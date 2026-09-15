"""CSV report renderer. Consumes the canonical report dict."""
from __future__ import annotations

import csv
import io

COLUMNS = [
    "id",
    "severity",
    "risk_score",
    "secret_type",
    "file_path",
    "line_number",
    "column_number",
    "redacted_value",
    "fingerprint",
    "confidence",
    "validation_status",
    "triage_status",
    "detection_reason",
]


def render_csv(report_data: dict) -> str:
    """Return a CSV string of the findings, using CRLF for Excel friendliness."""
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=COLUMNS,
        extrasaction="ignore",
        lineterminator="\r\n",
    )
    writer.writeheader()
    for row in report_data.get("findings", []):
        safe_row = {}
        for col in COLUMNS:
            value = row.get(col)
            if value is None:
                value = ""
            elif isinstance(value, str):
                # Neutralize spreadsheet formula injection.
                if value and value[0] in ("=", "+", "-", "@"):
                    value = "'" + value
            safe_row[col] = value
        writer.writerow(safe_row)
    return buffer.getvalue()


__all__ = ["render_csv", "COLUMNS"]
