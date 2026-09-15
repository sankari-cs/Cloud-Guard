"""PDF report renderer using reportlab.

Returns the PDF as bytes so the caller can save it or stream it.
"""
from __future__ import annotations

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#d97706"),
    "low": colors.HexColor("#0891b2"),
    "informational": colors.HexColor("#64748b"),
}


def _styles():
    base = getSampleStyleSheet()
    base.add(ParagraphStyle(
        name="CGTitle", parent=base["Title"], fontSize=18, spaceAfter=6,
    ))
    base.add(ParagraphStyle(
        name="CGSub", parent=base["Normal"], textColor=colors.HexColor("#64748b"),
        fontSize=9, spaceAfter=12,
    ))
    base.add(ParagraphStyle(
        name="CGHeading", parent=base["Heading2"], fontSize=12, spaceBefore=14,
        spaceAfter=6,
    ))
    base.add(ParagraphStyle(
        name="CGMono", parent=base["Code"], fontSize=8, leading=10,
    ))
    return base


def _kv_table(pairs: list[tuple[str, str]]) -> Table:
    rows = [[k, v] for k, v in pairs]
    t = Table(rows, colWidths=[1.6 * inch, 4.4 * inch])
    t.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, -1), "Helvetica", 9),
        ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#0f172a")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _findings_table(findings: list[dict], styles) -> Table:
    header = ["Severity", "Type", "File", "Line", "Redacted Value", "Risk"]
    rows = [header]
    for f in findings[:500]:  # cap to keep the PDF small
        rows.append([
            Paragraph(str(f["severity"]).upper(), styles["Normal"]),
            Paragraph(str(f["secret_type"]), styles["Normal"]),
            Paragraph(str(f["file_path"]), styles["CGMono"]),
            Paragraph(str(f["line_number"] or ""), styles["Normal"]),
            Paragraph(str(f["redacted_value"]), styles["CGMono"]),
            Paragraph(str(f["risk_score"]), styles["Normal"]),
        ])
    t = Table(
        rows,
        colWidths=[0.8 * inch, 1.3 * inch, 1.9 * inch, 0.4 * inch, 1.5 * inch, 0.5 * inch],
        repeatRows=1,
    )
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8),
        ("FONT", (0, 1), (-1, -1), "Helvetica", 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f9fc")]),
    ]
    for idx, f in enumerate(findings[:500], start=1):
        col = SEVERITY_COLORS.get(str(f["severity"]).lower())
        if col is not None:
            style.append(("TEXTCOLOR", (0, idx), (0, idx), col))
    t.setStyle(TableStyle(style))
    return t


def render_pdf(report_data: dict) -> bytes:
    """Render the canonical report dict to PDF bytes."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=LETTER,
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
        title=f"CloudGuard Report — {report_data['scan']['name']}",
    )
    styles = _styles()
    story = []

    story.append(Paragraph("CloudGuard Security Report", styles["CGTitle"]))
    story.append(Paragraph(
        f"Scan {report_data['scan']['id']} · {report_data['scan']['name']} · "
        f"generated {report_data['report']['generated_at']}",
        styles["CGSub"],
    ))

    story.append(Paragraph("Scan details", styles["CGHeading"]))
    scan = report_data["scan"]
    story.append(_kv_table([
        ("Status", str(scan["status"])),
        ("Source type", str(scan["source_type"])),
        ("Source path", str(scan["source_path"] or "")),
        ("Started", str(scan["started_at"] or "")),
        ("Completed", str(scan["completed_at"] or "")),
        ("Files scanned", str(scan["files_scanned"])),
    ]))

    story.append(Paragraph("Executive summary", styles["CGHeading"]))
    summary = report_data["summary"]
    sev = summary["by_severity"]
    story.append(_kv_table([
        ("Total findings", str(summary["total"])),
        ("Critical", str(sev.get("critical", 0))),
        ("High", str(sev.get("high", 0))),
        ("Medium", str(sev.get("medium", 0))),
        ("Low", str(sev.get("low", 0))),
        ("Informational", str(sev.get("informational", 0))),
        ("Average risk", str(summary["average_risk"])),
        ("Maximum risk", str(summary["max_risk"])),
    ]))

    story.append(Paragraph("Findings by type", styles["CGHeading"]))
    type_rows = [["Secret type", "Count"]]
    for name, count in sorted(summary["by_type"].items(), key=lambda kv: -kv[1]):
        type_rows.append([name, str(count)])
    t = Table(type_rows, colWidths=[4.0 * inch, 1.0 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8),
        ("FONT", (0, 1), (-1, -1), "Helvetica", 9),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
    ]))
    story.append(t)

    story.append(Paragraph("Findings", styles["CGHeading"]))
    if report_data["findings"]:
        story.append(_findings_table(report_data["findings"], styles))
    else:
        story.append(Paragraph("No findings.", styles["Normal"]))

    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "All secrets in this report are redacted. "
        "CloudGuard stores only redacted values and fingerprints.",
        styles["CGSub"],
    ))

    doc.build(story)
    return buffer.getvalue()


__all__ = ["render_pdf"]