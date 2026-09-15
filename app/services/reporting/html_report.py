"""HTML report renderer.

Self-contained: no external CSS or JS. Uses Jinja2 with autoescape so
redacted values cannot break out of markup.
"""
from __future__ import annotations

from jinja2 import Environment, select_autoescape

_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CloudGuard Report — {{ scan.name }}</title>
<style>
  :root {
    --bg:#ffffff; --panel:#f7f9fc; --border:#e2e8f0;
    --text:#0f172a; --muted:#64748b;
    --crit:#dc2626; --high:#ea580c; --med:#d97706;
    --low:#0891b2; --info:#64748b;
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, "Segoe UI", Roboto, Inter, sans-serif;
    background: var(--bg); color: var(--text);
    margin: 0; padding: 32px;
    font-size: 14px; line-height: 1.5;
  }
  h1 { font-size: 22px; margin: 0 0 4px; }
  h2 { font-size: 16px; margin: 32px 0 12px; }
  .muted { color: var(--muted); }
  .meta { margin-bottom: 24px; }
  .meta div { margin: 2px 0; }
  .cards {
    display: grid; grid-template-columns: repeat(5, 1fr);
    gap: 12px; margin: 16px 0 24px;
  }
  .card {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px;
  }
  .card .label {
    font-size: 11px; letter-spacing: 0.08em;
    text-transform: uppercase; color: var(--muted);
  }
  .card .value { font-size: 22px; font-weight: 600; margin-top: 4px; }
  table {
    width: 100%; border-collapse: collapse; margin-top: 8px;
    font-size: 13px;
  }
  th, td {
    text-align: left; padding: 8px 10px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }
  th {
    font-size: 11px; text-transform: uppercase;
    letter-spacing: 0.06em; color: var(--muted);
    border-bottom: 2px solid var(--border);
  }
  tr:hover td { background: var(--panel); }
  code {
    font-family: "JetBrains Mono", "Consolas", monospace;
    font-size: 12px;
  }
  .sev {
    display: inline-block; padding: 2px 8px; border-radius: 999px;
    font-size: 11px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.04em; color: #fff;
  }
  .sev-critical { background: var(--crit); }
  .sev-high { background: var(--high); }
  .sev-medium { background: var(--med); }
  .sev-low { background: var(--low); }
  .sev-informational { background: var(--info); }
  .foot { margin-top: 40px; color: var(--muted); font-size: 12px; }
</style>
</head>
<body>

<h1>CloudGuard Security Report</h1>
<div class="muted">Scan: {{ scan.name }} · ID {{ scan.id }}</div>

<div class="meta">
  <div><strong>Status:</strong> {{ scan.status }}</div>
  <div><strong>Source:</strong> {{ scan.source_type }}{% if scan.source_path %} — <code>{{ scan.source_path }}</code>{% endif %}</div>
  <div><strong>Started:</strong> {{ scan.started_at }}</div>
  <div><strong>Completed:</strong> {{ scan.completed_at }}</div>
  <div><strong>Files scanned:</strong> {{ scan.files_scanned }}</div>
  <div><strong>Report generated:</strong> {{ report.generated_at }}</div>
</div>

<h2>Executive Summary</h2>
<div class="cards">
  <div class="card"><div class="label">Total Findings</div><div class="value">{{ summary.total }}</div></div>
  <div class="card"><div class="label">Critical</div><div class="value">{{ summary.by_severity.get('critical', 0) }}</div></div>
  <div class="card"><div class="label">High</div><div class="value">{{ summary.by_severity.get('high', 0) }}</div></div>
  <div class="card"><div class="label">Average Risk</div><div class="value">{{ summary.average_risk }}</div></div>
  <div class="card"><div class="label">Max Risk</div><div class="value">{{ summary.max_risk }}</div></div>
</div>

<h2>Findings by Severity</h2>
<table>
  <tr><th>Severity</th><th>Count</th></tr>
  {% for sev in ['critical','high','medium','low','informational'] %}
  <tr><td><span class="sev sev-{{ sev }}">{{ sev }}</span></td><td>{{ summary.by_severity.get(sev, 0) }}</td></tr>
  {% endfor %}
</table>

<h2>Findings by Type</h2>
<table>
  <tr><th>Secret Type</th><th>Count</th></tr>
  {% for name, count in summary.by_type.items()|sort(attribute='1', reverse=True) %}
  <tr><td>{{ name }}</td><td>{{ count }}</td></tr>
  {% endfor %}
</table>

<h2>Findings ({{ findings|length }})</h2>
<table>
  <tr>
    <th>Severity</th><th>Type</th><th>File</th><th>Line</th>
    <th>Redacted Value</th><th>Risk</th><th>Validation</th>
  </tr>
  {% for f in findings %}
  <tr>
    <td><span class="sev sev-{{ f.severity|lower }}">{{ f.severity }}</span></td>
    <td>{{ f.secret_type }}</td>
    <td><code>{{ f.file_path }}</code></td>
    <td>{{ f.line_number }}</td>
    <td><code>{{ f.redacted_value }}</code></td>
    <td>{{ f.risk_score }}</td>
    <td>{{ f.validation_status }}</td>
  </tr>
  {% endfor %}
</table>

<div class="foot">
  CloudGuard report · All secrets are redacted · Version {{ report.version }}
</div>

</body>
</html>
"""


def _env() -> Environment:
    return Environment(autoescape=select_autoescape(["html", "xml"]))


def render_html(report_data: dict) -> str:
    """Render the canonical report dict to a full HTML document."""
    template = _env().from_string(_TEMPLATE)
    return template.render(
        report=report_data["report"],
        scan=report_data["scan"],
        summary=report_data["summary"],
        findings=report_data["findings"],
    )


__all__ = ["render_html"]