<div align="center">

# CloudGuard

### Cloud Secret Exposure Detection & Risk Analysis Platform

**Find leaked credentials before attackers do.**

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.x-D71F00)](https://www.sqlalchemy.org/)
[![Tests](https://img.shields.io/badge/tests-220%2B%20passing-brightgreen)](#testing)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](Dockerfile)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

</div>

---

## Overview

**CloudGuard** is a security platform that scans source code, configuration files, and archives for exposed secrets — API keys, cloud credentials, tokens, private keys, and database connection strings.

It is not a regex script. It combines **multi-strategy detection**, **context-aware false-positive reduction**, **provider-specific validation**, and an **explainable risk engine** to produce findings a security team can act on immediately.

> **Core principle:** No plaintext secret ever reaches the database. Every finding is redacted at write time and stored only as a partial mask plus a SHA-256 fingerprint.

### At a glance

| Metric | Value |
|---|---|
| Detection strategies | Regex + Shannon entropy + context analysis |
| Providers validated | AWS, GitHub, Slack, Stripe, Google, generic |
| Report formats | JSON, CSV, HTML, PDF |
| Test suite | 220+ pytest tests across 17 modules |
| Deployment | Local, Docker, docker compose |
| Storage | SQLite by default, any SQLAlchemy URI |

---

## The Problem

Credentials leaked into source control are one of the most common root causes of cloud breaches.

| Reality | Impact |
|---|---|
| A single AWS key in a public repo can lead to account takeover within minutes | Data loss, financial fraud |
| Long-lived credentials in source cannot be rotated quickly | Extended attacker dwell time |
| Manual review does not scale — one repo can hold thousands of files | Missed exposures |
| Existing tools are heavy SaaS or one-off regex scripts | Poor fit for self-hosted teams |

CloudGuard answers three questions fast:

1. **What** secrets are exposed?
2. **How bad** is each one?
3. **What do I do** about it, right now?

---

## Features

**Detection**
- Regex rules for AWS, GitHub, Slack, Stripe, Google, JWT, private keys, database URIs, bearer tokens
- Shannon entropy analysis for high-randomness strings
- Context-aware scoring — env-var references, placeholders, test markers are down-weighted
- Overlap deduplication — a specific AWS rule beats a generic `api_key=` match on the same span

**Validation**
- AWS access key / secret access key format checks
- GitHub classic PAT, fine-grained PAT, OAuth, App token shapes
- Generic length, character-class, empty-value checks
- Offline by default — no provider API calls, no third-party leak risk

**Risk Analysis**
- 0–100 explainable score with configurable severity bands
- Named, tunable factors — type weight, file sensitivity, exposure multiplier, confidence multiplier, validation delta
- Reuse detection across files
- Production-path bonus

**Storage & Reporting**
- SHA-256 fingerprinting for deduplication without storing plaintext
- Redaction across UI, snippets, reports, logs, and DB
- JSON, CSV, HTML, PDF reports
- Alerts with severity triggers and acknowledgement
- Triage — open, false positive, resolved, ignored

**Platform**
- Dark SOC-style web UI
- CLI for CI/CD integration (`flask scan`, `flask scan-zip`)
- Docker & docker compose with non-root user, health check, persistent volumes
- 220+ pytest tests across 17 modules

---

## Screenshots

> Save screenshots into `docs/screenshots/` with the filenames below.

| Page | Preview |
|---|---|
| Dashboard | ![Dashboard](docs/screenshots/dashboard.png) |
| Findings | ![Findings](docs/screenshots/findings.png) |
| Finding Detail | ![Finding detail](docs/screenshots/finding-detail.png) |
| Scan History | ![Scan history](docs/screenshots/scan-history.png) |
| Reports | ![Reports](docs/screenshots/reports.png) |
| Alerts | ![Alerts](docs/screenshots/alerts.png) |
| Settings | ![Settings](docs/screenshots/settings.png) |
| New Scan | ![New scan](docs/screenshots/new-scan.png) |

---

## Architecture

CloudGuard follows a layered pipeline. Each stage has one responsibility, pure inputs and outputs, and is unit-tested in isolation.

```mermaid
flowchart TD
    A[Scan Input<br/>ZIP or directory] --> B[Safe Archive Handler]
    B --> C[File Scanner]
    C --> D[Secret Detector]
    D --> E[Validator]
    E --> F[Risk Engine]
    F --> G[Remediation Engine]
    G --> H[Redactor + Fingerprint]
    H --> I[(Database)]
    I --> J[Web UI]
    I --> K[Reports<br/>JSON · CSV · HTML · PDF]
    I --> L[Alerts]

    style A fill:#1a2330,stroke:#3b82f6,color:#e6edf3
    style I fill:#1a2330,stroke:#3b82f6,color:#e6edf3
```

### Why these layers are separate

| Layer | Question | Optimized for |
|---|---|---|
| Detector | "Is this value suspicious?" | Recall — catch everything that might be a secret |
| Validator | "Is this shape a real credential?" | Precision — reject what cannot be real |
| Risk Engine | "How bad is it if real?" | Independent of detection; tunable without touching rules |
| Redactor | "How do we show this safely?" | Single source of truth for masking |
| Fingerprint | "Is this the same secret?" | Deduplication without storing plaintext |

Merging any two of these makes both worse. This is the core design decision of CloudGuard.

---

## Detection Pipeline

### 1. Input

Two entry points: local directory, or ZIP upload (max 50 MB).

### 2. Safe Archive Extraction

Every ZIP is validated **before** any file is written:

| Check | Blocks |
|---|---|
| Absolute paths (`/etc/passwd`) | Arbitrary write |
| Drive-letter paths (`C:/evil`) | Windows attack |
| `..` traversal | Zip Slip |
| Entry count cap | Resource exhaustion |
| Single-file size cap | Memory blow-up |
| Total uncompressed size cap | Disk exhaustion |
| Compression-ratio cap | Zip bombs |
| Per-write path verification | Defense in depth |

### 3. File Scanning

- Supported extensions: `.py`, `.js`, `.ts`, `.env`, `.yaml`, `.json`, `.xml`, `.ini`, `.conf`, `.properties`, `.sql`, `.tf`, and more
- Supported filenames: `Dockerfile`, `Makefile`, `Jenkinsfile`, `.env`, `.npmrc`, `.pypirc`, `.netrc`
- Skipped: binaries, symlinks, files over 5 MB, excluded directories (`.git`, `node_modules`, `.venv`, `__pycache__`, `dist`, `build`)

### 4. Multi-Strategy Detection

**Regex rules** — known credential formats:

| Provider | Pattern | Confidence |
|---|---|---|
| AWS Access Key | `AKIA[A-Z0-9]{16}` | 0.95 |
| GitHub PAT (classic) | `ghp_[A-Za-z0-9]{36}` | 0.98 |
| GitHub PAT (fine-grained) | `github_pat_[A-Za-z0-9_]{82}` | 0.98 |
| Slack Token | `xox[baprs]-[A-Za-z0-9-]{10,}` | 0.95 |
| Stripe Secret | `sk_live_[0-9a-zA-Z]{24,}` | 0.98 |
| Google API Key | `AIza[0-9A-Za-z_\-]{35}` | 0.95 |
| JWT | `eyJ...eyJ...` | 0.85 |
| Private Key | `-----BEGIN ... PRIVATE KEY-----` | 0.95 |

**Entropy analysis** — Shannon entropy above 3.5 bits/char for strings ≥ 16 chars.

**Generic assignments** — `password=`, `api_key=`, `token=`, `secret=` with quoted values.

### 5. Context-Aware Scoring

Penalties applied only to generic rules. Specific-format rules skip them because the format itself is proof of shape.

| Signal | Penalty | Example |
|---|---|---|
| Environment variable reference | −0.45 | `os.getenv("DB_PASSWORD")` |
| Placeholder value | −0.40 | `YOUR_API_KEY`, `changeme`, `xxxxx` |
| Test/example marker | −0.20 | value contains `example`, file in `tests/` |

### 6. Validation

```python
ValidationResult(
    status="format_valid" | "format_invalid" | "unknown",
    reason="...",
    confidence_delta=+0.0 | -0.20 | -0.30,
)
```

The `confidence_delta` flows into the risk engine and can drop a finding by a full severity band.

### 7. Redaction & Fingerprint

```
Original:   AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"

Stored:     redacted_value = "AKIA************MPLE"
            fingerprint    = "a3f9c1e8..." (SHA-256, 64 hex chars)
```

No plaintext is ever written to the database.

---

## Risk Scoring

Every finding receives a score from **0 to 100** using named, tunable factors.

### Formula

```
base  = 100 × type_weight × file_weight
      + 100 × validation_delta
      + 100 × public_repo_bonus
      + 100 × reuse_bonus
      + 100 × production_bonus
      +  10 × entropy_signal

confidence_multiplier = 0.30 + 0.80 × confidence
score = base × confidence_multiplier × exposure_multiplier
score = clamp(0, 100, score)
```

### Factor weights

**Secret type:**

| Type | Weight |
|---|---|
| AWS Access Key / Secret / Private Key / Stripe | 1.00 |
| GitHub Token | 0.95 |
| Database Connection String | 0.90 |
| Google API Key | 0.80 |
| JWT / API Key | 0.70 |
| Password / Token | 0.65 |

**File sensitivity:**

| File | Weight |
|---|---|
| `.env`, `.env.production`, `credentials` | 1.00 |
| `.netrc` | 0.95 |
| `docker-compose.yml`, `.npmrc`, `.pypirc` | 0.90 |
| `settings.py`, `config.py`, `application.yml` | 0.85 |
| Any other file | 0.50 |

**Exposure multiplier:**

| Location | Multiplier |
|---|---|
| Config file | × 1.15 |
| Source code | × 1.00 |
| Test file | × 0.60 |
| Documentation | × 0.50 |

### Severity bands

| Score | Severity |
|---|---|
| 0–24 | informational |
| 25–49 | low |
| 50–69 | medium |
| 70–84 | high |
| 85–100 | critical |

### Worked example

```
AWS Access Key in .env, format_valid, confidence 0.95, entropy 3.7

base  = 100 × 1.00 × 1.00  = 100
      +  0                     (validation_delta)
      +  0                     (no bonuses)
      +  7                     (entropy)
      = 107

confidence_multiplier = 0.30 + 0.80 × 0.95 = 1.06
exposure_multiplier   = 1.15              (config file)

score = 107 × 1.06 × 1.15 ≈ 130 → clamp → 100
severity = critical
```

---

## Security Controls

Full list in [`docs/SECURITY.md`](docs/SECURITY.md).

### Authentication & Authorization
- Passwords hashed with Werkzeug PBKDF2 (salted)
- Flask-Login session management
- CSRF protection on every state-changing form
- Rate limiting — 5 failed logins per IP per 5 minutes
- No user enumeration — same error for unknown user and wrong password
- Role-based access — `admin`, `analyst`, `viewer`
- Audit log for login success, failure, and logout

### Input Handling
- ZIP extension allowlist (`.zip` only)
- 50 MB upload cap
- `secure_filename` + random token prefix
- Zip Slip blocked at two layers
- Zip bombs blocked via compression-ratio and total-size caps
- No shell, no `eval`, no unsafe deserialization

### Storage & Output
- Only `redacted_value` and `fingerprint` persist
- Snippets redacted against every secret in the same file
- CSV formula injection neutralized (`=`, `+`, `-`, `@`)
- HTML autoescaped via Jinja2
- PDF capped at 500 findings per report

### Network & Headers
- No outbound calls by default
- `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`

### Errors & Logging
- Global handlers for `400`, `401`, `403`, `404`, `500`
- No stack traces returned to clients
- `RedactionFilter` masks known token shapes and key names in every log line

### Database
- SQLAlchemy parameterized queries only — no string concatenation

---

## Technology Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12+ |
| Web framework | Flask 3.x |
| ORM | SQLAlchemy 2.x + Flask-SQLAlchemy |
| Migrations | Flask-Migrate (Alembic) |
| Auth | Flask-Login, Werkzeug password hashing |
| Forms / CSRF | Flask-WTF |
| Templating | Jinja2 |
| Reporting | reportlab (PDF), Jinja2 (HTML), csv, json |
| Frontend | Server-rendered HTML + plain CSS (dark SOC theme) |
| Testing | pytest, pytest-cov |
| Server | Gunicorn |
| Container | Docker, docker compose |
| Database | SQLite (dev), any SQLAlchemy URI (prod) |

---

## Data Model

```mermaid
erDiagram
    USER ||--o{ SCAN : creates
    USER ||--o{ AUDIT_LOG : generates
    SCAN ||--o{ FINDING : contains
    FINDING ||--o{ ALERT : triggers
    USER ||--o{ ALERT : acknowledges
```

| Table | Purpose |
|---|---|
| `users` | Accounts, roles, hashed passwords, last login |
| `scans` | One row per scan; counters, risk score, status |
| `findings` | Redacted value, fingerprint, severity, triage |
| `alerts` | Severity-triggered alerts linked to findings |
| `settings` | Key-value runtime configuration |
| `audit_logs` | Security events with IP and user agent |

Key columns:

- `Finding.fingerprint` — SHA-256 hex (64 chars), used for deduplication
- `Finding.redacted_value` — partial mask, never plaintext
- `Finding.triage_status` — `open`, `false_positive`, `resolved`, `ignored`
- `Scan.error_message` — safe user-facing reason on failure

---

## Quickstart

### Prerequisites
- Python **3.12+**
- Windows, macOS, or Linux
- Git

### Install

```bash
git clone https://github.com/sankari-cs/Cloud-Guard.git
cd Cloud-Guard

python -m venv .venv
# Windows
.\.venv\Scripts\Activate.ps1
# macOS / Linux
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

### Configure

```bash
cp .env.example .env
```

Set `FLASK_SECRET_KEY` to a long random string:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### Initialize

```bash
export FLASK_APP=run.py       # Windows: $env:FLASK_APP = "run.py"
flask init-db
flask create-user --username admin --role admin
```

### Run

```bash
python run.py
```

Open **http://127.0.0.1:5000/** and sign in.

### First scan

```bash
flask scan --name my-project --path /path/to/project --user admin
```

Then visit **http://127.0.0.1:5000/scans/**.

---

## Configuration

Environment-driven. Copy `.env.example` to `.env`.

| Variable | Default | Purpose |
|---|---|---|
| `FLASK_SECRET_KEY` | *(required)* | Session signing key |
| `FLASK_ENV` | `development` | `development` or `production` |
| `DATABASE_URL` | `sqlite:///instance/cloudguard.db` | Any SQLAlchemy URI |
| `UPLOAD_FOLDER` | `uploads/` | Uploaded ZIPs |
| `REPORTS_FOLDER` | `reports/` | Generated reports |
| `MAX_UPLOAD_SIZE` | `52428800` (50 MB) | Upload cap |
| `SESSION_COOKIE_SECURE` | `false` | Set `true` under HTTPS |

Runtime settings (limits, thresholds, exclusions) live in the `Setting` table and are editable from the Settings page.

---

## CLI Reference

| Command | Purpose |
|---|---|
| `flask init-db` | Create all database tables |
| `flask create-user --username X --role admin` | Create a user |
| `flask list-users` | List users |
| `flask scan --name X --path ./dir --user admin` | Scan a directory |
| `flask scan-zip --name X --zip ./file.zip --user admin` | Scan a ZIP |
| `flask routes` | List routes |

### Scan output

```
status=completed files=412 findings=148 alerts=6
```

---

## Docker Deployment

```bash
cp .env.example .env
# Edit .env and set FLASK_SECRET_KEY

docker compose up --build
```

Open **http://127.0.0.1:8000/**.

Create the first user:

```bash
docker compose exec cloudguard flask create-user --username admin --role admin
```

Persistent volumes:

- `cloudguard_instance` — SQLite database
- `cloudguard_uploads` — uploaded ZIPs
- `cloudguard_reports` — generated reports

Stop / reset:

```bash
docker compose down        # stop
docker compose down -v     # stop and wipe data
```

Image properties:

- Base: `python:3.12-slim`
- Non-root user (`cloudguard`, uid 1001)
- `tini` for signal handling
- Health check on `/health`
- Gunicorn 2 workers, 4 threads

---

## Testing

```bash
python -m pytest -q
python -m pytest -v
python -m pytest --cov=app --cov-report=term-missing
```

Expected: **220+ tests passing.**

| Module | Tests |
|---|---|
| `test_app_factory.py` | 3 |
| `test_archive_handler.py` | 8 |
| `test_file_scanner.py` | 9 |
| `test_detector.py` | 24 |
| `test_validator.py` | 20 |
| `test_risk_engine.py` | 28 |
| `test_fingerprint.py` | 11 |
| `test_redactor.py` | 14 |
| `test_remediation.py` | 13 |
| `test_summary.py` | 12 |
| `test_integration.py` | 12 |
| `test_reporting.py` | 15 |
| `test_auth.py` | 12 |
| `test_dashboard.py` | 6 |
| `test_findings.py` | 9 |
| `test_scans.py` | 9 |
| `test_reports.py` | 9 |
| `test_new_scan.py` | 8 |
| `test_alerts.py` | 8 |
| `test_settings.py` | 4 |

---

## Project Structure

```
Cloud-Guard/
├── app/
│   ├── __init__.py              # Application factory
│   ├── config.py                # Environment config
│   ├── extensions.py            # db, login_manager, csrf, migrate
│   ├── errors.py                # Global error handlers
│   ├── logging_config.py        # Redacting log filter
│   ├── security.py              # Password policy, RBAC, rate limit, audit
│   ├── cli.py                   # flask CLI commands
│   │
│   ├── routes/                  # Blueprints
│   │   ├── auth.py
│   │   ├── dashboard.py
│   │   ├── findings.py
│   │   ├── scans.py
│   │   ├── reports.py
│   │   ├── alerts.py
│   │   └── settings.py
│   │
│   ├── services/                # Business logic
│   │   ├── archive_handler.py   # Safe ZIP extraction
│   │   ├── file_scanner.py      # Recursive walker
│   │   ├── detector.py
│   │   ├── detection/           # rules, entropy, context, engine
│   │   ├── validator.py
│   │   ├── validators/          # AWS, GitHub, generic
│   │   ├── risk_engine.py
│   │   ├── risk/                # factors, scoring, severity
│   │   ├── redactor.py
│   │   ├── fingerprint.py
│   │   ├── remediation.py
│   │   ├── summary.py
│   │   ├── reporting/           # JSON, CSV, HTML, PDF
│   │   └── orchestrator.py      # End-to-end pipeline
│   │
│   ├── models/                  # SQLAlchemy models
│   ├── templates/               # Jinja2 templates
│   └── static/                  # CSS, JS, images
│
├── tests/                       # 220+ tests
├── docs/
│   ├── SECURITY.md
│   └── screenshots/
│
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── requirements-dev.txt
├── pytest.ini
├── run.py
├── wsgi.py
├── .env.example
└── README.md
```

---

## Limitations

- **Detection is heuristic.** Regex and entropy will never be perfect. False positives and false negatives exist.
- **Validation is format-only by default.** No provider API calls. `format_valid` means the shape is plausible, not that the key is live.
- **Fingerprinting is unsalted.** Identical secrets produce identical fingerprints. Do not expose fingerprints to untrusted users.
- **Log redaction is best-effort.** Covers known token shapes and key names, not arbitrary strings.
- **SQLite is single-node.** For multi-worker deployments use PostgreSQL and swap the in-memory rate limiter for Redis.
- **Settings are persisted but not yet wired into the scanner.** Wiring is planned.
- **No Git history scanning yet.** Only the working tree is scanned.
- **No CI/CD emitter yet.** The orchestrator is CLI-ready but no SARIF output ships today.

---

## Roadmap

| Priority | Feature |
|---|---|
| High | Wire Setting values into scanner, detector, and risk engine |
| High | SARIF output for GitHub Code Scanning |
| High | Git history scanning (commit-level) |
| Medium | GitHub / GitLab App with webhook-triggered scans |
| Medium | Slack / email alerting |
| Medium | Redis-backed rate limiting |
| Medium | PostgreSQL migration guide |
| Low | Cloud provider integrations (AWS, GCP, Azure) |
| Low | Secret rotation workflows |
| Low | ML-based false-positive reduction |
| Low | Multi-tenant organizations |
| Low | Background scanning with Celery |

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for new behavior
4. Run `python -m pytest -q` — all tests must pass
5. Open a pull request with a clear description

### Code standards
- Type hints where useful
- Docstrings for public functions
- No `eval`, no `shell=True`, no plaintext secrets in test data
- One module, one responsibility

---

## License

Released under the **MIT License**. See [LICENSE](LICENSE).

---

## Acknowledgements

- **OWASP** — Top 10 and secrets management guidance
- **CWE** — Common weakness taxonomy
- **MITRE ATT&CK** — Credential access technique mapping
- **truffleHog**, **gitleaks**, **detect-secrets** — Prior art in secret scanning
- **Flask**, **SQLAlchemy**, **reportlab** — Excellent open-source foundations

---

<div align="center">

**Built as a security-engineering portfolio project.**

If CloudGuard helped you, give it a star.

</div>
