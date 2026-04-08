# Bug Bounty Platform

A production-grade, modular security assessment platform for authorized bug bounty workflows.

> **IMPORTANT**: This platform is for use **only in authorized environments**. All validation steps are analyst-assisted. No autonomous exploitation is performed.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         Bug Bounty Platform                       │
├─────────────┬──────────────┬──────────────┬──────────────────────┤
│  Next.js    │  FastAPI     │  Celery      │  Telegram Bot        │
│  Dashboard  │  REST API    │  Workers     │  (pyTelegramBotAPI)  │
├─────────────┴──────────────┴──────────────┴──────────────────────┤
│                PostgreSQL (SQLAlchemy ORM)                        │
│                Redis (Celery broker + result backend)             │
├──────────────────────────────────────────────────────────────────┤
│  Recon Tools: subfinder · assetfinder · httpx · gau              │
│               waybackurls · katana · ffuf · nuclei · gowitness   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
bugbounty-platform/
├── app/
│   ├── main.py                    # FastAPI app entry point
│   ├── config.py                  # Pydantic settings (env-based)
│   ├── api/
│   │   ├── scans.py               # POST/GET /scans
│   │   ├── targets.py             # CRUD /targets
│   │   ├── findings.py            # GET/PATCH /findings
│   │   └── misc.py                # /paths /assets /dashboard /reports
│   ├── workers/
│   │   ├── celery_app.py          # Celery factory
│   │   └── scan_tasks.py          # Full recon pipeline task
│   ├── services/
│   │   ├── recon_service.py       # Tool wrappers (subfinder, httpx, nuclei…)
│   │   ├── analysis_service.py    # Finding normalization + attack path analysis
│   │   ├── validation_service.py  # Suggested manual commands for analysts
│   │   └── report_service.py      # Markdown / JSON / HTML report generation
│   ├── models/
│   │   └── models.py              # SQLAlchemy ORM models
│   ├── schemas/
│   │   └── schemas.py             # Pydantic v2 request/response schemas
│   ├── utils/
│   │   ├── database.py            # Engine, sessions, init_db
│   │   ├── logging.py             # structlog setup
│   │   └── shell.py               # Shell command runner with timeout
│   └── bot/
│       └── telegram_bot.py        # Telegram bot (/scan /status /report…)
├── frontend/                      # Next.js dashboard
│   ├── pages/
│   │   ├── index.tsx              # Dashboard
│   │   ├── targets.tsx            # Target management
│   │   ├── findings.tsx           # Filterable findings view
│   │   ├── paths.tsx              # Attack path analysis view
│   │   └── scans/
│   │       ├── index.tsx          # Scan list + launch
│   │       └── [id].tsx           # Scan detail with tabs
│   ├── components/
│   │   ├── Layout.tsx
│   │   ├── Sidebar.tsx
│   │   └── ui.tsx                 # Reusable UI components
│   └── lib/
│       └── api.ts                 # Typed API client
├── docker/
│   ├── Dockerfile.api
│   ├── Dockerfile.worker
│   ├── Dockerfile.bot
│   └── Dockerfile.frontend
├── alembic/                       # Database migrations
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

---

## Quick Start

### Option A: Docker Compose (Recommended)

```bash
# 1. Clone / copy the project
cd bugbounty-platform

# 2. Configure environment
cp .env.example .env
# Edit .env — at minimum set POSTGRES_PASSWORD and APP_SECRET_KEY

# GEN-TOKEN
python3 -c "import secrets; print(secrets.token_hex(32))

# 3. Start all services
docker compose up --build -d

# 4. Services available at:
#   API:       http://localhost:8000
#   API Docs:  http://localhost:8000/docs
#   Dashboard: http://localhost:3000
#   Flower:    http://localhost:5555  (add to compose if needed)
```

### Option B: Local Development

#### Prerequisites

```bash
# Python 3.11+
python --version

# Node.js 20+
node --version

# PostgreSQL 15+
# Redis 7+

# Go tools (install all at once):
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/sensepost/gowitness@latest

# Update nuclei templates
nuclei -update-templates
```

#### Backend Setup

```bash
cd bugbounty-platform

# Create virtualenv
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your DB credentials

# Initialize database (auto-runs on first startup)
# OR manually via alembic:
alembic upgrade head

# Start API server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# In a separate terminal: start Celery worker
celery -A app.workers.celery_app worker --loglevel=info -Q scans --concurrency=4

# Optional: start Telegram bot
python -m app.bot.telegram_bot
```

#### Frontend Setup

```bash
cd frontend
npm install
npm run dev
# Dashboard at http://localhost:3000
```

---

## Configuration Reference

All configuration is via environment variables (`.env`):


| Variable                 | Default                              | Description                                  |
| ------------------------ | ------------------------------------ | -------------------------------------------- |
| `APP_SECRET_KEY`         | changeme                             | JWT secret key                               |
| `POSTGRES_PASSWORD`      | changeme                             | Database password                            |
| `REDIS_HOST`             | localhost                            | Redis host                                   |
| `TELEGRAM_BOT_TOKEN`     | *(empty)*                            | Bot token from @BotFather                    |
| `TELEGRAM_ALLOWED_USERS` | *(empty)*                            | Comma-separated user IDs (empty = allow all) |
| `NUCLEI_SEVERITY`        | low,medium,high,critical             | Nuclei scan severity filter                  |
| `FFUF_WORDLIST`          | /usr/share/wordlists/dirb/common.txt | Wordlist for ffuf                            |
| `DEFAULT_SCAN_TIMEOUT`   | 3600                                 | Max scan duration (seconds)                  |
| `REPORTS_DIR`            | ./reports                            | Where reports are saved                      |
| `SCREENSHOTS_DIR`        | ./screenshots                        | Where screenshots are saved                  |


---

## API Reference

### Trigger a Scan

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "options": {
      "run_ffuf": false,
      "run_gowitness": true,
      "nuclei_severity": "medium,high,critical"
    }
  }'
```

### Get Scan Status

```bash
curl http://localhost:8000/api/v1/scans/<scan_id>
```

### Get Findings

```bash
# All findings
curl http://localhost:8000/api/v1/findings?scan_id=<scan_id>

# High/Critical only
curl "http://localhost:8000/api/v1/findings?scan_id=<id>&severity=high&severity=critical"
```

### Get Suggested Validation Commands

```bash
curl http://localhost:8000/api/v1/findings/<finding_id>/validate
```

### Generate Report

```bash
# HTML report (open in browser)
curl http://localhost:8000/api/v1/reports/<scan_id>?fmt=html > report.html

# JSON report
curl http://localhost:8000/api/v1/reports/<scan_id>?fmt=json

# Markdown
curl http://localhost:8000/api/v1/reports/<scan_id>?fmt=markdown
```

### Dashboard Stats

```bash
curl http://localhost:8000/api/v1/dashboard
```

---

## Telegram Bot Commands

```
/scan example.com    — Start a scan
/status              — List recent scans
/report <id>         — Findings summary + report link
/findings <id>       — Findings list
/paths <id>          — Attack path analysis
/cancel <id>         — Cancel a running scan
```

---

## Recon Pipeline

Each step is independent, retried on failure, and logged incrementally:

```
1. subdomain_enum()     subfinder + assetfinder (passive)
2. probe_alive()        httpx — liveness, status, tech detection
3. collect_urls()       gau + waybackurls (passive) + katana (active)
4. take_screenshots()   gowitness [optional]
5. fuzz_endpoints()     ffuf with smart targeting [optional, off by default]
6. scan_vulnerabilities() nuclei with configurable severity
7. normalize_findings() Map raw output → categorized findings
8. analyze_findings()   Correlate findings → attack paths
```

---

## Attack Path Analysis

The analysis engine identifies these patterns (non-exhaustive):


| Pattern                  | Description                      | Confidence |
| ------------------------ | -------------------------------- | ---------- |
| XSS → Session Hijacking  | XSS + missing HttpOnly cookie    | 0.65       |
| SSRF → Cloud Metadata    | SSRF on cloud-hosted target      | 0.55       |
| SQLi → Data Exfiltration | SQLi + sensitive data endpoints  | 0.60–0.80  |
| LFI → Config Exposure    | LFI to read .env/config files    | 0.70       |
| Misconfiguration Cluster | 3+ misconfigs → elevated surface | 0.50       |


All paths include step-by-step analyst guidance and suggested manual commands.

---

## Database Schema

```
Target
  └─── Scan (many)
         ├─── Asset (many)        — subdomains, URLs, endpoints
         ├─── Finding (many)      — normalized vulnerabilities
         ├─── AttackPath (many)   — correlated finding chains
         │      └── AttackPathNode (many)
         └─── Log (many)          — step-level audit log
```

---

## Security Notes

- This platform does **not** perform autonomous exploitation
- All suggested commands in `validation_service.py` are for **manual analyst use only**
- Ensure targets are within your authorized scope before scanning
- `TELEGRAM_ALLOWED_USERS` should always be configured in production
- Rotate `APP_SECRET_KEY` and `POSTGRES_PASSWORD` from defaults
- Run in an isolated network segment when possible

---

## Development

### Run Tests

```bash
pytest tests/ -v
```

### Format Code

```bash
black app/
ruff check app/ --fix
```

### Create a Migration

```bash
alembic revision --autogenerate -m "describe change"
alembic upgrade head
```

### Monitor Celery Workers

```bash
# Flower web UI (add to docker-compose or run manually)
celery -A app.workers.celery_app flower --port=5555
```

