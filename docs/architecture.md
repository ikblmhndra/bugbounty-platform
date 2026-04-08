# Architecture

## High-Level Components

- **Frontend**: Next.js dashboard for scans, findings, paths, and reporting
- **API**: FastAPI backend exposing REST endpoints
- **Worker**: Celery worker executing scan jobs asynchronously
- **Bot**: Telegram bot as an operator interface
- **Database**: PostgreSQL for durable state
- **Queue/Cache**: Redis as Celery broker/result backend

## Runtime Flow

1. User submits scan request via frontend, API, or Telegram bot
2. API creates `Target` and `Scan` records
3. API enqueues Celery task (`run_scan`)
4. Worker executes multi-step recon and vulnerability workflow
5. Worker writes assets, findings, logs, and attack paths into PostgreSQL
6. Frontend and API read persisted state for monitoring and reporting

## Core Code Map

- API entrypoint: `app/main.py`
- API routers: `app/api/`
- Worker task orchestration: `app/workers/scan_tasks.py`
- Tool wrappers: `app/services/recon_service.py`
- Finding normalization and attack-path analysis: `app/services/analysis_service.py`
- Report generation: `app/services/report_service.py`
- Validation suggestion generation: `app/services/validation_service.py`
- ORM models: `app/models/models.py`
- DB/session lifecycle: `app/utils/database.py`
- Logging setup: `app/utils/logging.py`

## Data Model Overview

- `Target` -> one domain/program under assessment
- `Scan` -> one execution run for a target
- `Asset` -> discovered subdomains/URLs/endpoints and metadata
- `Finding` -> normalized vulnerability results
- `AttackPath` and `AttackPathNode` -> correlated multi-step risk chains
- `Log` -> scan execution logs by step and severity

## Reliability Notes

- Startup schema initialization is serialized on PostgreSQL with advisory transaction locks
- Worker uses incremental persistence to retain partial progress when steps fail
- Pipeline tolerates step-level failures and continues where possible
- Scan cancellation is supported through Celery task revocation
