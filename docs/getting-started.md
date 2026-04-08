# Getting Started

## Prerequisites

For local development:

- Python 3.11+
- Node.js 20+
- PostgreSQL 15+
- Redis 7+
- Go toolchain (for recon tools)

For containerized development:

- Docker Desktop (or Docker Engine + Compose plugin)

## Environment Setup

1. Copy environment template:

```bash
cp .env.example .env
```

2. Set at least:

- `APP_SECRET_KEY`
- `POSTGRES_PASSWORD`
- `POSTGRES_USER`
- `POSTGRES_DB`

3. Optional but recommended:

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_ALLOWED_USERS`
- `NUCLEI_SEVERITY`
- `FFUF_WORDLIST`

## Quick Start (Docker)

```bash
docker compose up --build -d
```

Expected endpoints:

- API: `http://localhost:8000`
- OpenAPI docs: `http://localhost:8000/docs`
- Frontend: `http://localhost:3000`

Sanity checks:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/api/v1/dashboard
```

## Local Development

### Backend

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

In a second terminal:

```bash
source venv/bin/activate
celery -A app.workers.celery_app worker --loglevel=info -Q scans --concurrency=4
```

Optional bot:

```bash
source venv/bin/activate
python -m app.bot.telegram_bot
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

## Makefile Workflow

If using the project `Makefile`:

```bash
make setup
make run-api
make run-worker
make run-frontend
```

Common utility targets:

- `make test`
- `make lint`
- `make format`
- `make migrate`
- `make docker-up`
- `make docker-down`
