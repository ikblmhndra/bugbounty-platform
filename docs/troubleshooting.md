# Troubleshooting

This runbook captures common issues seen during setup and runtime.

## Docker Build Fails for Worker (Go/tool install)

Symptoms:

- `go install ...` fails during `Dockerfile.worker` build
- upstream module/tool changes break latest installs

Checks and fixes:

- Ensure Go version in worker image is compatible with required tools
- Keep fragile tools optional if they are non-critical
- Rebuild worker image:

```bash
docker compose build worker
docker compose up -d worker
```

## Frontend Build Fails with Missing Import

Symptoms:

- Next.js build reports module not found on nested page paths

Fix:

- Verify relative imports from nested `pages/*` locations point to correct directories (`../../components`, `../../lib`, etc.)

## Frontend Runner Fails Copying `/app/public`

Symptoms:

- Docker build fails with `"/app/public": not found`

Fix:

- Remove `COPY --from=builder /app/public ./public` if no `public` directory exists.

## API Startup Crashes on Duplicate Index/Table

Symptoms:

- `DuplicateTableError` for index/table during `init_db()`
- crash loop during API startup

Causes:

- duplicate index definitions in models
- concurrent schema initialization races

Fixes:

- avoid duplicate ORM index declarations
- serialize schema init using PostgreSQL advisory transaction lock
- rebuild and restart API:

```bash
docker compose build api
docker compose up -d api
```

Validate:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/api/v1/dashboard
```

## Bot Logging Fails with structlog `PrintLogger` error

Symptoms:

- `AttributeError: 'PrintLogger' object has no attribute 'name'`

Fix:

- configure structlog with stdlib-compatible logger factory/wrapper.

## Fast Triage Commands

```bash
docker compose ps
docker compose logs -f api
docker compose logs -f worker
docker compose logs -f frontend
docker compose logs -f bot
docker compose logs -f postgres
docker compose logs -f redis
```

## When to Reset Local State

Use only in local/dev when DB state is corrupted or inconsistent:

```bash
docker compose down -v
docker compose up --build -d
```

Warning: this removes persisted local volumes.
