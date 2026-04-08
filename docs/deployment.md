# Deployment Guide

## Deployment Modes

- **Single-node Docker Compose**: fastest path for internal use
- **Container platform (recommended for production)**: managed orchestration, secret management, observability

## Baseline Requirements

- PostgreSQL with persistent storage and backup policy
- Redis with persistence strategy appropriate to your SLOs
- API and worker services with independent scaling
- Reverse proxy (TLS termination, request limits, access logs)

## Environment and Secrets

Store secrets outside source control:

- `APP_SECRET_KEY`
- `POSTGRES_PASSWORD`
- `TELEGRAM_BOT_TOKEN`
- any API keys or private integrations

Do not commit `.env` to version control.

## Production Hardening Checklist

- [ ] Set strong `APP_SECRET_KEY`
- [ ] Restrict network access (DB/Redis not publicly exposed)
- [ ] Configure `TELEGRAM_ALLOWED_USERS`
- [ ] Enable structured centralized logging
- [ ] Add health checks and restart policies
- [ ] Use pinned image tags and controlled rollouts
- [ ] Run periodic dependency updates and vulnerability scans
- [ ] Set CPU/memory limits per service

## Recommended Runtime Separation

- API: stateless, horizontally scalable
- Worker: CPU-bound, scale by queue depth and tool execution time
- Frontend: stateless, cache-enabled
- DB/Redis: stateful services with persistent volumes

## Migrations

Use Alembic for schema evolution:

```bash
alembic upgrade head
```

Apply migrations during deploy before routing traffic to new API versions when schema changes are backward-incompatible.

## Observability

At minimum, capture:

- API latency and error rate
- worker task success/failure counts
- queue depth and task duration
- DB connection saturation
- host/container resource usage
