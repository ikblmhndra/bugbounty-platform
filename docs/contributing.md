# Contributing

## Development Workflow

1. Create a feature branch
2. Implement focused changes
3. Run tests and lint checks
4. Update docs when behavior or interfaces change
5. Open a pull request with context and test evidence

## Local Quality Checks

Backend:

```bash
pytest tests/ -v
ruff check app/ tests/
black app/ tests/
```

Frontend:

```bash
cd frontend
npm run lint
npm run build
```

## Database Changes

When updating models:

```bash
alembic revision --autogenerate -m "describe change"
alembic upgrade head
```

Include migration rationale in your PR.

## Code Style

- Prefer small, composable service functions
- Keep API handlers thin; business logic belongs in services
- Avoid silent failures unless explicitly intended and logged
- Preserve structured logging for operational visibility

## Security and Scope

- Never introduce autonomous exploitation logic
- Keep analyst validation steps explicit and manual
- Avoid committing secrets or local `.env` values

## Commit and PR Guidance

- Use clear, intent-focused commit messages
- Describe why the change is needed, not only what changed
- Include test commands and outputs in PR description
