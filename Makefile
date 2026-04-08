SHELL := /bin/bash

PYTHON ?= python3
VENV_DIR ?= venv
COMPOSE := docker compose
VENV_BIN := $(VENV_DIR)/bin
PIP := $(VENV_BIN)/pip
PYTEST := $(VENV_BIN)/pytest
ALEMBIC := $(VENV_BIN)/alembic
UVICORN := $(VENV_BIN)/uvicorn
CELERY := $(VENV_BIN)/celery
RUFF := $(VENV_BIN)/ruff
BLACK := $(VENV_BIN)/black

FRONTEND_DIR := frontend
NPM := npm --prefix $(FRONTEND_DIR)

.PHONY: help setup setup-backend setup-frontend install install-frontend run-api run-worker run-frontend run-bot test lint format migrate docker-up docker-down docker-logs clean

help:
	@echo "Bug Bounty Platform - Make targets"
	@echo ""
	@echo "Setup:"
	@echo "  make setup             - Create venv + install backend and frontend deps"
	@echo "  make setup-backend     - Create venv and install Python deps"
	@echo "  make setup-frontend    - Install frontend npm deps"
	@echo ""
	@echo "Local dev:"
	@echo "  make run-api           - Start FastAPI with reload on :8000"
	@echo "  make run-worker        - Start Celery worker (queue: scans)"
	@echo "  make run-frontend      - Start Next.js dev server on :3000"
	@echo "  make run-bot           - Start Telegram bot"
	@echo ""
	@echo "Quality:"
	@echo "  make test              - Run pytest suite"
	@echo "  make lint              - Run ruff checks"
	@echo "  make format            - Run black and ruff --fix"
	@echo ""
	@echo "Database:"
	@echo "  make migrate           - Run alembic upgrade head"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-up         - Start all services with Docker Compose"
	@echo "  make docker-down       - Stop all services"
	@echo "  make docker-logs       - Tail docker compose logs"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean             - Remove local cache/build artifacts"

setup: setup-backend setup-frontend

up:
	$(COMPOSE) up --build -d

setup-backend:
	$(PYTHON) -m venv $(VENV_DIR)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

setup-frontend:
	$(NPM) install

install: setup-backend

install-frontend: setup-frontend

run-api:
	$(UVICORN) app.main:app --host 0.0.0.0 --port 8000 --reload

run-worker:
	$(CELERY) -A app.workers.celery_app worker --loglevel=info -Q scans --concurrency=4

run-frontend:
	$(NPM) run dev

run-bot:
	$(VENV_BIN)/python -m app.bot.telegram_bot

test:
	$(PYTEST) tests/ -v

lint:
	$(RUFF) check app/ tests/

format:
	$(BLACK) app/ tests/
	$(RUFF) check app/ tests/ --fix

migrate:
	$(ALEMBIC) upgrade head

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache
	rm -rf app/__pycache__ app/*/__pycache__ tests/__pycache__
	rm -rf $(FRONTEND_DIR)/.next $(FRONTEND_DIR)/node_modules/.cache
