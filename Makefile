# Stable task commands for the Secure AI Gateway.
# Every command runs through `uv` so the toolchain is identical locally and in CI.
# Windows hosts without GNU make can run the same commands via `python tasks.py <target>`.

UV ?= uv
RUN := $(UV) run

.DEFAULT_GOAL := help
.PHONY: help install format format-check lint typecheck test test-unit test-integration \
        test-privacy test-security coverage audit run seed migrate compose-up compose-down check

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

install: ## Create the virtualenv, install all dependencies, download the spaCy model
	$(UV) sync --all-extras
	$(RUN) python -m spacy download en_core_web_lg

format: ## Apply formatting
	$(RUN) ruff format app tests scripts
	$(RUN) ruff check --fix app tests scripts

format-check: ## Verify formatting without writing
	$(RUN) ruff format --check app tests scripts

lint: ## Lint
	$(RUN) ruff check app tests scripts

typecheck: ## Static type check
	$(RUN) mypy app

test: ## Unit tests
	$(RUN) pytest tests/unit

test-unit: test

test-integration: ## Integration tests (needs PostgreSQL + Redis)
	$(RUN) pytest tests/integration -m integration

test-privacy: ## Privacy regression suite
	$(RUN) pytest tests/privacy -m privacy

test-security: ## Security control suite
	$(RUN) pytest tests/security -m security

coverage: ## Full suite with coverage gate
	$(RUN) pytest tests/unit tests/privacy tests/security --cov=app --cov-report=term-missing --cov-report=xml

audit: ## Dependency and static security scan
	$(RUN) bandit -q -r app
	$(RUN) pip-audit

check: format-check lint typecheck test ## Everything CI runs on a fast path

run: ## Run the API locally with reload
	$(RUN) uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

migrate: ## Apply database migrations
	$(RUN) alembic upgrade head

seed: ## Seed a local tenant, API key, and default policy (idempotent)
	$(RUN) python -m scripts.seed_local

compose-up: ## Start the local stack
	docker compose up --build -d

compose-down: ## Stop the local stack and remove volumes
	docker compose down -v
