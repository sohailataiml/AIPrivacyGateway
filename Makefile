# Stable task commands for the Secure AI Gateway.
# Every command runs through `uv` so the toolchain is identical locally and in CI.
# Windows hosts without GNU make can run the same commands via `python tasks.py <target>`.

UV ?= uv
RUN := $(UV) run

.DEFAULT_GOAL := help
.PHONY: help install format format-check lint typecheck test test-unit test-integration \
        test-privacy test-security coverage audit run seed migrate compose-up compose-migrate \
        compose-seed compose-down check

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

# The two suites that drive a whole request through the real routers, the real
# composition root, and a provider adapter that records what crossed the
# boundary. They are the only place "no original reached the provider" is
# asserted against something that actually received the payload.
test-e2e: ## End-to-end request workflows, both routes
	$(RUN) pytest tests/privacy/test_document_workflow.py tests/privacy/test_outbound_conformance.py

# One session, not four. The per-suite targets above each start the application
# and each pass in isolation; a defect where startup leaves global state behind
# only shows when one process runs the whole tree. See PROGRESS.md defect 17.
test-all: ## Every suite in a single session (the real gate)
	$(RUN) pytest tests -m "not performance"

coverage: ## Full suite with coverage gate
	$(RUN) pytest tests/unit tests/privacy tests/security --cov=app --cov-report=term-missing --cov-report=xml

# The object store adapter sits at 34% without this: the fake is a dictionary
# and cannot exercise signing, multipart, or S3's part-size rules.
coverage-full: ## Coverage including the integration suites (needs the stack up)
	$(RUN) pytest tests/unit tests/privacy tests/security --cov=app --cov-report=
	$(RUN) pytest tests/integration -m integration --cov=app --cov-append --cov-report=term-missing

audit: ## Dependency and static security scan
	$(RUN) bandit -q -r app
	$(RUN) pip-audit

check: format-check lint typecheck test ## Everything CI runs on a fast path

run: ## Run the API locally with reload
	$(RUN) uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# The migrate/seed pair below targets whatever DATABASE_URL resolves to on the
# host -- a PostgreSQL you are running yourself. They cannot reach the compose
# database: that container publishes no host port on purpose, so only the
# gateway can talk to it. Use the compose-* pair for the composed stack.
migrate: ## Apply database migrations (host-run PostgreSQL)
	$(RUN) alembic upgrade head

seed: ## Seed a local tenant, API key, and default policy (idempotent)
	$(RUN) python -m scripts.seed_local

compose-up: ## Start the local stack
	docker compose up --build -d

compose-migrate: ## Apply migrations inside the stack (run after compose-up)
	docker compose run --rm gateway alembic upgrade head

compose-seed: ## Seed the stack's database and print an API key (run after compose-migrate)
	docker compose run --rm gateway python -m scripts.seed_local

compose-down: ## Stop the local stack and remove volumes
	docker compose down -v
