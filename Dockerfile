# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------------------
# Builder -- resolves dependencies and downloads the spaCy model.
# Nothing from this stage's toolchain reaches the runtime image.
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS builder

COPY --from=ghcr.io/astral-sh/uv:0.5 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

# The builder works in /app -- the same path the runtime image uses -- so the
# virtualenv is created where it will finally live. Two things break when these
# disagree:
#
#   * Console scripts carry an absolute shebang. A venv built at /build/.venv
#     and copied to /app/.venv leaves every entry point pointing at
#     /build/.venv/bin/python, which the runtime image does not have. The
#     kernel reports that as "exec /app/.venv/bin/uvicorn: no such file or
#     directory" -- naming the script, not the interpreter that is missing.
#   * ``spacy download`` shells out to uv, which resolves the environment from
#     the working directory. With the venv anywhere but ./.venv it fails with
#     "No virtual environment found".
WORKDIR /app

# Dependency layer first: it only reinstalls when the lock file changes.
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

# The spaCy model is a large, stable artifact -- keep it in its own layer so a
# source change does not re-download 600MB.
RUN --mount=type=cache,target=/root/.cache/uv \
    /app/.venv/bin/python -m spacy download en_core_web_lg

COPY app ./app
COPY migrations ./migrations
COPY scripts ./scripts
COPY alembic.ini ./alembic.ini

# --inexact is load-bearing, not a tuning flag. ``uv sync`` is declarative: by
# default it removes anything in the environment that the lock file does not
# mention, and ``en_core_web_lg`` is installed by the layer above rather than
# locked. Without this the model is silently deleted from the venv here, the
# image builds and starts, and the failure surfaces only at runtime -- as
# DetectorUnavailableError from the guard in app/detection/analyzer.py, which
# fails every request closed rather than degrading to no detection.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --inexact

# ---------------------------------------------------------------------------
# Runtime -- no build tools, no uv, no test or source-control artifacts.
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

# curl is needed by the container health check and nothing else.
RUN apt-get update \
    && apt-get install --no-install-recommends -y curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 gateway \
    && useradd --system --uid 10001 --gid gateway --no-create-home gateway

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_HOST=0.0.0.0 \
    APP_PORT=8000

WORKDIR /app

COPY --from=builder --chown=root:root /app/.venv /app/.venv
COPY --from=builder --chown=root:root /app/app /app/app
COPY --from=builder --chown=root:root /app/migrations /app/migrations
COPY --from=builder --chown=root:root /app/scripts /app/scripts
COPY --from=builder --chown=root:root /app/alembic.ini /app/alembic.ini

# Application files are owned by root and read-only to the runtime user: the
# process can execute them but cannot rewrite its own code.
USER gateway

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=40s --retries=5 \
    CMD curl --fail --silent http://127.0.0.1:8000/health/live || exit 1

# One worker, deliberately. Four separate bounds in this application are
# documented as per-process, and a second worker silently doubles or splits
# every one of them:
#
#   * the provider concurrency semaphore (app/pipeline/context.py) -- a stated
#     ceiling of 16 in-flight provider calls becomes 32;
#   * the bounded audit queue and its depth gauge (app/audit/) -- two queues,
#     and a scrape reports whichever process answered;
#   * the last_used_at write bound (app/auth/dependencies.py) -- one tracker
#     per process, so the bound doubles;
#   * the Prometheus registry (app/observability/metrics.py) -- counters split
#     across workers, so every rate is understated by whatever share of scrapes
#     the other worker answers.
#
# Scale by running more containers, not more workers in one. Making this safe
# instead would mean prometheus_client's multiprocess collector plus a shared
# writable directory, which this read-only image deliberately does not have.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
