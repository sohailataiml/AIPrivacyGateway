"""Cross-platform task runner mirroring the Makefile targets.

GNU make is not available on a stock Windows host, so this module exposes the
same stable task names required by ``implementation.md`` section 1.

Usage::

    python tasks.py check
    python tasks.py test
"""

from __future__ import annotations

import shutil
import subprocess
import sys

UV = shutil.which("uv") or f"{sys.executable} -m uv"

TASKS: dict[str, tuple[list[str], ...]] = {
    "install": (
        ["uv", "sync", "--all-extras"],
        ["uv", "run", "python", "-m", "spacy", "download", "en_core_web_lg"],
    ),
    "format": (
        ["uv", "run", "ruff", "format", "app", "tests", "scripts"],
        ["uv", "run", "ruff", "check", "--fix", "app", "tests", "scripts"],
    ),
    "format-check": (["uv", "run", "ruff", "format", "--check", "app", "tests", "scripts"],),
    "lint": (["uv", "run", "ruff", "check", "app", "tests", "scripts"],),
    "typecheck": (["uv", "run", "mypy", "app"],),
    "test": (["uv", "run", "pytest", "tests/unit"],),
    "test-integration": (["uv", "run", "pytest", "tests/integration", "-m", "integration"],),
    "test-privacy": (["uv", "run", "pytest", "tests/privacy", "-m", "privacy"],),
    "test-security": (["uv", "run", "pytest", "tests/security", "-m", "security"],),
    "coverage": (
        [
            "uv",
            "run",
            "pytest",
            "tests/unit",
            "tests/privacy",
            "tests/security",
            "--cov=app",
            "--cov-report=term-missing",
            "--cov-report=xml",
        ],
    ),
    "audit": (
        ["uv", "run", "bandit", "-q", "-r", "app"],
        ["uv", "run", "pip-audit"],
    ),
    "run": (
        [
            "uv",
            "run",
            "uvicorn",
            "app.main:app",
            "--reload",
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
        ],
    ),
    "migrate": (["uv", "run", "alembic", "upgrade", "head"],),
    "seed": (["uv", "run", "python", "-m", "scripts.seed_local"],),
    "compose-up": (["docker", "compose", "up", "--build", "-d"],),
    # Run inside the stack: the compose database publishes no host port, so the
    # host-run "migrate" and "seed" targets above cannot reach it.
    "compose-migrate": (
        ["docker", "compose", "run", "--rm", "gateway", "alembic", "upgrade", "head"],
    ),
    "compose-seed": (
        ["docker", "compose", "run", "--rm", "gateway", "python", "-m", "scripts.seed_local"],
    ),
    "compose-down": (["docker", "compose", "down", "-v"],),
}

TASKS["check"] = (
    *TASKS["format-check"],
    *TASKS["lint"],
    *TASKS["typecheck"],
    *TASKS["test"],
)


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in TASKS:
        sys.stderr.write(f"usage: python tasks.py <{'|'.join(TASKS)}>\n")
        return 2

    for command in TASKS[argv[1]]:
        resolved = [shutil.which(command[0]) or command[0], *command[1:]]
        result = subprocess.run(resolved, check=False)  # noqa: S603
        if result.returncode != 0:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
