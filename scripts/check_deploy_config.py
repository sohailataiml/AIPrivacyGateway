"""Run the real production gate against your intended values, locally.

``Settings`` refuses to build under ``APP_ENV=production`` if a pepper is a
known placeholder, a vault key is short or all zeroes, CORS is a wildcard, the
metrics endpoint is unauthenticated, or a key ring is missing the id it says is
active. That check is good, and it runs *at startup* -- so a bad value produces
a container that will not boot and a deploy log you have to go read.

This runs the same validation on your laptop, from a file you fill in, so the
failure arrives as a message instead of a rollback.

It imports the production ``Settings`` class rather than reimplementing its
rules. A separate copy of the rules would drift, and a drifted pre-flight check
is worse than none: it tells you the deploy is fine right up until it is not.

Usage::

    cp deploy.env.example deploy.env      # fill in real values, never commit
    python -m scripts.check_deploy_config deploy.env

``deploy.env`` is gitignored. Delete it when you are done.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Final

from app.config.settings import Settings

REQUIRED: Final[tuple[str, ...]] = (
    "API_KEY_PEPPER",
    "AUDIT_HMAC_KEY",
    "VAULT_ACTIVE_KEY_ID",
    "DOCUMENT_ACTIVE_KEY_ID",
    "METRICS_TOKEN",
    "CORS_ALLOWED_ORIGINS",
    "DATABASE_URL",
    "REDIS_URL",
    "OBJECT_STORE_ENDPOINT_URL",
    "OBJECT_STORE_BUCKET",
    "OBJECT_STORE_ACCESS_KEY_ID",
    "OBJECT_STORE_SECRET_ACCESS_KEY",
)


def _write(line: str = "") -> None:
    sys.stdout.write(line + "\n")


def _parse(path: Path) -> dict[str, str]:
    """Read a dotenv-shaped file. Deliberately simple: no interpolation."""
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        values[name.strip()] = value.strip().strip('"').strip("'")
    return values


def main() -> int:
    if len(sys.argv) != 2:
        _write("usage: python -m scripts.check_deploy_config <env-file>")
        return 2

    path = Path(sys.argv[1])
    if not path.is_file():
        _write(f"no such file: {path}")
        return 2

    values = _parse(path)
    values["APP_ENV"] = "production"

    missing = [name for name in REQUIRED if not values.get(name)]
    if missing:
        _write("missing or empty:")
        for name in missing:
            _write(f"  - {name}")
        return 1

    try:
        # Set the environment and construct with no arguments, which is exactly
        # what the application does at startup. Passing the values as keyword
        # arguments instead would skip the env-var collection that builds the
        # key rings -- `vault_keys` and `document_keys` are assembled from
        # `VAULT_KEY_<ID>` and `DOCUMENT_KEY_<ID>` variables, so a kwargs call
        # would validate an empty ring and report a broken deploy as fine.
        for name, value in values.items():
            os.environ[name] = value
        Settings(_env_file=None)
    except Exception as error:
        _write("REFUSED -- this configuration would fail at boot:")
        for line in str(error).splitlines():
            _write(f"  {line}")
        return 1

    _write("OK -- production settings validate.")
    _write()
    _write("Still not checked by this script, because it cannot be:")
    _write("  - that DATABASE_URL, REDIS_URL, and the object store are reachable")
    _write("  - that the bucket exists (Render has no minio-init equivalent)")
    _write("  - that migrations have been applied (alembic upgrade head)")
    _write("  - that CORS_ALLOWED_ORIGINS is the workspace's actual URL")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
