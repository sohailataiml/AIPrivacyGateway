"""Mint the secrets a production deployment needs, once, to stdout.

Three kinds of secret, and they are not interchangeable:

* **Vault keys** and **document keys** are AES-256-GCM keys. Exactly 32 bytes,
  base64-encoded. The gateway refuses anything else at startup -- a 34-byte key
  that *looked* right shipped in ``docker-compose.yml`` once and made every
  upload fail with a 503 (PROGRESS.md defect 12), so the length is checked here
  before it can reach a host.
* **The API key pepper** and **audit HMAC key** are secrets for keyed hashing.
  They have a minimum length rather than a fixed one.
* **The metrics token** is a bearer credential for the scrape endpoint.

Object store credentials are **not** minted here. Storage is AWS S3 (ADR-0035),
so its credentials are issued by IAM, not generated locally -- a key pair this
script invented would authenticate against nothing. What the deployment needs
from AWS is listed at the end of the output.

They are printed **once** and stored nowhere. Paste them into Render's dashboard
and close the terminal. Piping this to a file defeats the point; if you lose
one, generate a new one and update the host -- the vault and document key rings
are versioned by key id precisely so a rotation does not require re-encrypting
anything that already exists.

Each key is separate on purpose. One secret reused across the vault, documents,
and audit correlation would mean one compromise is three, and the two key rings
in particular protect data with different lifetimes -- session mappings expire
in hours, stored documents persist -- so they rotate on different schedules.
"""

from __future__ import annotations

import base64
import secrets
import sys
from typing import Final

AES_KEY_BYTES: Final = 32
"""AES-256. Not negotiable: the key ring rejects any other length."""

PEPPER_CHARS: Final = 48
TOKEN_CHARS: Final = 48


def _aes_key() -> str:
    """A base64-encoded 32-byte key, verified to decode back to 32 bytes."""
    raw = secrets.token_bytes(AES_KEY_BYTES)
    encoded = base64.b64encode(raw).decode("ascii")
    # Belt and braces against the defect-12 shape: assert the round trip rather
    # than trusting that the encoder and the label agree.
    if len(base64.b64decode(encoded)) != AES_KEY_BYTES:
        raise RuntimeError("generated key does not decode to 32 bytes")
    return encoded


def _write(line: str = "") -> None:
    """``print`` is banned by lint in this repository."""
    sys.stdout.write(line + "\n")


def main() -> None:
    _write("# Secure AI Gateway -- production secrets")
    _write("# Shown once. Paste into Render, then close this terminal.")
    _write("# Nothing here is written to disk by this script.")
    _write()

    _write("## sgw-api")
    _write(f"API_KEY_PEPPER={secrets.token_urlsafe(PEPPER_CHARS)}")
    _write(f"AUDIT_HMAC_KEY={secrets.token_urlsafe(PEPPER_CHARS)}")
    _write(f"VAULT_KEY_PROD1={_aes_key()}")
    _write(f"DOCUMENT_KEY_PROD1={_aes_key()}")
    _write(f"METRICS_TOKEN={secrets.token_urlsafe(TOKEN_CHARS)}")
    _write()

    _write("## Set by hand, once the services have URLs")
    _write("# CORS_ALLOWED_ORIGINS on sgw-api = https://<workspace>.onrender.com")
    _write("# GATEWAY_ORIGIN       on sgw-workspace = https://<api>.onrender.com")
    _write("# GATEWAY_DEMO_API_KEY on sgw-workspace = a seeded key, server-side only")
    _write()

    _write("## From AWS, not from this script")
    _write("# Storage is S3, so IAM issues these -- a generated pair signs nothing.")
    _write("#   OBJECT_STORE_BUCKET             an existing bucket, public access blocked")
    _write("#   OBJECT_STORE_REGION             the bucket's region")
    _write("#   OBJECT_STORE_ACCESS_KEY_ID      from an IAM user scoped to that bucket")
    _write("#   OBJECT_STORE_SECRET_ACCESS_KEY  its secret, shown once by AWS")
    _write("#")
    _write("# Render cannot assume an IAM role, which is why this is a static key")
    _write("# pair. Grant it s3:GetObject, s3:PutObject, s3:DeleteObject,")
    _write("# s3:AbortMultipartUpload, and s3:ListBucket on that bucket alone, and")
    _write("# rotate it on a schedule.")


if __name__ == "__main__":
    main()
