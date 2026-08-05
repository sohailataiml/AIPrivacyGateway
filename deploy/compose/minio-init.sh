#!/bin/sh
# Bucket initialization for the local MinIO (ADR-0027).
#
# Runs once when the stack comes up, before the gateway starts. Bucket creation
# is part of bringing the stack up rather than a manual step, so a fresh
# `docker compose up` from an empty volume produces a working upload path
# instead of a service that starts and then fails every POST.
#
# Idempotent: re-running against an existing bucket is a no-op, because the
# stack is expected to be brought up more than once.
set -eu

ENDPOINT="${MINIO_ENDPOINT:-http://minio:9000}"
BUCKET="${OBJECT_STORE_BUCKET:-sgw-documents}"

mc alias set local "$ENDPOINT" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null

if mc ls "local/$BUCKET" >/dev/null 2>&1; then
  echo "bucket $BUCKET already exists"
else
  mc mb "local/$BUCKET"
  echo "created bucket $BUCKET"
fi

# Private by default and explicitly re-asserted on every run. A public bucket
# would make every stored document readable by anyone who could guess a key,
# which is the one thing the opaque key naming is not meant to be relied on for.
mc anonymous set none "local/$BUCKET" >/dev/null
echo "bucket $BUCKET is private"

# Abandoned multipart uploads are invisible in listings and are billed until
# something removes them. The store aborts its own on failure; this catches
# whatever a hard crash left behind.
mc ilm rule add --expire-delete-marker --noncurrent-expire-days 1 "local/$BUCKET" 2>/dev/null ||
  echo "lifecycle rule not applied (optional for local use)"

echo "minio initialization complete"
