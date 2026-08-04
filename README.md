# Secure AI Gateway

A privacy-preserving gateway that sits between your application and an LLM provider.
It detects sensitive values in outbound prompts, replaces them with opaque reversible
tokens, calls the provider with the protected text only, and restores the original
values in the response returned to the authorized caller.

The provider never sees the original data. Neither do the logs, the metrics, the
traces, or the audit tables.

```
client → [ auth → policy → detect → tokenize → vault ] → provider
                                                            ↓
client ← [ restore ← vault ← parse ] ←──────────────────────┘
```

See [architecture.md](architecture.md) for the full specification and
[implementation.md](implementation.md) for the phased build plan.

## Status

Version 1 is under active construction. Phase completion is tracked in the
checklists in `implementation.md`.

## Requirements

- Python 3.12 (3.13+ is not yet supported by the spaCy/Presidio wheel set)
- [uv](https://docs.astral.sh/uv/) for dependency management
- Docker with Compose for the local stack

## Local setup

```bash
uv sync --all-extras
uv run python -m spacy download en_core_web_lg
cp .env.example .env
```

Stable task commands are exposed through the `Makefile`. On Windows hosts without
GNU make, `python tasks.py <target>` runs the identical commands:

| Target | Purpose |
| --- | --- |
| `install` | Sync dependencies and download the spaCy model |
| `format` | Apply Ruff formatting and safe fixes |
| `lint` | Ruff lint |
| `typecheck` | mypy (strict) |
| `test` | Unit tests |
| `test-integration` | Integration tests (needs PostgreSQL and Redis) |
| `test-privacy` | Privacy regression suite |
| `test-security` | Security control suite |
| `coverage` | Full gate with coverage report |
| `audit` | bandit + pip-audit |
| `check` | format-check, lint, typecheck, test |
| `run` | Run the API with reload |
| `compose-up` / `compose-down` | Local stack lifecycle |

```bash
python tasks.py check
python tasks.py run
```

The API then answers on <http://127.0.0.1:8000>, with OpenAPI at `/docs`.

## Configuration

All settings come from the environment. `.env.example` documents every variable
with a non-production placeholder. Production startup rejects development
defaults, short encryption keys, and missing secrets — see
[ADR-0008](docs/adr/0008-fail-closed.md).

The local default provider is `mock`, so a fresh checkout cannot accidentally
spend money against a paid provider.

## Operational warnings

- **Fail closed.** If detection, tokenization, the vault, or restoration cannot
  complete, the request fails. There is no bypass path, and one must never be added.
- **Redis is the vault.** Token mappings live in Redis under application-layer
  AES-256-GCM encryption with a TTL. Losing Redis loses the ability to restore
  in-flight sessions — that is the intended trade-off, not a bug.
- **Sessions are the blast radius.** A token only resolves within its own tenant
  *and* its own session. Reuse a session id across users and you have merged
  their data.
- **The detector is statistical.** Presidio plus custom recognizers will miss some
  values and over-match others. This gateway reduces exposure; it does not
  eliminate it, and it is not a compliance certification.

## Known limitations (v1)

No streaming, no dashboard, no Kubernetes manifests, a single external provider,
text only, English only, and no automated medical classification claims.

## License

Apache-2.0
