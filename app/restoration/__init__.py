"""Output parsing and restoration.

The public surface is deliberately small::

    pipeline = OutputPipeline(vault=vault)
    output = await pipeline.restore(
        tenant_id=tenant_id,
        session_id=session_id,
        response=provider_response,
        policy=policy_snapshot,
    )

``output.text`` is authorized plaintext. Return it to the request principal and
nowhere else.
"""

from __future__ import annotations

from app.restoration.pipeline import DEFAULT_MAX_OUTPUT_CHARS, OutputPipeline
from app.restoration.protocols import PolicyLike, VaultLike
from app.restoration.results import RestoredOutput

__all__ = [
    "DEFAULT_MAX_OUTPUT_CHARS",
    "OutputPipeline",
    "PolicyLike",
    "RestoredOutput",
    "VaultLike",
]
