"""Show the privacy transformation end to end, without a server or a provider.

Run it::

    python scripts/demo_pipeline.py

It uses the real detector, tokenizer, vault, and restoration modules -- only the
LLM is faked, by the same MockProvider the tests use. What it prints is what the
gateway would actually do to a prompt:

    what the caller sent   ->  what the provider would receive
                           ->  what the caller gets back

The point is the middle line. That is the only text that would ever leave the
network, and it contains no original values.
"""

from __future__ import annotations

import asyncio
import sys
from uuid import uuid4

from app.detection.config import DetectionConfig
from app.detection.engine import PresidioDetector
from app.domain.models import ChatMessage, ProtectedChatRequest
from app.llm.mock_provider import MockProvider
from app.policy.defaults import DEFAULT_POLICY
from app.policy.models import PolicySnapshot
from app.restoration.pipeline import OutputPipeline
from app.tokenization.tokenizer import Tokenizer
from app.vault.fakes import InMemoryTokenVault

PROMPT = (
    "Please email the discharge summary to jordan.rivera@example.com "
    "and copy Dana Whitfield. The member id is HPID-8KD93JF01M and the "
    "record is MRN-40217788. Call 415-555-0142 with questions."
)

RULE = "-" * 78


def _write(line: str = "") -> None:
    # print() is banned by lint in app/; scripts write to stdout directly.
    sys.stdout.write(line + "\n")


async def main() -> int:
    tenant_id, session_id, request_id = uuid4(), uuid4(), uuid4()

    # A policy is normally loaded from PostgreSQL. The shipped default is the
    # same document the seed script writes.
    policy = PolicySnapshot.from_document(
        DEFAULT_POLICY, policy_id=uuid4(), tenant_id=tenant_id, version=1
    )

    detector = PresidioDetector(config=DetectionConfig())
    vault = InMemoryTokenVault()
    tokenizer = Tokenizer(vault=vault)
    output = OutputPipeline(vault=vault)
    provider = MockProvider()

    _write(RULE)
    _write("1. WHAT THE CALLER SENT")
    _write(RULE)
    _write(PROMPT)
    _write()

    entities = await detector.detect(PROMPT, language="en")
    _write(RULE)
    _write(f"2. WHAT THE DETECTOR FOUND ({len(entities)} spans)")
    _write(RULE)
    for entity in sorted(entities, key=lambda e: e.start):
        action = policy.action_for(entity.entity_type)
        threshold = policy.min_score_for(entity.entity_type)
        # A detection below the policy's threshold is discarded, so the value
        # stays in the text that goes to the provider. Show that plainly.
        kept = "kept" if entity.score >= threshold else "BELOW THRESHOLD -> left in place"
        _write(
            f"  {entity.entity_type:<24} score={entity.score:.2f} "
            f"min={threshold:.2f}  action={action.value:<12} {kept}"
        )
    _write()

    transformed = await tokenizer.transform(
        tenant_id=tenant_id,
        session_id=session_id,
        text=PROMPT,
        entities=entities,
        policy=policy,
    )

    _write(RULE)
    _write("3. WHAT THE PROVIDER WOULD RECEIVE  <-- the only text leaving the network")
    _write(RULE)
    _write(transformed.text)
    _write()

    protected = ProtectedChatRequest(
        request_id=request_id,
        tenant_id=tenant_id,
        session_id=session_id,
        provider_alias=provider.alias,
        model_alias="general-chat",
        messages=(ChatMessage(role="user", content=transformed.text),),
        policy_version=policy.version,
    )
    response = await provider.complete(protected)

    restored = await output.restore(
        tenant_id=tenant_id,
        session_id=session_id,
        response=response,
        policy=policy,
    )

    _write(RULE)
    _write("4. WHAT THE CALLER GETS BACK  (tokens resolved from the vault)")
    _write(RULE)
    _write(restored.text)
    _write()

    _write(RULE)
    _write("5. PROOF")
    _write(RULE)
    originals = [PROMPT[e.start : e.end] for e in entities]
    leaked = [value for value in originals if value in transformed.text]
    _write(f"  detected spans:              {len(entities)}")
    _write(f"  tokenized:                   {transformed.summary.tokenized}")
    _write(f"  restored in the response:    {restored.summary.restored}")
    _write(f"  originals in provider text:  {len(leaked)}  <-- must be 0")

    # A token only resolves for its own tenant AND its own session.
    stranger = await output.restore(
        tenant_id=tenant_id,
        session_id=uuid4(),
        response=response,
        policy=policy,
    )
    _write(
        f"  same tokens, other session:  {stranger.summary.restored} restored, ",
    )
    _write(f"                               {stranger.summary.unknown_tokens} unresolvable")
    _write()

    return 1 if leaked else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
