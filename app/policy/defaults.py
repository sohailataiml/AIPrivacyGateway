"""The system default policy.

This is the document the Phase 2 seed script writes for a fresh tenant, and
the reference every test compares against. It is a validated
:class:`~app.policy.models.PolicyDocument` constant, not a dict, so a typo
here fails at import time rather than at the first request.

It is deliberately *not* an implicit runtime fallback. A tenant with no active
policy row is a configuration error, and :class:`~app.policy.service.
PolicyService` fails closed on it rather than quietly applying defaults that
nobody chose.
"""

from __future__ import annotations

from typing import Final

from app.domain.models import EntityAction, UnknownTokenAction
from app.policy.models import (
    POLICY_SCHEMA_VERSION,
    EntityRule,
    PolicyDocument,
    ProviderRule,
)

DEFAULT_POLICY_NAME: Final[str] = "default"

DEFAULT_PROVIDER_ALIAS: Final[str] = "openai-primary"
DEFAULT_MODEL_ALIAS: Final[str] = "general-chat"

DEFAULT_POLICY: Final[PolicyDocument] = PolicyDocument(
    schema_version=POLICY_SCHEMA_VERSION,
    name=DEFAULT_POLICY_NAME,
    session_ttl_seconds=1800,
    max_entities=500,
    providers={DEFAULT_PROVIDER_ALIAS: ProviderRule(models=(DEFAULT_MODEL_ALIAS,))},
    entities={
        # Contactable identifiers: reversible, so the assistant's answer can be
        # restored for the caller who already knows the value.
        "EMAIL_ADDRESS": EntityRule(action=EntityAction.TOKENIZE, min_score=0.7),
        "PHONE_NUMBER": EntityRule(action=EntityAction.TOKENIZE, min_score=0.65),
        # Regulated identifiers: never leave the gateway in any form.
        "US_SSN": EntityRule(action=EntityAction.BLOCK, min_score=0.5),
        "CREDIT_CARD": EntityRule(action=EntityAction.BLOCK, min_score=0.5),
        # Contextual identifiers: higher thresholds, because a false positive
        # here degrades the answer more than it protects anything.
        "PERSON": EntityRule(action=EntityAction.TOKENIZE, min_score=0.75),
        "LOCATION": EntityRule(action=EntityAction.TOKENIZE, min_score=0.8),
    },
    unknown_output_token_action=UnknownTokenAction.PRESERVE,
)
"""The default policy from the implementation plan, section 9."""
