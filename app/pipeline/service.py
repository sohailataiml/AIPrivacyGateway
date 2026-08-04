"""The secure pipeline: the one path a chat request may take.

Order is the security control this module exists to enforce, and it is fixed:

1. **Policy.** Resolves the snapshot and authorizes the provider and model. A
   request for a destination the tenant may not reach dies here, having cost one
   cached lookup and having created nothing.
2. **Provider lookup.** The adapter is *looked up*, not called, so an
   unregistered alias fails before any state exists.
3. **Detection.** Every message -- ``system``, ``user``, and ``assistant`` alike.
   An assistant turn replayed from a previous exchange carries exactly the same
   sensitive values as a user turn, so processing only ``user`` would leak the
   conversation back to the provider one round trip later.
4. **Whole-request guards.** Entity budget and blocked types, summed across all
   messages, before the first vault write.
5. **Tokenization.** The only stage that writes to the vault.
6. **Provider.** Reached only through a ``ProtectedChatRequest``, which cannot
   be constructed from anything but the output of step 5.
7. **Restoration**, then **audit**.

Steps 5 and 6 are the load-bearing pair. ``ProtectedChatRequest`` is built from
the tokenizer's output and nothing else, and the tokenizer returns only after
``vault.get_or_create`` has stored every mapping, so "no code path calls the
provider before mappings are persisted" holds by construction rather than by
review: there is no value of any local variable in this module that lets the
provider call happen first.

Nothing here logs message content, an original value, a mapping, or a token.
The only per-request log line carries identifiers and counts.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass
from http import HTTPStatus

from app.config.settings import Settings
from app.domain.errors import (
    DetectorUnavailableError,
    GatewayError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    RestorationError,
    VaultUnavailableError,
)
from app.domain.models import (
    ChatMessage,
    ChatRequest,
    ChatResponse,
    DetectedEntity,
    Principal,
    PrivacySummary,
    ProtectedChatRequest,
    ProviderResponse,
    RequestContext,
)
from app.llm.base import LLMProvider
from app.llm.registry import ProviderRegistry
from app.pipeline.context import (
    DEFAULT_LANGUAGE,
    PipelineAttempt,
    PipelineConfig,
    RequestOutcome,
)
from app.pipeline.guards import (
    Selections,
    enforce_entity_budget,
    enforce_message_sizes,
    entity_budget,
    reject_blocked_entities,
    select_request_entities,
    validate_provider_response,
)
from app.pipeline.protocols import (
    AuditServiceLike,
    DetectorLike,
    OutputPipelineLike,
    PolicyResolverLike,
    RestoredOutputLike,
    TokenizerLike,
)
from app.pipeline.reporting import build_response, log_completion, record_failure, record_outcome
from app.pipeline.session import resolve_session_id
from app.pipeline.stages import PipelineStage, run_stage, stage_failure
from app.policy.models import PolicySnapshot

_POLICY_FAILURE = stage_failure(GatewayError)
_DETECTION_FAILURE = stage_failure(DetectorUnavailableError)
_TOKENIZATION_FAILURE = stage_failure(VaultUnavailableError)
_PROVIDER_FAILURE = stage_failure(ProviderUnavailableError, timeout_type=ProviderTimeoutError)
_RESTORATION_FAILURE = stage_failure(RestorationError)


@dataclass(frozen=True, slots=True)
class _Protected:
    """The provider-ready request and the counts accumulated building it."""

    request: ProtectedChatRequest
    summary: PrivacySummary


@dataclass(frozen=True, slots=True)
class _Completed:
    """A finished request: what the caller gets, and what the audit row gets."""

    response: ChatResponse
    outcome: RequestOutcome


class SecurePipeline:
    """Wires policy, detection, tokenization, the vault, a provider, restoration,
    and audit into one request path.

    Every dependency is injected. The pipeline owns no client, no connection,
    and no cache of its own, so a test exercises the real ordering guarantees
    against in-memory fakes with nothing stubbed out of the path itself.
    """

    __slots__ = (
        "_audit",
        "_config",
        "_detector",
        "_output",
        "_policy",
        "_providers",
        "_semaphore",
        "_settings",
        "_tokenizer",
    )

    def __init__(
        self,
        *,
        policy_service: PolicyResolverLike,
        detector: DetectorLike,
        tokenizer: TokenizerLike,
        provider_registry: ProviderRegistry,
        output_pipeline: OutputPipelineLike,
        audit_service: AuditServiceLike,
        settings: Settings,
        config: PipelineConfig | None = None,
    ) -> None:
        self._policy = policy_service
        self._detector = detector
        self._tokenizer = tokenizer
        self._providers = provider_registry
        self._output = output_pipeline
        self._audit = audit_service
        self._settings = settings
        self._config = config if config is not None else PipelineConfig.from_settings(settings)
        # Created once and shared: a per-request semaphore would bound nothing.
        self._semaphore = asyncio.Semaphore(self._config.max_concurrent_provider_calls)

    async def invoke(self, request: ChatRequest, principal: Principal) -> ChatResponse:
        """Run one chat request end to end.

        Args:
            request: Raw caller input. Its contents reach a provider only after
                detection, policy, tokenization, and a durable vault write.
            principal: The authenticated caller. Supplies the tenant every stage
                is scoped by; nothing tenant-related is read from ``request``.

        Returns:
            The restored response, addressed to this principal alone.

        Raises:
            GatewayError: for every failure. Each one stops the request; none
                of them can be triggered to skip a privacy stage.
        """
        attempt = self._begin(request, principal)
        snapshot: PolicySnapshot | None = None
        try:
            snapshot = await self._resolve_policy(attempt)
            completed = await self._run(request, attempt, snapshot)
        except GatewayError as exc:
            await record_failure(self._audit, attempt=attempt, snapshot=snapshot, error=exc)
            raise
        await record_outcome(
            self._audit,
            attempt=attempt,
            snapshot=snapshot,
            outcome=completed.outcome,
            fail_closed=self._audit_required,
        )
        log_completion(attempt, snapshot, completed.outcome)
        return completed.response

    # -- Admission --------------------------------------------------------
    def _begin(self, request: ChatRequest, principal: Principal) -> PipelineAttempt:
        """Fix the request id, the session id, and the deadline, once."""
        enforce_message_sizes(request.messages, max_chars=self._settings.max_message_chars)
        return PipelineAttempt.begin(
            request=request,
            principal=principal,
            session_id=resolve_session_id(request.session_id),
            clock_now=asyncio.get_running_loop().time(),
            timeout_seconds=self._config.timeout_seconds,
        )

    # -- Stages -----------------------------------------------------------
    async def _resolve_policy(self, attempt: PipelineAttempt) -> PolicySnapshot:
        return await run_stage(
            self._policy.resolve(
                tenant_id=attempt.tenant_id,
                provider=attempt.provider_alias,
                model=attempt.model_alias,
            ),
            stage=PipelineStage.POLICY,
            deadline=attempt.deadline,
            failure=_POLICY_FAILURE,
        )

    async def _run(
        self,
        request: ChatRequest,
        attempt: PipelineAttempt,
        snapshot: PolicySnapshot,
    ) -> _Completed:
        """Everything after the policy resolves, in order."""
        context = attempt.with_policy(snapshot)
        # Lookup only. Constructing a ProtectedChatRequest is still the only way
        # to reach ``complete``, so holding the adapter here calls nothing.
        provider = self._providers.get(attempt.provider_alias)

        detections = await self._detect(request, attempt, snapshot)
        self._guard_request(request, detections, snapshot)
        protected = await self._tokenize(request, context, attempt, snapshot, detections)

        clock = asyncio.get_running_loop()
        started = clock.time()
        provider_response = await self._complete(provider, protected.request, attempt)
        provider_ms = max(int((clock.time() - started) * 1000), 0)

        restored = await self._restore(context, snapshot, provider_response, attempt)
        summary = protected.summary.merged_with(restored.summary)
        return _Completed(
            response=build_response(attempt, restored, summary),
            outcome=RequestOutcome(
                status_code=int(HTTPStatus.OK),
                summary=summary,
                input_character_count=sum(len(message.content) for message in request.messages),
                output_character_count=len(restored.text),
                provider_latency_ms=provider_ms,
                pipeline_latency_ms=attempt.elapsed_ms(clock.time()),
            ),
        )

    async def _detect(
        self,
        request: ChatRequest,
        attempt: PipelineAttempt,
        snapshot: PolicySnapshot,
    ) -> tuple[tuple[DetectedEntity, ...], ...]:
        """Detect over every message, whatever its role.

        The detector is deliberately *not* restricted to the policy's configured
        types. Narrowing the request to ``snapshot.entity_types`` would mean a
        sensitive type the detector supports but the policy has not listed is
        never reported at all -- and ``action_for``'s protective default for an
        unconfigured type could then never fire, because no such entity would
        ever reach it. Detecting the full supported set and letting policy
        decide keeps that default meaningful. The detector already filters its
        own output to the architecture's supported entity list, so this asks for
        a bounded superset, not everything imaginable.
        """
        results: list[tuple[DetectedEntity, ...]] = []
        for message in request.messages:
            entities = await run_stage(
                self._detector.detect(
                    message.content,
                    language=DEFAULT_LANGUAGE,
                    requested_entities=None,
                ),
                stage=PipelineStage.DETECTION,
                deadline=attempt.deadline,
                failure=_DETECTION_FAILURE,
            )
            results.append(tuple(entities))
        return tuple(results)

    def _guard_request(
        self,
        request: ChatRequest,
        detections: Sequence[Sequence[DetectedEntity]],
        snapshot: PolicySnapshot,
    ) -> None:
        """Enforce the budget and the block list across the whole request."""
        selections: Selections = select_request_entities(
            messages=request.messages, detections=detections, policy=snapshot
        )
        enforce_entity_budget(
            selections,
            budget=entity_budget(
                policy=snapshot,
                deployment_max_entities=self._settings.max_entities_per_request,
            ),
        )
        reject_blocked_entities(selections, policy=snapshot)

    async def _tokenize(
        self,
        request: ChatRequest,
        context: RequestContext,
        attempt: PipelineAttempt,
        snapshot: PolicySnapshot,
        detections: Sequence[Sequence[DetectedEntity]],
    ) -> _Protected:
        """Protect every message under one session, then build the provider request.

        Returns only after every mapping this request creates is in the vault.
        """
        messages: list[ChatMessage] = []
        summary = PrivacySummary()
        for message, entities in zip(request.messages, detections, strict=True):
            transformed = await run_stage(
                self._tokenizer.transform(
                    tenant_id=context.principal.tenant_id,
                    session_id=context.session_id,
                    text=message.content,
                    entities=entities,
                    policy=snapshot,
                ),
                stage=PipelineStage.TOKENIZATION,
                deadline=attempt.deadline,
                failure=_TOKENIZATION_FAILURE,
            )
            messages.append(ChatMessage(role=message.role, content=transformed.text))
            summary = summary.merged_with(transformed.summary)

        return _Protected(
            request=ProtectedChatRequest(
                request_id=context.request_id,
                tenant_id=context.principal.tenant_id,
                session_id=context.session_id,
                provider_alias=request.provider,
                model_alias=request.model,
                messages=tuple(messages),
                policy_version=snapshot.version,
                temperature=request.temperature,
                max_output_tokens=request.max_output_tokens,
            ),
            summary=summary,
        )

    async def _complete(
        self,
        provider: LLMProvider,
        protected: ProtectedChatRequest,
        attempt: PipelineAttempt,
    ) -> ProviderResponse:
        """Call the provider under the concurrency bound and the deadline."""
        response = await run_stage(
            self._bounded_complete(provider, protected),
            stage=PipelineStage.PROVIDER,
            deadline=attempt.deadline,
            failure=_PROVIDER_FAILURE,
        )
        return validate_provider_response(response)

    async def _bounded_complete(
        self, provider: LLMProvider, protected: ProtectedChatRequest
    ) -> ProviderResponse:
        # Acquired inside the deadline: waiting for a slot is part of the
        # request's budget, not additional to it.
        async with self._semaphore:
            return await provider.complete(protected)

    async def _restore(
        self,
        context: RequestContext,
        snapshot: PolicySnapshot,
        response: ProviderResponse,
        attempt: PipelineAttempt,
    ) -> RestoredOutputLike:
        return await run_stage(
            self._output.restore(
                tenant_id=context.principal.tenant_id,
                session_id=context.session_id,
                response=response,
                policy=snapshot,
            ),
            stage=PipelineStage.RESTORATION,
            deadline=attempt.deadline,
            failure=_RESTORATION_FAILURE,
        )

    @property
    def _audit_required(self) -> bool:
        return self._settings.audit_fail_closed
