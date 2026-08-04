"""Observability tests.

The assertions here are mostly about what *cannot* get into a metric, because
that is where the risk is. A Prometheus registry is a process-lifetime data
structure with no eviction: a label value drawn from a request is not a leak in
the ordinary sense, it is a permanent one, and enough of them is an outage. So
every recorder is tested for what it refuses as much as for what it counts.

Counters are process-global and accumulate across tests, so nothing here asserts
an absolute value. :func:`sample` reads a series and the tests compare deltas.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from fastapi import FastAPI
from prometheus_client import REGISTRY

from app.api.middleware import MetricsMiddleware, RequestIdMiddleware
from app.config.settings import Settings
from app.detection.entities import EMAIL_ADDRESS, SUPPORTED_ENTITY_TYPES
from app.domain.errors import (
    DetectorUnavailableError,
    EntityLimitExceededError,
    GatewayError,
    ModelNotAllowedError,
    PolicyViolationError,
    ProviderNotAllowedError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)
from app.domain.models import DetectedEntity, EntityAction
from app.main import create_app
from app.observability import metrics as http_metrics
from app.pipeline import metrics as pipeline_metrics
from app.pipeline.stages import DEADLINE_EXCEEDED, PipelineStage
from app.tokenization import metrics as token_metrics

METRICS_TOKEN = "scrape-token-" + "z" * 40


def sample(name: str, **labels: str) -> float:
    """Return one series' current value, or 0.0 if it has never been observed."""
    value = REGISTRY.get_sample_value(name, labels or None)
    return 0.0 if value is None else value


def entity(entity_type: str, *, start: int = 0, end: int = 4) -> DetectedEntity:
    return DetectedEntity(entity_type=entity_type, start=start, end=end, score=0.9)


# ---------------------------------------------------------------------------
# HTTP label folding
# ---------------------------------------------------------------------------
class TestHttpLabels:
    @pytest.mark.parametrize("method", ["GET", "post", "DELETE", "options"])
    def test_a_standard_method_keeps_its_name(self, method: str) -> None:
        assert http_metrics.normalize_method(method) == method.upper()

    @pytest.mark.parametrize("method", ["TRACE", "PROPFIND", "", "GET /etc/passwd", "\x00"])
    def test_an_invented_method_collapses_onto_one_label(self, method: str) -> None:
        """A method is a token in the request line, so it is caller-controlled.
        Without folding, a scanner cycling methods mints a series per attempt."""
        assert http_metrics.normalize_method(method) == http_metrics.METHOD_OTHER

    def test_a_matched_route_is_labelled_by_its_template(self) -> None:
        assert http_metrics.normalize_route("/v1/sessions/{session_id}") == (
            "/v1/sessions/{session_id}"
        )

    @pytest.mark.parametrize("route", [None, ""])
    def test_an_unmatched_route_collapses_onto_one_label(self, route: str | None) -> None:
        assert http_metrics.normalize_route(route) == http_metrics.ROUTE_UNMATCHED

    def test_recording_folds_both_labels_at_the_recorder(self) -> None:
        """Folding lives in ``observe_request``, not at the call site, so a
        caller that forgets to normalise still cannot widen the label space."""
        before = sample(
            "sgw_http_requests_total",
            method=http_metrics.METHOD_OTHER,
            route=http_metrics.ROUTE_UNMATCHED,
            status="404",
        )

        http_metrics.observe_request(
            method="BREW", route=None, status=404, duration_seconds=0.01
        )

        assert (
            sample(
                "sgw_http_requests_total",
                method=http_metrics.METHOD_OTHER,
                route=http_metrics.ROUTE_UNMATCHED,
                status="404",
            )
            == before + 1
        )


class TestInFlightGauge:
    def test_the_gauge_returns_to_its_baseline(self) -> None:
        baseline = sample("sgw_active_requests")

        with http_metrics.track_in_flight():
            assert sample("sgw_active_requests") == baseline + 1

        assert sample("sgw_active_requests") == baseline

    def test_a_failed_request_still_releases_its_slot(self) -> None:
        """A gauge that only counts up reads as permanent saturation, which is
        worse than having no gauge at all."""
        baseline = sample("sgw_active_requests")

        with pytest.raises(RuntimeError), http_metrics.track_in_flight():
            raise RuntimeError("handler blew up")

        assert sample("sgw_active_requests") == baseline


class TestRender:
    def test_the_payload_is_prometheus_text_carrying_every_subsystem(self) -> None:
        """One export surface. Vault, auth, and audit register against the same
        default registry and appear without knowing the endpoint exists."""
        payload, content_type = http_metrics.render()
        text = payload.decode()

        assert "text/plain" in content_type
        assert "sgw_http_requests_total" in text
        assert "sgw_vault_operations_total" in text
        assert "sgw_auth_attempts_total" in text
        assert "sgw_audit_queue_depth" in text


# ---------------------------------------------------------------------------
# Pipeline metrics
# ---------------------------------------------------------------------------
class TestStageMetrics:
    def test_a_successful_stage_is_timed_and_counted(self) -> None:
        before = sample("sgw_pipeline_stage_total", stage="detection", outcome="success")

        with pipeline_metrics.observe_stage(PipelineStage.DETECTION):
            pass

        assert (
            sample("sgw_pipeline_stage_total", stage="detection", outcome="success") == before + 1
        )

    def test_a_failing_stage_is_still_measured(self) -> None:
        """A histogram that only sees successes reports a system as fast at
        exactly the moment it is failing."""
        before = sample("sgw_pipeline_stage_seconds_count", stage="tokenization")
        counted = sample("sgw_pipeline_stage_total", stage="tokenization", outcome="failed")

        with (
            pytest.raises(GatewayError),
            pipeline_metrics.observe_stage(PipelineStage.TOKENIZATION),
        ):
            raise DetectorUnavailableError(log_context={"reason": "stage_failed"})

        assert (
            sample("sgw_pipeline_stage_total", stage="tokenization", outcome="failed")
            == counted + 1
        )
        assert sample("sgw_pipeline_stage_duration_seconds_count", stage="tokenization") >= before

    def test_a_deadline_is_distinguished_from_a_fault(self) -> None:
        """"The detector is down" and "we ran out of time" have different
        remedies, so they must not share a series."""
        before = sample(
            "sgw_pipeline_stage_total", stage="provider", outcome="deadline_exceeded"
        )

        with (
            pytest.raises(GatewayError),
            pipeline_metrics.observe_stage(PipelineStage.PROVIDER),
        ):
            raise ProviderTimeoutError(log_context={"reason": DEADLINE_EXCEEDED})

        assert (
            sample("sgw_pipeline_stage_total", stage="provider", outcome="deadline_exceeded")
            == before + 1
        )

    def test_a_stage_label_must_be_an_enum_member(self) -> None:
        with pytest.raises(TypeError, match="PipelineStage"):
            pipeline_metrics.record_stage(
                stage="detection",  # type: ignore[arg-type]
                outcome=pipeline_metrics.OUTCOME_SUCCESS,
                duration_seconds=0.0,
            )

    def test_an_invented_outcome_is_refused(self) -> None:
        with pytest.raises(ValueError, match="stage outcome"):
            pipeline_metrics.record_stage(
                stage=PipelineStage.POLICY, outcome="mostly-fine", duration_seconds=0.0
            )


class TestRefusalMetrics:
    @pytest.mark.parametrize(
        ("error", "reason"),
        [
            (PolicyViolationError(), pipeline_metrics.REASON_BLOCKED_ENTITY),
            (EntityLimitExceededError(), pipeline_metrics.REASON_ENTITY_LIMIT),
            (ModelNotAllowedError(), pipeline_metrics.REASON_MODEL_NOT_ALLOWED),
            (ProviderNotAllowedError(), pipeline_metrics.REASON_PROVIDER_NOT_ALLOWED),
        ],
    )
    def test_a_refusal_is_counted_under_its_reason(
        self, error: GatewayError, reason: str
    ) -> None:
        before = sample("sgw_policy_blocks_total", reason=reason)

        pipeline_metrics.record_refusal(error)

        assert sample("sgw_policy_blocks_total", reason=reason) == before + 1

    @pytest.mark.parametrize(
        "error",
        [DetectorUnavailableError(), ProviderTimeoutError(), ProviderUnavailableError()],
    )
    def test_a_dependency_failure_is_not_a_policy_block(self, error: GatewayError) -> None:
        """The blocks counter answers "is policy refusing traffic". Folding
        outages into it would make a Redis incident look like a policy change."""
        assert pipeline_metrics.refusal_reason(error) is None

    def test_every_mapped_reason_is_in_the_declared_set(self) -> None:
        """Guards the two lists against drifting apart: a new mapping whose
        reason is not declared would be rejected at record time, in production."""
        mapped = {reason for _error_type, reason in pipeline_metrics._REFUSAL_BY_ERROR}

        assert mapped <= pipeline_metrics.REFUSAL_REASONS


class TestProviderMetrics:
    def test_a_successful_call_is_labelled_by_the_registered_alias(self) -> None:
        before = sample("sgw_provider_requests_total", provider="mock", result="success")

        with pipeline_metrics.observe_provider_call("mock"):
            pass

        assert (
            sample("sgw_provider_requests_total", provider="mock", result="success") == before + 1
        )

    @pytest.mark.parametrize(
        ("error", "result"),
        [
            (ProviderTimeoutError(), pipeline_metrics.PROVIDER_RESULT_TIMEOUT),
            (ProviderUnavailableError(), pipeline_metrics.PROVIDER_RESULT_UNAVAILABLE),
            (GatewayError(), pipeline_metrics.PROVIDER_RESULT_ERROR),
        ],
    )
    def test_a_failure_is_classified_by_exception_type(
        self, error: GatewayError, result: str
    ) -> None:
        before = sample("sgw_provider_requests_total", provider="mock", result=result)

        with pytest.raises(GatewayError), pipeline_metrics.observe_provider_call("mock"):
            raise error

        assert sample("sgw_provider_requests_total", provider="mock", result=result) == before + 1

    def test_an_outside_cancellation_is_its_own_result(self) -> None:
        """The request deadline cancelling a call is not the provider failing;
        confusing the two sends an operator to the wrong dashboard."""
        before = sample("sgw_provider_requests_total", provider="mock", result="cancelled")

        # The real shape of it: the outer deadline cancels the task mid-call.
        with (
            pytest.raises(asyncio.CancelledError),
            pipeline_metrics.observe_provider_call("mock"),
        ):
            raise asyncio.CancelledError

        assert (
            sample("sgw_provider_requests_total", provider="mock", result="cancelled")
            == before + 1
        )

    def test_an_invented_result_is_refused(self) -> None:
        with pytest.raises(ValueError, match="provider result"):
            pipeline_metrics.record_provider_call(
                provider="mock", result="probably-ok", duration_seconds=0.0
            )

    def test_the_model_alias_is_not_a_label(self) -> None:
        """The model reaches the provider stage caller-supplied. Labelling by it
        would let a caller mint series; the audit row records it instead."""
        assert "model" not in pipeline_metrics.PROVIDER_REQUESTS_TOTAL._labelnames
        assert "model" not in pipeline_metrics.PROVIDER_DURATION_SECONDS._labelnames


class TestUnknownTokenMetric:
    def test_unknown_tokens_are_counted(self) -> None:
        before = sample("sgw_restoration_unknown_tokens_total")

        pipeline_metrics.record_unknown_tokens(3)

        assert sample("sgw_restoration_unknown_tokens_total") == before + 3

    def test_a_clean_restoration_records_nothing(self) -> None:
        before = sample("sgw_restoration_unknown_tokens_total")

        pipeline_metrics.record_unknown_tokens(0)

        assert sample("sgw_restoration_unknown_tokens_total") == before


# ---------------------------------------------------------------------------
# Tokenization metrics
# ---------------------------------------------------------------------------
class TestEntityMetrics:
    def test_a_supported_type_keeps_its_name(self) -> None:
        assert token_metrics.normalize_entity_type(EMAIL_ADDRESS) == EMAIL_ADDRESS

    @pytest.mark.parametrize("entity_type", ["INVOICE_NUMBER", "", "jane@example.test"])
    def test_an_unsupported_type_collapses_onto_one_label(self, entity_type: str) -> None:
        """A custom recognizer -- or a policy naming a type the detector never
        produces -- must not be able to add a series per distinct string."""
        assert entity_type not in SUPPORTED_ENTITY_TYPES
        assert token_metrics.normalize_entity_type(entity_type) == token_metrics.ENTITY_TYPE_OTHER

    def test_a_plan_is_counted_by_type_and_action(self) -> None:
        before = sample(
            "sgw_entities_detected_total", entity_type=EMAIL_ADDRESS, action="tokenize"
        )

        token_metrics.record_plan(
            [
                (entity(EMAIL_ADDRESS), EntityAction.TOKENIZE),
                (entity(EMAIL_ADDRESS, start=10, end=14), EntityAction.TOKENIZE),
            ]
        )

        assert (
            sample("sgw_entities_detected_total", entity_type=EMAIL_ADDRESS, action="tokenize")
            == before + 2
        )

    def test_an_action_label_must_be_an_enum_member(self) -> None:
        with pytest.raises(TypeError, match="EntityAction"):
            token_metrics.record_entity(
                entity_type=EMAIL_ADDRESS,
                action="tokenize",  # type: ignore[arg-type]
            )

    def test_no_span_text_is_ever_passed_to_the_recorder(self) -> None:
        """``record_entity`` takes a type and an action. There is no parameter
        it could receive a value through -- which is the point."""
        import inspect

        parameters = set(inspect.signature(token_metrics.record_entity).parameters)

        assert parameters == {"entity_type", "action", "count"}


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------
def build_probe_app() -> FastAPI:
    """A minimal app carrying only the middleware under test."""
    application = FastAPI()

    @application.get("/items/{item_id}")
    async def item(item_id: str) -> dict[str, str]:
        return {"item_id": item_id}

    @application.get("/boom")
    async def boom() -> None:
        raise RuntimeError("handler blew up")

    application.add_middleware(MetricsMiddleware)
    application.add_middleware(RequestIdMiddleware)
    return application


@pytest.fixture
async def probe() -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=build_probe_app(), raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://probe") as client:
        yield client


class TestMetricsMiddleware:
    async def test_path_parameters_do_not_become_labels(self, probe: httpx.AsyncClient) -> None:
        """The single most important assertion in this file. Labelling by
        ``request.url.path`` would mean one series per session id ever
        requested, and session ids are unbounded and caller-supplied."""
        before = sample(
            "sgw_http_requests_total", method="GET", route="/items/{item_id}", status="200"
        )

        for item_id in ("a1", "b2", "c3"):
            assert (await probe.get(f"/items/{item_id}")).status_code == 200

        assert (
            sample(
                "sgw_http_requests_total", method="GET", route="/items/{item_id}", status="200"
            )
            == before + 3
        )
        assert sample("sgw_http_requests_total", method="GET", route="/items/a1", status="200") == 0

    async def test_an_unmatched_path_is_counted_without_being_recorded(
        self, probe: httpx.AsyncClient
    ) -> None:
        before = sample(
            "sgw_http_requests_total",
            method="GET",
            route=http_metrics.ROUTE_UNMATCHED,
            status="404",
        )

        assert (await probe.get("/../../etc/passwd")).status_code == 404

        assert (
            sample(
                "sgw_http_requests_total",
                method="GET",
                route=http_metrics.ROUTE_UNMATCHED,
                status="404",
            )
            == before + 1
        )

    async def test_a_handler_exception_is_counted_as_a_500(
        self, probe: httpx.AsyncClient
    ) -> None:
        """The requests an operator most wants counted are the ones that blew
        up, and those never reach the ``return response`` path."""
        before = sample("sgw_http_requests_total", method="GET", route="/boom", status="500")
        baseline = sample("sgw_active_requests")

        assert (await probe.get("/boom")).status_code == 500

        assert (
            sample("sgw_http_requests_total", method="GET", route="/boom", status="500")
            == before + 1
        )
        assert sample("sgw_active_requests") == baseline


# ---------------------------------------------------------------------------
# GET /metrics
# ---------------------------------------------------------------------------
def scrape_settings(**overrides: object) -> Settings:
    return Settings(app_env="test", **overrides)  # type: ignore[arg-type]


async def scrape_client(settings: Settings) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(settings), raise_app_exceptions=False)
    return httpx.AsyncClient(transport=transport, base_url="http://gateway")


def _without_request_id(response: httpx.Response) -> dict[str, object]:
    error = dict(response.json()["error"])
    error.pop("request_id", None)
    return error


class TestMetricsEndpoint:
    async def test_a_correct_token_is_served(self) -> None:
        client = await scrape_client(scrape_settings(metrics_token=METRICS_TOKEN))
        async with client:
            response = await client.get(
                "/metrics", headers={"Authorization": f"Bearer {METRICS_TOKEN}"}
            )

        assert response.status_code == 200
        assert "sgw_http_requests_total" in response.text

    @pytest.mark.parametrize(
        "headers",
        [
            {},
            {"Authorization": f"Bearer {'q' * 52}"},
            {"Authorization": METRICS_TOKEN},
            {"Authorization": f"Basic {METRICS_TOKEN}"},
            {"Authorization": "Bearer "},
        ],
    )
    async def test_anything_but_the_token_is_refused(self, headers: dict[str, str]) -> None:
        client = await scrape_client(scrape_settings(metrics_token=METRICS_TOKEN))
        async with client:
            response = await client.get("/metrics", headers=headers)

        assert response.status_code == 401
        assert response.json()["error"]["code"] == "AUTHENTICATION_FAILED"

    async def test_a_refusal_does_not_say_which_part_was_wrong(self) -> None:
        """"No token" and "wrong token" answer identically, so the endpoint is
        not an oracle for whether a guess had the right shape."""
        client = await scrape_client(scrape_settings(metrics_token=METRICS_TOKEN))
        async with client:
            missing = await client.get("/metrics")
            wrong = await client.get("/metrics", headers={"Authorization": "Bearer nope"})

        # Everything but the per-request correlation id, which is meant to differ.
        assert missing.status_code == wrong.status_code
        assert _without_request_id(missing) == _without_request_id(wrong)

    async def test_an_unset_token_leaves_a_local_stack_scrapable(self) -> None:
        """Convenience for local work only: production cannot build a Settings
        with metrics enabled and no token."""
        client = await scrape_client(scrape_settings())
        async with client:
            response = await client.get("/metrics")

        assert response.status_code == 200

    async def test_disabling_metrics_removes_the_route_entirely(self) -> None:
        """Absent, not forbidden. A 401 still confirms there are metrics here
        worth asking for."""
        settings = scrape_settings(metrics_enabled=False)
        client = await scrape_client(settings)
        async with client:
            response = await client.get("/metrics")

        assert response.status_code == 404
        assert "/metrics" not in create_app(settings).openapi()["paths"]
