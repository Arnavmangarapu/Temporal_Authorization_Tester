"""Runner integration and fault checks; no security-oracle verdict assertions."""

import asyncio
from contextlib import asynccontextmanager
import json

import httpx
import pytest
from typer.testing import CliRunner

from document_lab.app import create_app
from document_lab.settings import LabSettings
from temporal_auth.cli import app as cli
from temporal_auth.config import TargetConfig
from temporal_auth.runner import run_experiment
from temporal_auth.runner.engine import MAX_RESPONSE_BYTES, json_pointer
from temporal_auth.runner.evidence import RequestEvent, RunReport

PASSWORDS = {"LAB_ALICE_PASSWORD": "alice-demo-password", "LAB_BOB_PASSWORD": "bob-demo-password"}


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    async def sleep(self, delay):
        self.now += delay
        await asyncio.sleep(0)


def events(result):
    return [json.loads(line) for line in (result.directory / "events.jsonl").read_text().splitlines()]


@asynccontextmanager
async def lab(mode="immediate"):
    clock = Clock()
    target = create_app(LabSettings(mode=mode), clock=clock)
    async with target.router.lifespan_context(target):
        yield clock, lambda: httpx.ASGITransport(app=target)


@pytest.mark.parametrize("mode,old_status", [("immediate", 403), ("delayed", 403), ("stale_session", 200)])
def test_runner_collects_all_modes_with_distinct_sessions(config_data, tmp_path, mode, old_status):
    async def check():
        async with lab(mode) as (clock, transport):
            result = await run_experiment(TargetConfig.model_validate(config_data), tmp_path,
                environ=PASSWORDS, clock=clock, sleep=clock.sleep, transport_factory=transport)
        assert result.report.status == "completed"
        assert result.report.verdict == "not_evaluated"
        assert result.report.request_count == 12
        rows = events(result)
        assert len(rows) == 12
        by_step = {row["step"]: row for row in rows}
        assert by_step["probe_old_session"]["status_code"] == old_status
        assert by_step["probe_fresh_session"]["status_code"] == 403
        assert by_step["control_after_revoke"]["status_code"] == 200
        old = by_step["probe_old_session"]
        fresh = by_step["probe_fresh_session"]
        assert old["actor"] == fresh["actor"] == "bob"
        assert old["generation"] != fresh["generation"]
        assert old["started_elapsed_seconds"] >= result.report.probe_not_before_elapsed_seconds
        assert result.report.bindings["document_id"] in old["path"]
        for row in rows:
            RequestEvent.model_validate(row)
            assert row["finished_elapsed_seconds"] >= row["started_elapsed_seconds"]
        persisted = RunReport.model_validate_json((result.directory / "run.json").read_text())
        assert persisted.status == "completed"
        text = (result.directory / "events.jsonl").read_text()
        for password in PASSWORDS.values():
            assert password not in text
        for row in rows:
            if row["step"].startswith("login_"):
                assert "access_token" not in row["response_json"]
        assert result.directory.stat().st_mode & 0o777 == 0o700
        assert (result.directory / "run.json").stat().st_mode & 0o777 == 0o600
    asyncio.run(check())


def test_missing_credentials_fails_before_http(config_data, tmp_path):
    def never_called(request):
        pytest.fail("Target must not be contacted")
    result = asyncio.run(run_experiment(TargetConfig.model_validate(config_data), tmp_path,
        environ={}, transport_factory=lambda: httpx.MockTransport(never_called)))
    assert result.report.status == "setup_failed"
    assert result.report.error_code == "missing_credentials"
    assert result.report.request_count == 0
    assert events(result) == []


def test_returned_identity_overlap_stops_before_creating_a_resource(config_data, tmp_path):
    def handler(request):
        assert request.url.path == "/auth/login"
        return httpx.Response(200, json={"user_id": "same-account", "access_token": "private-session-token"})
    result = asyncio.run(run_experiment(TargetConfig.model_validate(config_data), tmp_path,
        environ=PASSWORDS, transport_factory=lambda: httpx.MockTransport(handler)))
    assert result.report.status == "setup_failed"
    assert result.report.error_code == "actor_identity_overlap"
    assert result.report.request_count == 2


def test_resource_owner_binding_is_verified(config_data, tmp_path):
    async def check():
        clock = Clock()
        target = create_app(LabSettings(), clock=clock)
        async with target.router.lifespan_context(target):
            upstream = httpx.ASGITransport(app=target)
            async def handler(request):
                response = await upstream.handle_async_request(request)
                if request.method == "POST" and request.url.path == "/documents":
                    await response.aread()
                    data = response.json()
                    data["owner_id"] = "wrong-owner"
                    return httpx.Response(201, json=data)
                return response
            result = await run_experiment(TargetConfig.model_validate(config_data), tmp_path,
                environ=PASSWORDS, clock=clock, sleep=clock.sleep,
                transport_factory=lambda: httpx.MockTransport(handler))
        assert result.report.status == "setup_failed"
        assert result.report.error_code == "resource_owner_mismatch"
        assert result.report.request_count == 3
    asyncio.run(check())


def test_unknown_policy_is_not_treated_as_zero_delay(config_data, tmp_path):
    config_data["policy"]["timing"] = {"mode": "unknown", "reason": "No bound available"}
    result = asyncio.run(run_experiment(TargetConfig.model_validate(config_data), tmp_path, environ={}))
    assert result.report.status == "policy_unknown"
    assert result.report.request_count == 0
    assert result.report.probe_not_before_elapsed_seconds is None


@pytest.mark.parametrize("path", ["/documents/{unknown}", "/documents/{document_id!r}", "/documents/{document_id:>5}", "/documents/{"])
def test_unsupported_binding_is_rejected_before_execution(config_data, tmp_path, path):
    config_data["operations"]["read_document"]["path"] = path
    result = asyncio.run(run_experiment(TargetConfig.model_validate(config_data), tmp_path, environ=PASSWORDS))
    assert result.report.status == "setup_failed"
    assert result.report.error_code == "unsupported_adapter_config"
    assert result.report.request_count == 0


@pytest.mark.parametrize("cap", [1, 8, 9, 11])
def test_request_budget_stops_without_extra_requests(config_data, tmp_path, cap):
    config_data["budget"]["max_requests"] = cap
    async def check():
        async with lab() as (clock, transport):
            result = await run_experiment(TargetConfig.model_validate(config_data), tmp_path,
                environ=PASSWORDS, clock=clock, sleep=clock.sleep, transport_factory=transport)
        assert result.report.status == "budget_exhausted"
        assert result.report.error_code == "request_budget_exhausted"
        assert result.report.request_count == len(events(result)) == cap
    asyncio.run(check())


def test_exact_request_budget_can_complete(config_data, tmp_path):
    config_data["budget"]["max_requests"] = 12
    async def check():
        async with lab() as (clock, transport):
            result = await run_experiment(TargetConfig.model_validate(config_data), tmp_path,
                environ=PASSWORDS, clock=clock, sleep=clock.sleep, transport_factory=transport)
        assert result.report.status == "completed"
    asyncio.run(check())


def test_tokens_passwords_and_cookies_are_isolated_and_not_exported(config_data, tmp_path):
    async def check():
        clock = Clock()
        target = create_app(LabSettings(mode="stale_session"), clock=clock)
        captured_tokens = []
        captured_requests = []
        async with target.router.lifespan_context(target):
            upstream = httpx.ASGITransport(app=target)
            async def handler(request):
                captured_requests.append((request.url.path, request.headers.get("authorization"), request.headers.get("cookie")))
                response = await upstream.handle_async_request(request)
                await response.aread()
                data = response.json()
                if request.url.path == "/auth/login":
                    captured_tokens.append(data["access_token"])
                    return httpx.Response(response.status_code, json=data,
                        headers={"set-cookie": f"session_generation={len(captured_tokens)}; Path=/"})
                if isinstance(data, dict):
                    data["debug_echo"] = f"{PASSWORDS['LAB_ALICE_PASSWORD']} {captured_tokens[-1]}"
                return httpx.Response(response.status_code, json=data)
            result = await run_experiment(TargetConfig.model_validate(config_data), tmp_path,
                environ=PASSWORDS, clock=clock, sleep=clock.sleep,
                transport_factory=lambda: httpx.MockTransport(handler))
        assert result.report.status == "completed"
        text = "\n".join(path.read_text() for path in result.directory.glob("*.json*"))
        for secret in [*PASSWORDS.values(), *captured_tokens]:
            assert secret not in text
        login_requests = [entry for entry in captured_requests if entry[0] == "/auth/login"]
        assert all(auth is None and cookie is None for _, auth, cookie in login_requests)
        old, fresh, control = captured_requests[-3:]
        assert old[1] != fresh[1]
        assert old[2] == "session_generation=3"
        assert fresh[2] == "session_generation=4"
        assert control[2] == "session_generation=1"
        assert not any(path == "/testing/reset" for path, _, _ in captured_requests)
    asyncio.run(check())


def test_setup_requires_actual_protected_content_before_revocation(config_data, tmp_path):
    async def check():
        clock = Clock()
        target = create_app(LabSettings(), clock=clock)
        paths = []
        async with target.router.lifespan_context(target):
            upstream = httpx.ASGITransport(app=target)
            async def handler(request):
                paths.append((request.method, request.url.path))
                if request.method == "GET":
                    return httpx.Response(200, json={"public_metadata": "available"})
                return await upstream.handle_async_request(request)
            result = await run_experiment(TargetConfig.model_validate(config_data), tmp_path,
                environ=PASSWORDS, clock=clock, sleep=clock.sleep,
                transport_factory=lambda: httpx.MockTransport(handler))
        assert result.report.status == "setup_failed"
        assert result.report.error_code == "protected_marker_not_established"
        assert all(method != "DELETE" for method, _ in paths)
    asyncio.run(check())


def test_setup_cost_can_leave_insufficient_time_for_probe(config_data, tmp_path):
    config_data["budget"]["max_runtime_seconds"] = 5.2
    config_data["budget"]["request_timeout_seconds"] = 1
    async def check():
        clock = Clock()
        target = create_app(LabSettings(), clock=clock)
        async with target.router.lifespan_context(target):
            upstream = httpx.ASGITransport(app=target)
            async def handler(request):
                if request.method == "DELETE":
                    clock.now += 2
                return await upstream.handle_async_request(request)
            result = await run_experiment(TargetConfig.model_validate(config_data), tmp_path,
                environ=PASSWORDS, clock=clock, sleep=clock.sleep,
                transport_factory=lambda: httpx.MockTransport(handler))
        assert result.report.status == "budget_exhausted"
        assert result.report.error_code == "insufficient_time_for_probe"
        assert not any(row["step"].startswith("probe_") for row in events(result))
    asyncio.run(check())


def test_each_run_creates_its_own_evidence_directory(config_data, tmp_path):
    cfg = TargetConfig.model_validate(config_data)
    first = asyncio.run(run_experiment(cfg, tmp_path, environ={}))
    second = asyncio.run(run_experiment(cfg, tmp_path, environ={}))
    assert first.directory != second.directory
    assert (first.directory / "run.json").exists()
    assert (second.directory / "run.json").exists()


@pytest.mark.parametrize("body", [b'{"value": NaN}', b'{"value": 1e999}'])
def test_invalid_json_numbers_do_not_break_evidence_serialization(config_data, tmp_path, body):
    result = asyncio.run(run_experiment(TargetConfig.model_validate(config_data), tmp_path,
        environ=PASSWORDS, transport_factory=lambda: httpx.MockTransport(lambda _: httpx.Response(200, content=body))))
    assert result.report.status == "setup_failed"
    assert result.report.error_code == "invalid_response_binding"
    assert (result.directory / "run.json").exists()


@pytest.mark.parametrize("response,code", [
    (httpx.Response(401, json={"detail": "bad credentials"}), "setup_http_status"),
    (httpx.Response(200, text="not JSON"), "invalid_response_binding"),
    (httpx.Response(200, json={"user_id": "bob"}), "invalid_login_token"),
])
def test_bad_login_is_not_a_successful_experiment(config_data, tmp_path, response, code):
    result = asyncio.run(run_experiment(TargetConfig.model_validate(config_data), tmp_path,
        environ=PASSWORDS, transport_factory=lambda: httpx.MockTransport(lambda _: response)))
    assert result.report.status == "setup_failed"
    assert result.report.error_code == code
    assert result.report.request_count == 1


def test_redirect_does_not_forward_credentials_or_follow_target(config_data, tmp_path):
    seen = []
    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(307, headers={"location": "http://other.invalid/login"})
    result = asyncio.run(run_experiment(TargetConfig.model_validate(config_data), tmp_path,
        environ=PASSWORDS, transport_factory=lambda: httpx.MockTransport(handler)))
    assert result.report.status == "setup_failed"
    assert len(seen) == 1
    assert "other.invalid" not in seen[0]


def test_transport_error_is_recorded_without_exception_contents(config_data, tmp_path):
    def handler(request):
        raise httpx.ConnectError("sensitive-private-error-detail", request=request)
    result = asyncio.run(run_experiment(TargetConfig.model_validate(config_data), tmp_path,
        environ=PASSWORDS, transport_factory=lambda: httpx.MockTransport(handler)))
    assert result.report.error_code == "transport_error"
    assert events(result)[0]["error_code"] == "transport_error"
    assert "sensitive-private-error-detail" not in (result.directory / "events.jsonl").read_text()


def test_oversized_response_is_bounded_and_incomplete(config_data, tmp_path):
    result = asyncio.run(run_experiment(TargetConfig.model_validate(config_data), tmp_path,
        environ=PASSWORDS, transport_factory=lambda: httpx.MockTransport(
            lambda _: httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1)))))
    assert result.report.status == "execution_error"
    assert result.report.error_code == "response_too_large"
    assert events(result)[0]["body_truncated"] is True


def test_absolute_request_deadline_cancels_slow_transport(config_data, tmp_path):
    config_data["budget"]["request_timeout_seconds"] = 0.02
    async def handler(request):
        await asyncio.sleep(5)
        pytest.fail("Timed-out transport must not complete")
    result = asyncio.run(run_experiment(TargetConfig.model_validate(config_data), tmp_path,
        environ=PASSWORDS, transport_factory=lambda: httpx.MockTransport(handler)))
    assert result.report.status == "execution_error"
    assert result.report.error_code == "request_deadline_exceeded"
    assert result.report.request_count == 1


def test_global_budget_cancels_in_flight_request(config_data, tmp_path):
    config_data["policy"]["timing"]["max_delay_seconds"] = 0
    config_data["policy"]["timing"]["tolerance_seconds"] = 0
    config_data["budget"]["max_runtime_seconds"] = 0.02
    config_data["budget"]["request_timeout_seconds"] = 0.02
    async def handler(request):
        await asyncio.sleep(5)
    result = asyncio.run(run_experiment(TargetConfig.model_validate(config_data), tmp_path,
        environ=PASSWORDS, transport_factory=lambda: httpx.MockTransport(handler)))
    assert result.report.status == "budget_exhausted"
    assert result.report.error_code == "runtime_budget_exhausted"
    assert result.report.elapsed_seconds < 1


def test_short_password_does_not_corrupt_report_schema(config_data, tmp_path):
    environ = {"LAB_ALICE_PASSWORD": "a", "LAB_BOB_PASSWORD": "b"}
    result = asyncio.run(run_experiment(TargetConfig.model_validate(config_data), tmp_path,
        environ=environ, transport_factory=lambda: httpx.MockTransport(lambda _: httpx.Response(401))))
    report = RunReport.model_validate_json((result.directory / "run.json").read_text())
    assert report.status == "setup_failed"
    assert report.verdict == "not_evaluated"


def test_cancelled_run_persists_partial_evidence(config_data, tmp_path):
    async def handler(request):
        raise asyncio.CancelledError
    async def check():
        with pytest.raises(asyncio.CancelledError):
            await run_experiment(TargetConfig.model_validate(config_data), tmp_path,
                environ=PASSWORDS, transport_factory=lambda: httpx.MockTransport(handler))
    asyncio.run(check())
    report_file, = tmp_path.glob("*/run.json")
    report = RunReport.model_validate_json(report_file.read_text())
    assert report.status == "interrupted"
    assert report.request_count == 1
    assert json.loads((report_file.parent / "events.jsonl").read_text())["outcome"] == "interrupted"


def test_cli_missing_password_returns_nonzero_and_report(example_path, tmp_path, monkeypatch):
    for variable in PASSWORDS:
        monkeypatch.delenv(variable, raising=False)
    result = CliRunner().invoke(cli, ["run", str(example_path), "--output", str(tmp_path)])
    assert result.exit_code == 1
    assert "missing_credentials" in result.output
    assert "not_evaluated" in result.output
    report_file, = tmp_path.glob("*/run.json")
    assert json.loads(report_file.read_text())["request_count"] == 0


@pytest.mark.parametrize("data,pointer,expected", [
    ({"a/b": {"~key": ["token"]}}, "/a~1b/~0key/0", "token"),
    ({"content": "marker"}, "/content", "marker"),
])
def test_json_pointer_handles_escaped_fields_and_arrays(data, pointer, expected):
    assert json_pointer(data, pointer) == expected


@pytest.mark.parametrize("pointer", ["/-1", "/01", "/missing"])
def test_json_pointer_does_not_accept_negative_or_ambiguous_array_indices(pointer):
    with pytest.raises((KeyError, IndexError)):
        json_pointer(["value"], pointer)
