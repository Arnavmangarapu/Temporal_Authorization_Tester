"""Policy oracle and clean-replay checks against independent target behavior."""

import asyncio
import json
import math

import httpx
import pytest
from typer.testing import CliRunner

from document_lab.app import create_app
from document_lab.settings import LabSettings
from temporal_auth.cli import app as cli
from temporal_auth.config import TargetConfig
from temporal_auth.oracles import analyze_run
from temporal_auth.replay import check_lab
from temporal_auth.runner import run_experiment

ENV = {"LAB_ALICE_PASSWORD": "alice-demo-password", "LAB_BOB_PASSWORD": "bob-demo-password", "LAB_RESET_KEY": "local-lab-reset-key"}


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    async def sleep(self, delay):
        # Advance at least one representable tick across replay-relative origins.
        self.now = math.nextafter(self.now + delay, math.inf)
        await asyncio.sleep(0)


def collect(config_data, tmp_path, mode="stale_session"):
    config = TargetConfig.model_validate(config_data)
    async def execute():
        clock = Clock()
        target = create_app(LabSettings(mode=mode), clock=clock)
        async with target.router.lifespan_context(target):
            return await run_experiment(config, tmp_path, environ=ENV, clock=clock,
                sleep=clock.sleep, transport_factory=lambda: httpx.ASGITransport(app=target))
    return config, asyncio.run(execute())


def read_evidence(result):
    report = json.loads((result.directory / "run.json").read_text())
    events = [json.loads(line) for line in (result.directory / "events.jsonl").read_text().splitlines()]
    return report, events


def rewrite(result, report, events):
    (result.directory / "run.json").write_text(json.dumps(report))
    (result.directory / "events.jsonl").write_text("".join(json.dumps(row) + "\n" for row in events))


@pytest.mark.parametrize("mode,verdict", [("immediate", "no_violation_observed"), ("delayed", "no_violation_observed"), ("stale_session", "candidate")])
def test_oracle_classifies_independent_lab_modes(config_data, tmp_path, mode, verdict):
    cfg, result = collect(config_data, tmp_path, mode)
    analysis = analyze_run(cfg, result.directory)
    assert analysis.verdict == verdict, analysis
    if verdict == "candidate":
        assert analysis.kind == "stale_session_access"
        assert analysis.exposed_sessions == ["old"]
    assert json.loads((result.directory / "run.json").read_text())["verdict"] == "not_evaluated"


@pytest.mark.parametrize("status", [403, 500])
def test_status_code_does_not_hide_real_protected_data(config_data, tmp_path, status):
    cfg, result = collect(config_data, tmp_path)
    report, events = read_evidence(result)
    events[-3]["status_code"] = status
    rewrite(result, report, events)
    assert analyze_run(cfg, result.directory).verdict == "candidate"


def test_public_200_without_protected_content_is_not_a_bug(config_data, tmp_path):
    cfg, result = collect(config_data, tmp_path)
    report, events = read_evidence(result)
    events[-3]["response_json"] = {"id": report["bindings"]["document_id"], "public_metadata": "available"}
    rewrite(result, report, events)
    assert analyze_run(cfg, result.directory).verdict == "no_violation_observed"


def test_protected_marker_in_error_text_is_still_disclosure(config_data, tmp_path):
    cfg, result = collect(config_data, tmp_path)
    report, events = read_evidence(result)
    events[-3]["response_json"] = None
    events[-3]["response_text"] = f"Error: {report['bindings']['protected_marker']}"
    events[-3]["status_code"] = 403
    rewrite(result, report, events)
    assert analyze_run(cfg, result.directory).verdict == "candidate"


@pytest.mark.parametrize("change,reason", [
    ("early_probe", "probe_before_deadline"),
    ("failed_control", "control_or_precondition_failed"),
    ("truncated", "incomplete_response"),
    ("missing_event", "request_count_mismatch"),
    ("duplicate_step", "workflow_order_mismatch"),
    ("wrong_session", "event_session_mismatch"),
    ("wrong_resource", "resource_path_mismatch_or_redaction"),
    ("unacknowledged", "revocation_not_acknowledged"),
    ("policy_conflict", "acknowledged_policy_conflict"),
    ("bad_anchor", "timing_anchor_mismatch"),
    ("redacted_marker", "protected_marker_missing_or_redacted"),
    ("incomplete_run", "collection_incomplete"),
    ("invalid_clock", "invalid_event_timing"),
    ("unhealthy_fresh", "uninterpretable_probe"),
])
def test_ambiguous_evidence_never_becomes_a_finding(config_data, tmp_path, change, reason):
    cfg, result = collect(config_data, tmp_path)
    report, events = read_evidence(result)
    by_step = {row["step"]: row for row in events}
    if change == "early_probe": events[-3]["started_elapsed_seconds"] -= 0.01
    elif change == "failed_control": events[-1]["status_code"] = 500
    elif change == "truncated": events[-3]["body_truncated"] = True
    elif change == "missing_event": events.pop()
    elif change == "duplicate_step": events[-2]["step"] = "probe_old_session"
    elif change == "wrong_session": events[-3]["generation"] = events[-2]["generation"]
    elif change == "wrong_resource": events[-3]["path"] = "/documents/another"
    elif change == "unacknowledged": by_step["revoke_access"]["response_json"]["status"] = "pending"
    elif change == "policy_conflict": by_step["revoke_access"]["response_json"]["max_delay_seconds"] = 10
    elif change == "bad_anchor": report["transition_acknowledged_elapsed_seconds"] = -1
    elif change == "redacted_marker": report["bindings"]["protected_marker"] = "protected-[REDACTED]"
    elif change == "incomplete_run": report["status"] = "budget_exhausted"
    elif change == "invalid_clock": events[-3]["finished_elapsed_seconds"] = -1
    elif change == "unhealthy_fresh": events[-2]["status_code"] = 500
    rewrite(result, report, events)
    analysis = analyze_run(cfg, result.directory)
    assert analysis.verdict == "inconclusive"
    assert analysis.reason == reason


def test_unknown_policy_cannot_be_analyzed_as_immediate(config_data, tmp_path):
    cfg, result = collect(config_data, tmp_path)
    config_data["policy"]["timing"] = {"mode": "unknown", "reason": "Not specified"}
    assert analyze_run(TargetConfig.model_validate(config_data), result.directory).reason == "timing_policy_unknown"


def test_different_config_is_not_silently_applied(config_data, tmp_path):
    cfg, result = collect(config_data, tmp_path)
    config_data["budget"]["max_requests"] = 100
    assert analyze_run(TargetConfig.model_validate(config_data), result.directory).reason == "configuration_mismatch"


@pytest.mark.parametrize("kind", ["invalid_json", "duplicate_json_keys", "nan", "missing_file"])
def test_corrupt_evidence_is_inconclusive(config_data, tmp_path, kind):
    cfg, result = collect(config_data, tmp_path)
    path = result.directory / "run.json"
    if kind == "invalid_json": path.write_text("{")
    elif kind == "duplicate_json_keys": path.write_text('{"status":"completed","status":"running"}')
    elif kind == "nan": path.write_text('{"elapsed_seconds":NaN}')
    else: path.unlink()
    assert analyze_run(cfg, result.directory).verdict == "inconclusive"


@pytest.mark.parametrize("mode,verdict,requests", [("immediate", "no_violation_observed", 13), ("delayed", "no_violation_observed", 13), ("stale_session", "confirmed_violation", 39)])
def test_clean_check_confirms_only_reproducible_defect(config_data, tmp_path, mode, verdict, requests):
    async def execute():
        clock = Clock()
        target = create_app(LabSettings(mode=mode), clock=clock)
        async with target.router.lifespan_context(target):
            return await check_lab(TargetConfig.model_validate(config_data), tmp_path, environ=ENV,
                clock=clock, sleep=clock.sleep, transport_factory=lambda: httpx.ASGITransport(app=target))
    result = asyncio.run(execute())
    assert result.report.verdict == verdict, result.report
    assert result.report.total_requests == requests
    assert result.report.fixture_requests == (3 if mode == "stale_session" else 1)
    if mode == "stale_session":
        assert result.report.reproductions == 2
        assert len(result.report.attempts) == 3
        ids = []
        for attempt in result.report.attempts:
            run = json.loads((result.directory / attempt.evidence / "run.json").read_text())
            ids.append(run["bindings"]["document_id"])
        assert len(set(ids)) == 3


@pytest.mark.parametrize("cap", [13, 38])
def test_shared_budget_preserves_candidate_without_false_confirmation(config_data, tmp_path, cap):
    config_data["budget"]["max_requests"] = cap
    async def execute():
        clock = Clock()
        target = create_app(LabSettings(mode="stale_session"), clock=clock)
        async with target.router.lifespan_context(target):
            return await check_lab(TargetConfig.model_validate(config_data), tmp_path, environ=ENV,
                clock=clock, sleep=clock.sleep, transport_factory=lambda: httpx.ASGITransport(app=target))
    result = asyncio.run(execute())
    assert result.report.verdict == "candidate"
    assert result.report.status == "budget_exhausted"
    assert result.report.confirmation == "incomplete"
    assert result.report.total_requests == cap
    assert result.report.reproductions < 2


def test_exact_shared_budget_can_confirm(config_data, tmp_path):
    config_data["budget"]["max_requests"] = 39
    async def execute():
        clock = Clock()
        target = create_app(LabSettings(mode="stale_session"), clock=clock)
        async with target.router.lifespan_context(target):
            return await check_lab(TargetConfig.model_validate(config_data), tmp_path, environ=ENV,
                clock=clock, sleep=clock.sleep, transport_factory=lambda: httpx.ASGITransport(app=target))
    result = asyncio.run(execute())
    assert result.report.verdict == "confirmed_violation"
    assert result.report.total_requests == 39


def test_reset_key_is_required_before_any_request(config_data, tmp_path):
    environ = {key: value for key, value in ENV.items() if key != "LAB_RESET_KEY"}
    result = asyncio.run(check_lab(TargetConfig.model_validate(config_data), tmp_path, environ=environ))
    assert result.report.error_code == "missing_reset_key"
    assert result.report.total_requests == 0


def test_noop_reset_cannot_count_as_clean_reproduction(config_data, tmp_path):
    async def execute():
        clock = Clock()
        target = create_app(LabSettings(mode="stale_session"), clock=clock)
        async with target.router.lifespan_context(target):
            upstream = httpx.ASGITransport(app=target)
            async def handler(request):
                if request.url.path == "/testing/reset":
                    return httpx.Response(200, json={"status": "reset"})
                return await upstream.handle_async_request(request)
            return await check_lab(TargetConfig.model_validate(config_data), tmp_path, environ=ENV,
                clock=clock, sleep=clock.sleep, transport_factory=lambda: httpx.MockTransport(handler))
    result = asyncio.run(execute())
    assert result.report.verdict == "candidate"
    assert result.report.error_code == "reset_not_clean"
    assert result.report.confirmation == "incomplete"


@pytest.mark.parametrize("denied_resets,confirmation,reproductions", [({3}, "flaky", 1), ({2, 3}, "not_reproduced", 0)])
def test_inconsistent_replay_retains_candidate(config_data, tmp_path, denied_resets, confirmation, reproductions):
    async def execute():
        clock = Clock()
        target = create_app(LabSettings(mode="stale_session"), clock=clock)
        resets = 0
        revoked = False
        async with target.router.lifespan_context(target):
            upstream = httpx.ASGITransport(app=target)
            # The last three GETs follow each DELETE: old, fresh, then control.
            post_reads = 0
            async def varying(request):
                nonlocal resets, revoked, post_reads
                if request.url.path == "/testing/reset":
                    resets += 1
                    revoked, post_reads = False, 0
                response = await upstream.handle_async_request(request)
                if request.method == "DELETE": revoked = True
                if revoked and request.method == "GET":
                    post_reads += 1
                    if resets in denied_resets and post_reads == 1:
                        await response.aread()
                        return httpx.Response(403, json={"detail": "denied"})
                return response
            return await check_lab(TargetConfig.model_validate(config_data), tmp_path, environ=ENV,
                clock=clock, sleep=clock.sleep, transport_factory=lambda: httpx.MockTransport(varying))
    result = asyncio.run(execute())
    assert result.report.verdict == "candidate"
    assert result.report.confirmation == confirmation
    assert result.report.reproductions == reproductions


@pytest.mark.parametrize("exposed,kind", [(["fresh"], "fresh_session_access"), (["old", "fresh"], "revocation_enforcement")])
def test_oracle_diagnoses_fresh_and_both_session_disclosure(config_data, tmp_path, exposed, kind):
    cfg, result = collect(config_data, tmp_path)
    report, records = read_evidence(result)
    protected = records[-3]["response_json"]
    records[-2]["response_json"] = protected
    records[-2]["status_code"] = 200
    if exposed == ["fresh"]:
        records[-3]["response_json"] = {"detail": "denied"}
        records[-3]["status_code"] = 403
    rewrite(result, report, records)
    analysis = analyze_run(cfg, result.directory)
    assert analysis.verdict == "candidate"
    assert analysis.exposed_sessions == exposed
    assert analysis.kind == kind


def test_campaign_runtime_is_shared_across_replays(config_data, tmp_path):
    config_data["budget"]["max_runtime_seconds"] = 10
    config_data["budget"]["request_timeout_seconds"] = 1
    async def execute():
        clock = Clock()
        target = create_app(LabSettings(mode="stale_session"), clock=clock)
        async with target.router.lifespan_context(target):
            return await check_lab(TargetConfig.model_validate(config_data), tmp_path, environ=ENV,
                clock=clock, sleep=clock.sleep, transport_factory=lambda: httpx.ASGITransport(app=target))
    result = asyncio.run(execute())
    assert result.report.verdict == "candidate"
    assert result.report.status == "budget_exhausted"
    assert result.report.elapsed_seconds <= 10
    assert result.report.confirmation == "incomplete"


def test_wrong_reset_key_stops_without_workflow_or_credential_leak(config_data, tmp_path):
    async def execute():
        clock = Clock()
        target = create_app(LabSettings(), clock=clock)
        async with target.router.lifespan_context(target):
            return await check_lab(TargetConfig.model_validate(config_data), tmp_path,
                environ={**ENV, "LAB_RESET_KEY": "wrong-private-reset-key"}, clock=clock, sleep=clock.sleep,
                transport_factory=lambda: httpx.ASGITransport(app=target))
    result = asyncio.run(execute())
    assert result.report.verdict == "inconclusive"
    assert result.report.error_code == "reset_not_acknowledged"
    assert result.report.total_requests == 1
    assert not result.report.attempts
    assert "wrong-private-reset-key" not in (result.directory / "events.jsonl").read_text()


def test_unknown_policy_does_not_reset_fixture(config_data, tmp_path):
    config_data["policy"]["timing"] = {"mode": "unknown", "reason": "Not documented"}
    result = asyncio.run(check_lab(TargetConfig.model_validate(config_data), tmp_path, environ=ENV))
    assert result.report.verdict == "inconclusive"
    assert result.report.error_code == "timing_policy_unknown"
    assert result.report.total_requests == 0


def test_check_cancellation_keeps_partial_campaign(config_data, tmp_path):
    async def handler(request):
        raise asyncio.CancelledError
    async def execute():
        with pytest.raises(asyncio.CancelledError):
            await check_lab(TargetConfig.model_validate(config_data), tmp_path, environ=ENV,
                transport_factory=lambda: httpx.MockTransport(handler))
    asyncio.run(execute())
    path, = tmp_path.glob("*/check.json")
    report = json.loads(path.read_text())
    assert report["status"] == "interrupted"
    assert report["total_requests"] == 1


def test_check_cli_requires_explicit_reset_credential(example_path, tmp_path, monkeypatch):
    for name, value in ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("LAB_RESET_KEY")
    result = CliRunner().invoke(cli, ["check", str(example_path), "--output", str(tmp_path)])
    assert result.exit_code == 1
    assert "missing_reset_key" in result.output


def test_analyze_cli_cannot_promote_to_confirmed(example_path, config_data, tmp_path):
    cfg, result = collect(config_data, tmp_path)
    original = (result.directory / "run.json").read_bytes()
    response = CliRunner().invoke(cli, ["analyze", str(example_path), str(result.directory)])
    assert response.exit_code == 4
    assert "candidate" in response.output
    assert (result.directory / "run.json").read_bytes() == original
    assert json.loads((result.directory / "analysis.json").read_text())["verdict"] == "candidate"
