"""Native adapter and orchestration contracts, including adversarial observations."""

from contextlib import contextmanager
import copy
import json
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from typer.testing import CliRunner

from temporal_auth.cli import app
from temporal_auth.integrations.fixtures import Fixture, managed_fixture, checked_command
from temporal_auth.integrations.pilot import (
    PilotBudget, Recorder, analyze_observations, profile_probes, run_pilot,
)
from temporal_auth.integrations.evomaster import recording_proxy


def observed_trace():
    rows = []
    for index, (step, status, body) in enumerate([
        ("read_before", 200, "protected-marker"),
        ("control_before", 200, "protected-marker"),
        ("transition", 200, '{"role":"viewer"}'),
        ("transition_control", 200, '{"role":"viewer"}'),
        ("probe_old", 403, "denied"),
        ("probe_fresh", 404, "denied"),
        ("control_after", 200, "protected-marker"),
    ]):
        rows.append({"step": step, "method": "PATCH" if step == "transition" else "GET",
                     "path": "/api/roles" if step.startswith("transition") else "/api/protected",
                     "status": status, "body": body, "started": index * 2,
                     "finished": index * 2 + 1, "error": None, "truncated": False})
    return rows


def analyze(rows, probes=("old", "fresh")):
    return analyze_observations(rows, "protected-marker", probes, not_before=5.05, read_path="/api/protected")


@pytest.mark.parametrize("status", [200, 403, 500])
def test_disclosure_is_content_based_even_on_error(status):
    rows = observed_trace()
    rows[4].update(status=status, body="protected-marker")
    assert analyze(rows) == {"verdict": "candidate", "exposed_sessions": ["old"], "reason": "protected_content"}


def test_public_metadata_does_not_equal_protected_disclosure():
    rows = observed_trace()
    rows[4].update(status=200, body='{"public":true}')
    assert analyze(rows)["verdict"] == "no_violation_observed"


@pytest.mark.parametrize("mutation", [
    "bad_precontrol", "bad_postcontrol", "missing", "duplicate", "wrong_path",
    "early", "read_before_transition", "control_before_probe", "truncated", "network", "ambiguous500",
    "failed_transition_control", "failed_transition",
])
def test_broken_evidence_never_becomes_a_clean_denial(mutation):
    rows = observed_trace()
    if mutation == "bad_precontrol": rows[1]["body"] = "wrong resource"
    elif mutation == "bad_postcontrol": rows[-1]["status"] = 500
    elif mutation == "missing": rows.pop(4)
    elif mutation == "duplicate": rows.append(copy.deepcopy(rows[4]))
    elif mutation == "wrong_path": rows[4]["path"] = "/api/unrelated"
    elif mutation == "early": rows[4]["started"] = 5.01
    elif mutation == "read_before_transition": rows[0]["finished"] = 5.1
    elif mutation == "control_before_probe": rows[-1]["started"] = 10.1
    elif mutation == "truncated": rows[4]["truncated"] = True
    elif mutation == "network": rows[4]["error"] = "timeout"
    elif mutation == "ambiguous500": rows[4]["status"] = 500
    elif mutation == "failed_transition_control": rows[3]["status"] = 403
    elif mutation == "failed_transition": rows[2]["status"] = 500
    assert analyze(rows)["verdict"] == "inconclusive"


@pytest.mark.parametrize("probes", [[], ["old", "old"], ["other"]])
def test_no_empty_or_unknown_probe_coverage(probes):
    assert analyze(observed_trace(), probes)["verdict"] == "inconclusive"


def test_comparison_profiles_keep_explicit_probe_coverage():
    assert profile_probes("temporal", 0) == ["old", "fresh"]
    assert profile_probes("p4-single-event", 0) == ["fresh"]
    assert profile_probes("p4-single-event", 1) == ["old"]
    assert sorted(profile_probes("generic-valid-order", 19)) == ["fresh", "old"]
    with pytest.raises(ValueError): profile_probes("invented", 0)


@pytest.fixture
def native_mock(monkeypatch):
    """A fake upstream used to test the real PocketBase adapter's boundary.

    These controlled mutations are test doubles, never existing-app findings.
    """
    state = {"attempts": 0, "mode": "correct", "tokens": set()}
    original_client = httpx.Client

    def upstream(request):
        current = state["current"]
        path = request.url.path
        body = json.loads(request.content) if request.content else {}
        auth = request.headers.get("Authorization")
        if path.endswith("/_superusers/auth-with-password"):
            current["owner"] = "owner-token-" + uuid4().hex
            state["tokens"].add(current["owner"])
            state["password"] = body["password"]
            return httpx.Response(200, json={"token": current["owner"]})
        if path == "/api/collections": return httpx.Response(200, json=body)
        if path.endswith("/auth-with-password"):
            token = "session-token-" + uuid4().hex
            current["sessions"][token] = current["role"]
            state["tokens"].add(token)
            return httpx.Response(200, json={"token": token, "record": {"id": current["subject"]}})
        if "/actors_" in path and request.method == "POST":
            return httpx.Response(200, json={"id": current["subject"]})
        if "/documents_" in path and request.method == "POST":
            current["marker"] = body["content"]
            return httpx.Response(200, json={"id": current["resource"]})
        if "/actors_" in path and request.method == "PATCH":
            current["role"] = "editor" if state["mode"] == "noop" else "viewer"
            return httpx.Response(200, json={"id": current["subject"], "role": current["role"]})
        if "/actors_" in path:
            return httpx.Response(200, json={"id": current["subject"], "role": current["role"]})
        if "/documents_" in path:
            allowed = auth == current["owner"] or current["role"] == "editor"
            if state["mode"] == "stale" or (state["mode"] == "flaky" and state["attempts"] == 1):
                allowed |= current["sessions"].get(auth) == "editor"
            return httpx.Response(200 if allowed else 404,
                                  json={"content": current["marker"]} if allowed else {"message": "denied"})
        raise AssertionError("Unexpected native operation")

    def client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(upstream)
        return original_client(*args, **kwargs)
    monkeypatch.setattr(httpx, "Client", client)

    @contextmanager
    def fixture(target, tools, *, budget):
        state["attempts"] += 1
        state["current"] = {"role": "editor", "sessions": {},
                            "subject": uuid4().hex, "resource": uuid4().hex}
        try:
            yield Fixture(target, "http://127.0.0.1:1", "owner@example.test", "bootstrap-secret-password",
                          "0.40.6", 0, 0)
        finally:
            state["closed"] = state.get("closed", 0) + 1
    state["fixture"] = fixture
    return state


def pilot(tmp_path, state, **kwargs):
    return run_pilot("pocketbase", Path("unused"), tmp_path, fixture_factory=state["fixture"], **kwargs)


def test_correct_native_adapter_and_secret_free_evidence(tmp_path, native_mock):
    result = pilot(tmp_path, native_mock)
    assert result.report["status"] == "completed"
    assert result.report["verdict"] == "no_violation_observed"
    assert result.report["total_requests"] == 14
    assert native_mock["attempts"] == native_mock["closed"] == 1
    exported = "\n".join(p.read_text() for p in result.directory.rglob("*") if p.is_file())
    assert native_mock["password"] not in exported
    for token in native_mock["tokens"]: assert token not in exported


def test_confirmation_really_recreates_three_fixtures(tmp_path, native_mock):
    native_mock["mode"] = "stale"
    result = pilot(tmp_path, native_mock)
    assert result.report["verdict"] == "confirmed_violation"
    assert result.report["reproductions"] == 2
    assert result.report["total_requests"] == 42
    assert native_mock["attempts"] == native_mock["closed"] == 3
    attempts = result.report["attempts"]
    assert len({a["marker"] for a in attempts}) == len({a["subject_id"] for a in attempts}) == 3


@pytest.mark.parametrize("mode,verdict,status", [
    ("flaky", "candidate", "completed"), ("noop", "inconclusive", "execution_error"),
])
def test_nonreproducing_or_ineffective_transition_is_not_confirmed(tmp_path, native_mock, mode, verdict, status):
    native_mock["mode"] = mode
    report = pilot(tmp_path, native_mock).report
    assert report["verdict"] == verdict
    assert report["status"] == status
    assert report["reproductions"] == 0
    assert native_mock["closed"] == native_mock["attempts"]


def test_shared_request_cap_includes_failed_confirmation(tmp_path, native_mock):
    native_mock["mode"] = "stale"
    report = pilot(tmp_path, native_mock, max_requests=20).report
    assert report["total_requests"] == 20
    assert report["error"] == "request_budget_exhausted"
    assert report["verdict"] == "candidate"
    assert report["reproductions"] == 0
    assert native_mock["closed"] == 2


@pytest.mark.parametrize("profile,seed,cost", [("p4-single-event", 0, 13),
    ("p4-single-event", 1, 12), ("generic-valid-order", 0, 16)])
def test_baseline_costs_are_actual_requests(tmp_path, native_mock, profile, seed, cost):
    result = pilot(tmp_path, native_mock, profile=profile, seed=seed)
    assert result.report["verdict"] == "no_violation_observed"
    assert result.report["total_requests"] == cost


@pytest.mark.parametrize("kwargs", [{"max_requests": True}, {"max_requests": 0},
    {"max_runtime_seconds": float("nan")}, {"max_runtime_seconds": float("inf")}, {"max_runtime_seconds": 0}])
def test_invalid_budget_does_not_start_a_target(tmp_path, native_mock, kwargs):
    with pytest.raises(ValueError): pilot(tmp_path, native_mock, **kwargs)
    assert native_mock["attempts"] == 0


def test_unknown_cli_target_fails_without_launch(tmp_path):
    result = CliRunner().invoke(app, ["external-check", "unknown", "--output", str(tmp_path)])
    assert result.exit_code == 2
    assert not list(tmp_path.iterdir())


def test_fixture_version_must_match_complete_token(tmp_path, monkeypatch):
    (tmp_path / "pocketbase").write_text("placeholder")
    monkeypatch.setattr("temporal_auth.integrations.fixtures.checked_command", lambda *a, **k: "pocketbase version 0.40.60")
    with pytest.raises(ValueError, match="unexpected_target_version"):
        with managed_fixture("pocketbase", tmp_path): pass


def test_bootstrap_errors_do_not_echo_credentials(tmp_path):
    with pytest.raises(RuntimeError) as caught:
        checked_command(["/nonexistent/secret-password"], cwd=tmp_path)
    assert str(caught.value) == "fixture_bootstrap_failed"


@pytest.mark.network
def test_proxy_preserves_security_methods_headers_and_malformed_bodies(tmp_path, monkeypatch):
    original_client = httpx.Client
    seen = []
    def upstream(request):
        seen.append((request.method, request.content, request.headers.get("Origin")))
        return httpx.Response(204 if request.method == "OPTIONS" else 422,
            content=b"" if request.method in ("OPTIONS", "HEAD") else b"upstream-not-proxy",
            headers={"Access-Control-Allow-Origin": "https://example.test", "Allow": "GET, OPTIONS"})
    def client(*args, **kwargs):
        if kwargs.get("base_url") == "http://upstream": kwargs["transport"] = httpx.MockTransport(upstream)
        return original_client(*args, **kwargs)
    monkeypatch.setattr(httpx, "Client", client)
    recorder = Recorder("http://upstream", PilotBudget(10, 10), tmp_path / "events.jsonl")
    try:
        with recording_proxy(recorder, {}) as origin, original_client(base_url=origin, trust_env=False) as external:
            response = external.request("PATCH", "/api/test", content=b'{"invalid":', headers={"Origin": "https://example.test"})
            assert response.status_code == 422 and response.text == "upstream-not-proxy"
            response = external.options("/api/test", headers={"Origin": "https://example.test"})
            assert response.status_code == 204
            assert response.headers["Access-Control-Allow-Origin"] == "https://example.test"
            assert external.head("/api/test").status_code == 422
    finally:
        recorder.close()
    assert seen[0] == ("PATCH", b'{"invalid":', "https://example.test")
    assert {item[0] for item in seen} == {"PATCH", "OPTIONS", "HEAD"}


@pytest.mark.network
def test_proxy_caps_upstream_requests_without_credential_export(tmp_path, monkeypatch):
    original_client = httpx.Client
    def client(*args, **kwargs):
        if kwargs.get("base_url") == "http://upstream":
            kwargs["transport"] = httpx.MockTransport(lambda request: httpx.Response(200, text="test-token-value"))
        return original_client(*args, **kwargs)
    monkeypatch.setattr(httpx, "Client", client)
    recorder = Recorder("http://upstream", PilotBudget(1, 10), tmp_path / "events.jsonl")
    recorder.redactor.add("test-token-value")
    try:
        with recording_proxy(recorder, {}) as origin, original_client(base_url=origin, trust_env=False) as external:
            assert external.get("/api/test").status_code == 200
            assert external.get("/api/test").status_code == 503
    finally:
        recorder.close()
    assert len(recorder.events) == recorder.budget.requests == 1
    assert "test-token-value" not in (tmp_path / "events.jsonl").read_text()
