"""Local web contracts, durable jobs, evidence boundaries and actual worker execution."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import io
import json
import os
from pathlib import Path
import signal
import time
import zipfile

from fastapi.testclient import TestClient
import pytest
from pydantic import ValidationError
import yaml

from temporal_auth.integrations.pilot import PilotBudget
from temporal_auth.web.app import create_app
from temporal_auth.web.evidence import export_bundle, inspect_evidence
from temporal_auth.web.execution import cancellable
from temporal_auth.web.models import JobSpec, lab_config, preview
from temporal_auth.web.store import Store


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path / "web", tmp_path / "tools", start_worker=False)
    with TestClient(app, base_url="http://localhost") as browser:
        browser.headers["X-CSRF-Token"] = app.state.csrf
        yield browser


@pytest.mark.parametrize("path,text", [("/", "Start with a permission change"), ("/new", "Build an experiment"),
    ("/?view=findings", "No findings to review"), ("/static/workspace.js", "X-CSRF-Token")])
def test_web_pages_and_local_assets(client, path, text):
    response = client.get(path)
    assert response.status_code == 200
    assert text in response.text
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"


def test_host_origin_and_csrf_boundary(client):
    assert client.get("/", headers={"Host": "rebinding.example"}).status_code == 400
    client.headers.pop("X-CSRF-Token")
    assert client.post("/api/jobs", json={}).status_code == 403
    client.headers["X-CSRF-Token"] = client.app.state.csrf
    for headers in ({"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"}):
        assert client.post("/api/jobs", json={}, headers=headers).status_code == 403


def test_validation_is_read_only_and_does_not_need_demo_secrets(client):
    response = client.post("/api/validate", json={})
    assert response.status_code == 200
    assert response.json()["missing_credentials"] == []
    assert client.get("/api/jobs").json() == []


@pytest.mark.parametrize("payload", [{"target": "other"}, {"title": "  "}, {"password": "top-secret"},
    {"max_requests": 0}, {"max_requests": True}, {"max_runtime_seconds": 0},
    {"target": "gitea", "action": "write"}, {"profile": "p4-single-event"},
    {"target": "configured_lab", "config_yaml": "password: top-secret", "reset_authorized": True}])
def test_invalid_browser_inputs_do_not_queue_or_echo_secrets(client, payload):
    response = client.post("/api/jobs", json=payload)
    assert response.status_code == 422
    assert "top-secret" not in response.text
    assert client.get("/api/jobs").json() == []


def test_request_body_limit(client):
    assert client.post("/api/jobs", content=b"x"*100001).status_code == 413


def test_durable_queue_cancel_replay_and_terminal_export(client):
    response = client.post("/api/jobs", json={"title": "My test"})
    assert response.status_code == 202
    identifier = response.json()["id"]
    assert client.get(response.json()["url"]).status_code == 200
    assert client.get(f"/runs/{identifier}/download").status_code == 409
    assert client.post(f"/api/jobs/{identifier}/replay").status_code == 409
    assert client.post(f"/api/jobs/{identifier}/cancel").json()["status"] == "cancelled"
    assert client.post(f"/api/jobs/{identifier}/replay").status_code == 202
    bundle = client.get(f"/runs/{identifier}/download")
    assert bundle.status_code == 200
    with zipfile.ZipFile(io.BytesIO(bundle.content)) as archive:
        assert {"replay.json", "replay.py", "README.txt", "job.json"} <= set(archive.namelist())
        assert "execute_spec" in archive.read("replay.py").decode()


def test_missing_native_tools_are_actionable(client):
    response = client.post("/api/jobs", json={"target": "gitea"})
    assert response.status_code == 422
    assert "fetch_pilot_tools.py" in response.json()["detail"]


@pytest.mark.parametrize("path", ["/runs/not-a-uuid", "/api/jobs/00000000-0000-0000-0000-000000000000", "/runs/%2e%2e/download"])
def test_unknown_ids_and_traversal_are_not_filesystem_access(client, path):
    assert client.get(path).status_code == 404


@pytest.mark.parametrize("lifecycle", ["sharing_revocation", "role_downgrade", "ownership_transfer"])
@pytest.mark.parametrize("action", ["read", "write"])
def test_guided_configs_preserve_all_six_lab_contracts(lifecycle, action):
    spec = JobSpec(lifecycle=lifecycle, action=action)
    cfg = lab_config(spec)
    assert cfg.policy.lifecycle == lifecycle and cfg.policy.action == action
    assert preview(spec, {})["valid"]


def test_configured_lab_requires_reset_permission_loopback_and_secret_refs():
    data = lab_config(JobSpec(action="write", lifecycle="role_downgrade")).model_dump(mode="json")
    valid = dict(target="configured_lab", reset_authorized=True, config_yaml=yaml.safe_dump(data))
    spec = JobSpec(**valid)
    assert spec.lifecycle == "role_downgrade" and spec.action == "write"
    assert preview(spec, {})["missing_credentials"] == ["LAB_ALICE_PASSWORD", "LAB_BOB_PASSWORD", "LAB_RESET_KEY"]
    with pytest.raises(ValidationError): JobSpec(**{**valid, "reset_authorized": False})
    data["base_url"] = "http://outside.example"
    with pytest.raises(ValidationError): JobSpec(**{**valid, "config_yaml": yaml.safe_dump(data)})


def test_unknown_timing_needs_no_credentials_and_makes_no_validation_requests():
    data = lab_config(JobSpec()).model_dump(mode="json")
    data["policy"]["timing"] = {"mode": "unknown", "reason": "No bound established"}
    spec = JobSpec(target="configured_lab", reset_authorized=True, config_yaml=yaml.safe_dump(data))
    info = preview(spec, {})
    assert not info["missing_credentials"] and "unknown" in info["notice"]


def test_sqlite_claim_is_exclusive_and_restart_preserves_queued_jobs(tmp_path):
    store = Store(tmp_path)
    identifiers = {store.create(JobSpec(title=f"Experiment {n}")) for n in range(6)}
    with ThreadPoolExecutor(6) as pool:
        claims = list(pool.map(lambda _: Store(tmp_path).claim(), range(6)))
    assert {job["id"] for job in claims} == identifiers
    queued = store.create(JobSpec())
    store.interrupt_unfinished()
    assert all(store.get(identifier)["status"] == "interrupted" for identifier in identifiers)
    assert Store(tmp_path).get(queued)["status"] == "queued"


def test_cancel_wins_finish_race_without_discarding_observation(tmp_path):
    store = Store(tmp_path)
    identifier = store.create(JobSpec())
    store.claim()
    store.cancel(identifier)
    store.finish(identifier, "completed", {"verdict": "candidate", "requests": 13})
    job = store.get(identifier)
    assert job["status"] == "cancelled" and job["result"]["verdict"] == "candidate"


def test_queue_limit(tmp_path):
    store = Store(tmp_path)
    for _ in range(20): store.create(JobSpec())
    with pytest.raises(ValueError): store.create(JobSpec())


def test_supervisor_recovery_is_scoped_to_its_worker(tmp_path):
    store = Store(tmp_path)
    first = store.create(JobSpec())
    second = store.create(JobSpec())
    store.claim(owner_pid=101)
    store.claim(owner_pid=202)
    store.interrupt_unfinished(owner_pid=303)
    assert store.get(first)["status"] == store.get(second)["status"] == "running"
    store.interrupt_unfinished(owner_pid=101)
    assert store.get(first)["status"] == "interrupted"
    assert store.get(second)["status"] == "running"


def test_partial_candidate_retained_and_evidence_html_escaped(client):
    identifier = client.post("/api/jobs", json={"title": "<script>window.bad=true</script>"}).json()["id"]
    store = client.app.state.store
    directory = store.root / "jobs" / identifier / "evidence" / "check-one" / "attempts" / "run-one"
    directory.mkdir(parents=True)
    (directory / "events.jsonl").write_text(json.dumps({"sequence": 1, "step": "probe_old", "method": "GET", "path": "/documents/one",
        "status_code": 403, "response_text": "<script>window.bad=true</script>", "started_elapsed_seconds": 5.1, "finished_elapsed_seconds": 5.2})+'\n')
    (directory / "analysis.json").write_text(json.dumps({"verdict": "candidate", "kind": "stale_session_access"}))
    store.finish(identifier, "interrupted", {})
    response = client.get(f"/runs/{identifier}")
    assert response.status_code == 200
    assert "&lt;script&gt;" in response.text and "<script>window.bad" not in response.text
    assert client.get(f"/api/jobs/{identifier}").json()["observation"]["verdict"] == "candidate"


def test_export_does_not_follow_symlinks_or_include_logs(tmp_path):
    store = Store(tmp_path / "store")
    identifier = store.create(JobSpec())
    directory = tmp_path / "files"
    directory.mkdir()
    secret = tmp_path / "secret.json"
    secret.write_text('"private-secret"')
    (directory / "link.json").symlink_to(secret)
    (directory / "worker.log").write_text("private-secret")
    data = export_bundle(directory, store.get(identifier))
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert "link.json" not in archive.namelist() and "worker.log" not in archive.namelist()
        assert all(b"private-secret" not in archive.read(name) for name in archive.namelist())


def test_evidence_ignores_incomplete_lines_and_nonfinite_numbers(tmp_path):
    directory = tmp_path / "evidence"
    directory.mkdir()
    (directory / "events.jsonl").write_text('{"step":"bad","started":NaN}\n{"step":"partial"')
    assert not inspect_evidence(tmp_path, {"status": "failed", "result": {}})["groups"]


def test_write_readback_lane_uses_actual_session_identity(tmp_path):
    directory = tmp_path / "evidence" / "attempt"
    directory.mkdir(parents=True)
    (directory / "run.json").write_text(json.dumps({"policy": {"timing": {"mode": "bounded", "max_delay_seconds": 5.0, "tolerance_seconds": 0.05}}, "sessions": {
        "owner": {"actor": "alice", "generation": 1}, "subject_old": {"actor": "bob", "generation": 2}}}))
    rows = [
        {"sequence": 1, "step": "baseline_old", "actor": "alice", "generation": 1},
        {"sequence": 2, "step": "transition", "actor": "bob", "generation": 2},
    ]
    (directory / "events.jsonl").write_text(''.join(json.dumps(row)+'\n' for row in rows))
    group = inspect_evidence(tmp_path, {"status": "completed", "result": {}})["groups"][0]
    events = group["events"]
    assert [event["role"] for event in events] == ["Owner / control", "Old session"]
    assert group["end"] >= group["deadline"]  # Cancellation cannot move a future policy boundary to the last request time.


def test_cancelled_native_budget_never_reserves_a_followup_request():
    budget = PilotBudget(20, 10, should_cancel=lambda: True)
    with pytest.raises(RuntimeError, match="cancelled"): budget.reserve()
    assert budget.requests == 0 and budget.remaining() == 0


def test_async_cancellation_closes_current_operation():
    closed = []
    async def slow():
        try: await asyncio.sleep(20)
        finally: closed.append(True)
    async def run():
        nonlocal_deadline[0] = asyncio.get_running_loop().time()+0.05
        task = asyncio.create_task(cancellable(slow(), lambda: asyncio.get_running_loop().time() > nonlocal_deadline[0]))
        with pytest.raises(asyncio.CancelledError): await task
    nonlocal_deadline = [0]
    asyncio.run(run())
    assert closed == [True]


def wait_for(client, identifier, states, timeout=35):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        job = client.get(f"/api/jobs/{identifier}").json()
        if job["status"] in states: return job
        time.sleep(0.1)
    raise AssertionError(f"Worker did not reach {states}: {job}")


@pytest.mark.network
def test_real_worker_confirmed_run_export_and_cancel(tmp_path):
    app = create_app(tmp_path / "live", start_worker=True)
    with TestClient(app, base_url="http://localhost") as client:
        client.headers["X-CSRF-Token"] = app.state.csrf
        identifier = client.post("/api/jobs", json={"title": "Live stale session"}).json()["id"]
        # Browser navigation is independent of execution.
        assert client.get("/new").status_code == 200
        job = wait_for(client, identifier, {"completed", "failed"})
        assert job["status"] == "completed", job
        assert job["observation"]["verdict"] == "confirmed_violation"
        assert job["observation"]["reproductions"] == 2
        directory = app.state.store.root / "jobs" / identifier
        fixture = json.loads((directory / "fixture.json").read_text())
        assert fixture["process_stopped"]
        assert job["result"]["requests"] == 45 + fixture["readiness_requests"]
        assert client.get(f"/runs/{identifier}/live").status_code == 200
        data = client.get(f"/runs/{identifier}/download").content
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            assert any(name.endswith("analysis.json") for name in archive.namelist())
            exported = b'\n'.join(archive.read(name) for name in archive.namelist())
            assert b'"password": "[REDACTED]"' in exported
        cancelled = client.post("/api/jobs", json={"title": "Cancel during grace"}).json()["id"]
        wait_for(client, cancelled, {"running"})
        time.sleep(0.8)
        client.post(f"/api/jobs/{cancelled}/cancel")
        stopped = wait_for(client, cancelled, {"cancelled"}, timeout=8)
        count = stopped["observation"]["requests"]
        time.sleep(0.3)
        assert client.get(f"/api/jobs/{cancelled}").json()["observation"]["requests"] == count
        assert stopped["observation"]["verdict"] != "confirmed_violation"


@pytest.mark.network
def test_worker_crash_is_visible_and_job_not_retried(tmp_path):
    app = create_app(tmp_path / "crash", start_worker=True)
    with TestClient(app, base_url="http://localhost") as client:
        client.headers["X-CSRF-Token"] = app.state.csrf
        identifier = client.post("/api/jobs", json={}).json()["id"]
        wait_for(client, identifier, {"running"})
        os.kill(app.state.supervisor.process.pid, signal.SIGKILL)
        job = wait_for(client, identifier, {"interrupted"}, timeout=8)
        assert job["error"] == "worker_interrupted"
        time.sleep(0.5)
        assert client.get(f"/api/jobs/{identifier}").json()["status"] == "interrupted"


@pytest.mark.network
def test_rejected_second_dashboard_does_not_interrupt_first_worker(tmp_path):
    root = tmp_path / "shared"
    first_app = create_app(root)
    with TestClient(first_app, base_url="http://localhost") as first:
        first.headers["X-CSRF-Token"] = first_app.state.csrf
        identifier = first.post("/api/jobs", json={"fixture_mode": "immediate"}).json()["id"]
        wait_for(first, identifier, {"running"})
        second_app = create_app(root)
        with TestClient(second_app, base_url="http://localhost"):
            deadline = time.monotonic()+5
            while not second_app.state.supervisor.error and time.monotonic() < deadline:
                time.sleep(0.05)
            assert second_app.state.supervisor.error
        assert first.get(f"/api/jobs/{identifier}").json()["status"] == "running"
        job = wait_for(first, identifier, {"completed", "interrupted", "failed"})
        assert job["status"] == "completed"
        assert job["result"]["verdict"] == "no_violation_observed"
