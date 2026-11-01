"""Monitoring reconciles with evidence and never participates in the oracle."""

import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

from fastapi.testclient import TestClient
import httpx
from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.parser import text_string_to_metric_families
import pytest
import yaml

from temporal_auth.monitoring import EvidenceCollector, WorkerExporter
from temporal_auth.web.app import create_app
from temporal_auth.web.models import JobSpec
from temporal_auth.web.store import Store


def expose(collector):
    registry = CollectorRegistry()
    registry.register(collector)
    return generate_latest(registry).decode()


def samples(text, name):
    return [s for f in text_string_to_metric_families(text) for s in f.samples if s.name == name]


def total(text, name):
    return sum(s.value for s in samples(text, name))


def event(start=0.0, finish=0.02, **extra):
    return {"started_elapsed_seconds": start, "finished_elapsed_seconds": finish,
            "outcome": "response", "step": "probe_old", **extra}


def evidence(store, identifier, events):
    directory = store.root / "jobs" / identifier / "evidence" / "attempt"
    directory.mkdir(parents=True)
    path = directory / "events.jsonl"
    path.write_text("".join(json.dumps(e) + "\n" for e in events))
    return path


def test_incremental_histogram_partial_line_and_restart(tmp_path):
    store = Store(tmp_path)
    identifier = store.create(JobSpec())
    store.claim()
    path = evidence(store, identifier, [event(), event(1, 1.1, error_code="http_error")])
    collector = EvidenceCollector(store)
    first = expose(collector)
    assert total(first, "temporal_auth_requests_total") == 2
    assert total(first, "temporal_auth_request_duration_seconds_count") == 2
    assert total(first, "temporal_auth_request_duration_seconds_sum") == pytest.approx(0.12)
    assert total(expose(collector), "temporal_auth_requests_total") == 2
    with path.open("a") as stream: stream.write(json.dumps(event(2, 2.2)))
    assert total(expose(collector), "temporal_auth_requests_total") == 2
    with path.open("a") as stream: stream.write("\n")
    assert total(expose(collector), "temporal_auth_requests_total") == 3
    store.finish(identifier, "completed", {"verdict": "no_violation_observed", "requests": 8, "fixture_requests": 5})
    final = expose(collector)
    rebuilt = expose(EvidenceCollector(Store(tmp_path)))
    for name in ("temporal_auth_requests_total", "temporal_auth_request_duration_seconds_count",
                 "temporal_auth_terminal_job_budget_requests_total", "temporal_auth_jobs_finished_total"):
        assert samples(final, name) == samples(rebuilt, name)
    assert total(final, "temporal_auth_terminal_job_budget_requests_total") == 8


def test_native_format_failures_and_invalid_evidence(tmp_path):
    store = Store(tmp_path)
    identifier = store.create(JobSpec(target="gitea"))
    path = evidence(store, identifier, [{"started": 1, "finished": 1.03, "status": 403, "error": None},
                                       {"started": 2, "finished": 2.02, "error": "runtime_budget_exhausted"}])
    with path.open("a") as stream: stream.write('garbage\n' + json.dumps(event(3, 2)) + '\n')
    store.finish(identifier, "failed", {"verdict": "inconclusive"})
    text = expose(EvidenceCollector(store))
    assert total(text, "temporal_auth_requests_total") == 2
    assert {s.labels["outcome"] for s in samples(text, "temporal_auth_requests_total")} == {"response", "execution_error"}
    assert total(text, "temporal_auth_evidence_invalid_lines") == 2
    assert total(text, "temporal_auth_execution_errors_total") == 1


def test_confirmation_deduplication_and_sequence_deadline_samples(tmp_path):
    store = Store(tmp_path)
    for action, kind in (("read", "stale_session_access"), ("read", "stale_session_access"), ("write", "stale_session_write")):
        identifier = store.create(JobSpec(action=action, fixture_mode="stale_session"))
        path = evidence(store, identifier, [event(1.99, 2), event(2, 2.01, step="probe_fresh")])
        path.with_name("run.json").write_text(json.dumps({"status": "completed", "probe_not_before_elapsed_seconds": 2}))
        path.with_name("analysis.json").write_text(json.dumps({"verdict": "candidate"}))
        store.finish(identifier, "completed", {"verdict": "confirmed_violation", "kind": kind})
    candidate = store.create(JobSpec())
    store.finish(candidate, "interrupted", {"verdict": "candidate"})
    text = expose(EvidenceCollector(store))
    assert total(text, "temporal_auth_confirmed_finding_signatures") == 2
    assert total(text, "temporal_auth_sequences_completed_total") == 3
    assert total(text, "temporal_auth_sampled_probes_total") == 6
    assert {s.labels["boundary"] for s in samples(text, "temporal_auth_sampled_probes_total")} == {"before_deadline", "after_deadline"}


def test_labels_do_not_contain_secrets_resource_ids_or_arbitrary_outcomes(tmp_path):
    store = Store(tmp_path)
    identifier = store.create(JobSpec(title="SECRET-TOKEN http://sensitive.example/doc/UUID"))
    evidence(store, identifier, [event(error_code="SECRET-TOKEN", path="/doc/UUID")])
    store.finish(identifier, "failed", {"verdict": "SECRET-TOKEN", "kind": "UUID"})
    text = expose(EvidenceCollector(store))
    for sensitive in ("SECRET-TOKEN", "UUID", "sensitive.example", identifier): assert sensitive not in text
    assert 'verdict="other"' in text
    all_labels = {label for f in text_string_to_metric_families(text) for s in f.samples for label in s.labels}
    assert all_labels <= {"state", "target", "lifecycle", "verdict", "outcome", "session", "boundary", "le"}


def test_no_ui_history_limit_and_no_following_external_symlinks(tmp_path):
    store = Store(tmp_path / "workspace")
    for _ in range(205):
        identifier = store.create(JobSpec())
        store.cancel(identifier)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "events.jsonl").write_text(json.dumps(event()) + "\n")
    root = store.root / "jobs" / identifier
    root.mkdir(parents=True)
    (root / "evidence").symlink_to(outside, target_is_directory=True)
    text = expose(EvidenceCollector(store))
    assert total(text, "temporal_auth_jobs_finished_total") == 205
    assert total(text, "temporal_auth_requests_total") == 0


def test_default_web_and_cli_work_without_prometheus_import(tmp_path):
    code = '''
import importlib.abc, sys
class Block(importlib.abc.MetaPathFinder):
 def find_spec(self, fullname, *args):
  if fullname.startswith('prometheus_client'): raise ImportError('optional dependency absent')
sys.meta_path.insert(0, Block())
from temporal_auth.web.app import create_app
from pathlib import Path
app = create_app(Path(sys.argv[1]), start_worker=False)
assert app.state.supervisor.metrics_port is None
from temporal_auth.cli import app
from typer.testing import CliRunner
r = CliRunner().invoke(app, ['validate', 'examples/document-lab.yaml'])
assert r.exit_code == 0, r.output
r = CliRunner().invoke(app, ['serve', '--metrics-port', '9464'])
assert r.exit_code == 2 and 'Install monitoring' in r.output, r.output
'''
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    subprocess.run([sys.executable, "-c", code, str(tmp_path)], env=env, check=True, timeout=15)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.network
def test_exporter_port_conflict_does_not_leak_or_take_over(tmp_path):
    store = Store(tmp_path)
    first = WorkerExporter(store, free_port())
    try:
        port = first.server.server_port
        with pytest.raises(OSError): WorkerExporter(store, port)
        response = httpx.get(f"http://127.0.0.1:{port}/metrics", trust_env=False)
        assert response.status_code == 200
        assert total(response.text, "temporal_auth_jobs") == 0
    finally: first.close()


@pytest.mark.network
def test_worker_live_metrics_reconcile_and_rebuild_after_crash(tmp_path):
    port = free_port()
    app = create_app(tmp_path, metrics_port=port)
    with TestClient(app, base_url="http://localhost") as client:
        client.headers["X-CSRF-Token"] = app.state.csrf
        response = client.post("/api/jobs", json={"fixture_mode": "immediate"})
        identifier = response.json()["id"]
        deadline = time.monotonic() + 35
        live = False
        while time.monotonic() < deadline:
            try:
                text = httpx.get(f"http://127.0.0.1:{port}/metrics", timeout=2, trust_env=False).text
                live |= any(s.labels.get("state") == "running" and s.value == 1 for s in samples(text, "temporal_auth_jobs"))
            except httpx.TransportError: pass
            job = app.state.store.get(identifier)
            if job["status"] not in ("queued", "running", "cancelling"): break
            time.sleep(0.1)
        assert live and job["status"] == "completed"
        assert job["result"]["verdict"] == "no_violation_observed"
        text = httpx.get(f"http://127.0.0.1:{port}/metrics", trust_env=False).text
        events = [json.loads(line) for p in (tmp_path / "jobs").rglob("events.jsonl") for line in p.read_text().splitlines()]
        assert total(text, "temporal_auth_requests_total") == len(events)
        assert total(text, "temporal_auth_request_duration_seconds_sum") == pytest.approx(sum(e["finished_elapsed_seconds"] - e["started_elapsed_seconds"] for e in events))
        assert total(text, "temporal_auth_terminal_job_budget_requests_total") == job["result"]["requests"]
        assert total(text, "temporal_auth_sequences_completed_total") == 1
        pid = app.state.supervisor.process.pid
        os.kill(pid, signal.SIGKILL)
        deadline = time.monotonic() + 10
        rebuilt = None
        while time.monotonic() < deadline:
            time.sleep(0.1)
            try:
                rebuilt = httpx.get(f"http://127.0.0.1:{port}/metrics", timeout=1, trust_env=False).text
                if app.state.supervisor.process.pid != pid and total(rebuilt, "temporal_auth_requests_total") == len(events): break
            except httpx.TransportError: pass
        assert rebuilt and total(rebuilt, "temporal_auth_requests_total") == len(events)
        assert total(rebuilt, "temporal_auth_sequences_completed_total") == 1


@pytest.mark.network
def test_occupied_port_is_visible_worker_error_without_restart_loop(tmp_path):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0)); sock.listen()
        app = create_app(tmp_path, metrics_port=sock.getsockname()[1])
        with TestClient(app):
            deadline = time.monotonic() + 8
            while not app.state.supervisor.error and time.monotonic() < deadline: time.sleep(0.1)
            assert "Monitoring could not start" in app.state.supervisor.error
            assert not app.state.supervisor.healthy


def test_compose_profiles_and_dashboard_queries():
    compose = yaml.safe_load(Path("compose.yaml").read_text())
    for service in compose["services"].values():
        assert service["profiles"] == ["monitoring"]
        assert "@sha256:" in Path(service["build"]["dockerfile"]).read_text().splitlines()[0]
        assert service["network_mode"] == "host"
    dashboard = json.loads(Path("monitoring/grafana/dashboards/temporal-auth.json").read_text())
    assert len({p["id"] for p in dashboard["panels"]}) == len(dashboard["panels"])
    assert all(t["expr"] for p in dashboard["panels"] for t in p.get("targets", []))
