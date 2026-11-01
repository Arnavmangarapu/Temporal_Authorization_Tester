"""Real TCP and wall-clock smoke check, without using the future testing engine."""

from contextlib import ExitStack, contextmanager
import socket
from threading import Thread
import time
from uuid import uuid4

import httpx
import pytest
import uvicorn
import json
import yaml
from typer.testing import CliRunner

from document_lab.app import create_app
from document_lab.settings import LabSettings
from temporal_auth.cli import app as runner_cli


@contextmanager
def live_lab(mode):
    listener = socket.socket()
    server = None
    thread = None
    try:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(
            create_app(LabSettings(mode=mode)), host="127.0.0.1", port=port,
            log_level="error", access_log=False, lifespan="on", ws="none",
        ))
        thread = Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        startup_deadline = time.monotonic() + 10
        while not server.started:
            if not thread.is_alive() or time.monotonic() >= startup_deadline:
                raise RuntimeError("Temporary lab server did not start")
            time.sleep(0.01)
        with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=5, trust_env=False) as client:
            yield client
    finally:
        if server is not None:
            server.should_exit = True
        if thread is not None:
            thread.join(timeout=5)
        listener.close()
        if thread is not None:
            assert not thread.is_alive(), "Temporary lab server failed to stop"


def login(client, username):
    response = client.post("/auth/login", json={"username": username, "password": f"{username}-demo-password"})
    assert response.status_code == 200
    data = response.json()
    return data["user_id"], {"Authorization": f"Bearer {data['access_token']}"}


@pytest.mark.network
def test_three_modes_over_http_after_actual_five_second_bound():
    observations = []
    with ExitStack() as stack:
        for mode in ("immediate", "delayed", "stale_session"):
            client = stack.enter_context(live_lab(mode))
            assert client.get("/health").json() == {"status": "ok"}
            _, owner = login(client, "alice")
            bob, _ = login(client, "bob")
            marker = f"real-http-{uuid4()}"
            created = client.post("/documents", headers=owner, json={"content": marker})
            assert created.status_code == 201
            document_id = created.json()["id"]
            path = f"/documents/{document_id}"
            assert client.post(f"{path}/shares", headers=owner, json={"subject_id": bob}).status_code == 200
            _, old = login(client, "bob")
            assert client.get(path, headers=old).json()["content"] == marker
            revoked = client.delete(f"{path}/shares/{bob}", headers=owner)
            assert revoked.status_code == 200
            acknowledged_at = time.monotonic()
            _, fresh = login(client, "bob")
            observations.append((mode, client, path, old, fresh, owner, marker, acknowledged_at))

        # One shared wait; every subsequent probe starts beyond its own bound.
        deadline = max(item[-1] for item in observations) + 5.05
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.1, remaining))
        for mode, client, path, old, fresh, owner, marker, acknowledged_at in observations:
            assert time.monotonic() > acknowledged_at + 5
            old_response = client.get(path, headers=old)
            if mode == "stale_session":
                assert old_response.status_code == 200
                assert old_response.json()["content"] == marker
            else:
                assert old_response.status_code == 403
                assert marker not in old_response.text
            fresh_response = client.get(path, headers=fresh)
            assert fresh_response.status_code == 403
            assert marker not in fresh_response.text
            control = client.get(path, headers=owner)
            assert control.status_code == 200
            assert control.json()["content"] == marker


@pytest.mark.network
def test_runner_cli_collects_real_http_evidence(config_data, tmp_path, monkeypatch):
    with live_lab("stale_session") as client:
        config_data["base_url"] = str(client.base_url)
        path = tmp_path / "target.yaml"
        path.write_text(yaml.safe_dump(config_data), encoding="utf-8")
        monkeypatch.setenv("LAB_ALICE_PASSWORD", "alice-demo-password")
        monkeypatch.setenv("LAB_BOB_PASSWORD", "bob-demo-password")
        output = tmp_path / "evidence"
        result = CliRunner().invoke(runner_cli, ["run", str(path), "--output", str(output)])
    assert result.exit_code == 0, result.output
    assert "not_evaluated" in result.output
    report_file, = output.glob("*/run.json")
    report = json.loads(report_file.read_text())
    assert report["status"] == "completed"
    assert report["request_count"] == 12
    records = [json.loads(line) for line in (report_file.parent / "events.jsonl").read_text().splitlines()]
    by_step = {record["step"]: record for record in records}
    assert by_step["probe_old_session"]["status_code"] == 200
    assert by_step["probe_fresh_session"]["status_code"] == 403
    assert by_step["control_after_revoke"]["status_code"] == 200
    for step in ("probe_old_session", "probe_fresh_session", "control_after_revoke"):
        assert by_step[step]["started_elapsed_seconds"] >= report["probe_not_before_elapsed_seconds"]


@pytest.mark.network
def test_check_cli_confirms_two_real_http_clean_replays(config_data, tmp_path, monkeypatch):
    with live_lab("stale_session") as client:
        config_data["base_url"] = str(client.base_url)
        path = tmp_path / "target.yaml"
        path.write_text(yaml.safe_dump(config_data), encoding="utf-8")
        for name, value in {"LAB_ALICE_PASSWORD": "alice-demo-password", "LAB_BOB_PASSWORD": "bob-demo-password", "LAB_RESET_KEY": "local-lab-reset-key"}.items():
            monkeypatch.setenv(name, value)
        output = tmp_path / "checks"
        result = CliRunner().invoke(runner_cli, ["check", str(path), "--output", str(output)])
    assert result.exit_code == 3, result.output
    assert "confirmed_violation" in result.output
    report_path, = output.glob("*/check.json")
    report = json.loads(report_path.read_text())
    assert report["verdict"] == "confirmed_violation"
    assert report["reproductions"] == 2
    assert report["total_requests"] == 39
    assert report["fixture_requests"] == 3
    assert len(report["attempts"]) == 3
    for attempt in report["attempts"]:
        directory = report_path.parent / attempt["evidence"]
        run = json.loads((directory / "run.json").read_text())
        assert run["verdict"] == "not_evaluated"
        assert json.loads((directory / "analysis.json").read_text())["verdict"] == "candidate"


@pytest.mark.network
def test_generated_write_cli_confirms_denied_but_committed_effect(tmp_path, monkeypatch):
    from pathlib import Path
    from temporal_auth.config import load_config
    cfg = load_config(Path(__file__).resolve().parents[1] / 'examples/lifecycle-role-write.yaml')
    with live_lab('write_side_effect') as client:
        data = cfg.model_dump(mode='json')
        data['base_url'] = str(client.base_url)
        path = tmp_path / 'target.yaml'
        path.write_text(yaml.safe_dump(data), encoding='utf-8')
        for name, value in {'LAB_ALICE_PASSWORD': 'alice-demo-password', 'LAB_BOB_PASSWORD': 'bob-demo-password', 'LAB_RESET_KEY': 'local-lab-reset-key'}.items():
            monkeypatch.setenv(name, value)
        planned = CliRunner().invoke(runner_cli, ['plan', str(path), '--seed', '7'])
        assert planned.exit_code == 0
        manifest = tmp_path / 'scenario.json'
        manifest.write_text(planned.stdout, encoding='utf-8')
        output = tmp_path / 'checks'
        response = CliRunner().invoke(runner_cli, ['check', str(path), '--scenario', str(manifest), '--output', str(output)])
    assert response.exit_code == 3, response.output
    report_file, = output.glob('*/check.json')
    report = json.loads(report_file.read_text())
    assert report['verdict'] == 'confirmed_violation'
    assert report['kind'] == 'unauthorized_write'
    assert report['total_requests'] == 63
    assert report['reproductions'] == 2
    for attempt in report['attempts']:
        directory = report_file.parent / attempt['evidence']
        events = [json.loads(line) for line in (directory / 'events.jsonl').read_text().splitlines()]
        by_step = {event['step']: event for event in events}
        for role in ('old', 'fresh'):
            assert by_step[f'probe_{role}']['status_code'] == 403
            assert by_step[f'readback_{role}']['status_code'] == 200
            assert by_step[f'readback_{role}']['response_json']['content'] == by_step[f'probe_{role}']['request_json']['content']
