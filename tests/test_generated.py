"""Generated lifecycle/write tests and verified dependency-preserving reduction."""

import asyncio
import json
import math
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from document_lab.app import create_app
from document_lab.settings import LabSettings
from temporal_auth.cli import app as cli
from temporal_auth.config import load_config
from temporal_auth.config.lifecycle import LifecycleConfig
from temporal_auth.generator import Scenario, generate_scenario
from temporal_auth.oracles import analyze_run
from temporal_auth.replay import check_lab
from temporal_auth.replay.minimize import minimize_check, source_scenario
from temporal_auth.runner import run_experiment

ENV = {"LAB_ALICE_PASSWORD": "alice-demo-password", "LAB_BOB_PASSWORD": "bob-demo-password", "LAB_RESET_KEY": "local-lab-reset-key"}
EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


class Clock:
    def __init__(self): self.now = 0.0
    def __call__(self): return self.now
    async def sleep(self, delay):
        self.now = math.nextafter(self.now + delay, math.inf)
        await asyncio.sleep(0)


def configuration(life="sharing", action="write"):
    return load_config(EXAMPLES / f"lifecycle-{life}-{action}.yaml")


@pytest.mark.parametrize("life", ["sharing", "role", "ownership"])
@pytest.mark.parametrize("action", ["read", "write"])
def test_examples_and_seeded_plans_are_valid(life, action):
    cfg = configuration(life, action)
    assert isinstance(cfg, LifecycleConfig)
    manifests = []
    for seed in range(10):
        plan = generate_scenario(cfg, seed)
        plan.validate_for(cfg)
        assert plan == generate_scenario(cfg, seed)
        manifests.append(plan.model_dump_json())
    assert len(set(manifests)) > 1


@pytest.mark.parametrize("damage", ["missing_prerequisite", "reordered", "dependency_removed", "duplicate", "unknown", "wrong_policy"])
def test_invalid_graphs_are_rejected(damage):
    cfg = configuration()
    data = generate_scenario(cfg).model_dump()
    if damage == "missing_prerequisite": data["nodes"] = [node for node in data["nodes"] if node["id"] != "establish_access"]
    elif damage == "reordered": data["nodes"].reverse()
    elif damage == "dependency_removed": next(node for node in data["nodes"] if node["id"] == "transition")["depends_on"] = []
    elif damage == "duplicate": data["nodes"].append(data["nodes"][0])
    elif damage == "unknown": data["nodes"].append({"id": "arbitrary_request", "depends_on": []})
    else: data["lifecycle"] = "role_downgrade"
    with pytest.raises(ValueError): Scenario.model_validate(data).validate_for(cfg)


def test_cannot_remove_mandatory_transition_or_timing():
    cfg = configuration()
    plan = generate_scenario(cfg)
    for name in ("transition", "wait_for_deadline", "establish_access", "readback_old", "control_after_transition"):
        with pytest.raises(ValueError): plan.without(name, cfg)
    smaller = plan.without("warmup_old", cfg).without("warmup_control", cfg)
    smaller.validate_for(cfg)
    assert len(smaller.nodes) == len(plan.nodes) - 2


@pytest.mark.parametrize("life", ["sharing", "role", "ownership"])
@pytest.mark.parametrize("action", ["read", "write"])
@pytest.mark.parametrize("mode", ["immediate", "delayed", "stale_session", "write_side_effect"])
def test_generated_oracle_against_independent_modes(tmp_path, life, action, mode):
    cfg = configuration(life, action)
    async def execute():
        clock = Clock()
        target = create_app(LabSettings(mode=mode), clock=clock)
        async with target.router.lifespan_context(target):
            result = await run_experiment(cfg, tmp_path, environ=ENV, clock=clock, sleep=clock.sleep,
                transport_factory=lambda: httpx.ASGITransport(app=target), scenario=generate_scenario(cfg, 7))
        return result
    result = asyncio.run(execute())
    assert result.report.status == "completed", result.report
    analysis = analyze_run(cfg, result.directory)
    expected = "candidate" if mode == "stale_session" or mode == "write_side_effect" and action == "write" else "no_violation_observed"
    assert analysis.verdict == expected, analysis
    if mode == "stale_session":
        assert analysis.exposed_sessions == ["old"]
    if mode == "write_side_effect" and action == "write":
        assert analysis.exposed_sessions == ["old", "fresh"]
        assert analysis.kind == "unauthorized_write"
        rows = [json.loads(line) for line in (result.directory / "events.jsonl").read_text().splitlines()]
        assert all(row["status_code"] == 403 for row in rows if row["step"] in ("probe_old", "probe_fresh"))


@pytest.mark.parametrize("order", ["old_first", "fresh_first"])
def test_both_write_orders_confirm_by_readback(tmp_path, order):
    cfg = configuration("ownership", "write")
    plan = next(generate_scenario(cfg, seed) for seed in range(100) if generate_scenario(cfg, seed).write_order == order)
    async def execute():
        clock = Clock()
        target = create_app(LabSettings(mode="write_side_effect"), clock=clock)
        async with target.router.lifespan_context(target):
            return await check_lab(cfg, tmp_path, environ=ENV, clock=clock, sleep=clock.sleep,
                transport_factory=lambda: httpx.ASGITransport(app=target), scenario=plan)
    result = asyncio.run(execute())
    assert result.report.verdict == "confirmed_violation", result.report
    assert result.report.reproductions == 2


def test_200_write_without_actual_change_is_not_a_violation(tmp_path):
    cfg = configuration()
    async def execute():
        clock = Clock()
        target = create_app(LabSettings(mode="immediate"), clock=clock)
        transitioned = False
        async with target.router.lifespan_context(target):
            upstream = httpx.ASGITransport(app=target)
            async def handler(request):
                nonlocal transitioned
                if request.method == "DELETE": transitioned = True
                if transitioned and request.method == "PATCH":
                    return httpx.Response(200, json={"message": "updated"})
                return await upstream.handle_async_request(request)
            result = await run_experiment(cfg, tmp_path, environ=ENV, clock=clock, sleep=clock.sleep,
                transport_factory=lambda: httpx.MockTransport(handler))
        return analyze_run(cfg, result.directory)
    assert asyncio.run(execute()).verdict == "no_violation_observed"


@pytest.mark.parametrize("damage", ["baseline", "readback", "early", "scenario", "transition"])
def test_write_evidence_requires_healthy_observers_and_valid_state(tmp_path, damage):
    cfg = configuration("role", "write")
    async def execute():
        clock = Clock()
        target = create_app(LabSettings(mode="write_side_effect"), clock=clock)
        async with target.router.lifespan_context(target):
            return await run_experiment(cfg, tmp_path, environ=ENV, clock=clock, sleep=clock.sleep,
                transport_factory=lambda: httpx.ASGITransport(app=target))
    result = asyncio.run(execute())
    report = json.loads((result.directory / "run.json").read_text())
    rows = [json.loads(line) for line in (result.directory / "events.jsonl").read_text().splitlines()]
    by_step = {row["step"]: row for row in rows}
    if damage == "baseline": by_step["baseline_old"]["response_json"]["content"] = "unrelated"
    elif damage == "readback": by_step["readback_old"]["status_code"] = 500
    elif damage == "early": by_step["probe_old"]["started_elapsed_seconds"] = -1
    elif damage == "scenario": report["scenario"]["nodes"].pop()
    else: by_step["transition"]["response_json"]["role"] = "editor"
    (result.directory / "run.json").write_text(json.dumps(report))
    (result.directory / "events.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
    assert analyze_run(cfg, result.directory).verdict == "inconclusive"


@pytest.mark.parametrize("life,action", [("sharing", "read"), ("role", "write"), ("ownership", "write")])
def test_minimization_clean_confirms_reductions(tmp_path, life, action):
    cfg = configuration(life, action)
    async def execute():
        clock = Clock()
        target = create_app(LabSettings(mode="stale_session"), clock=clock)
        async with target.router.lifespan_context(target):
            factory = lambda: httpx.ASGITransport(app=target)
            original = await check_lab(cfg, tmp_path / "source", environ=ENV, clock=clock, sleep=clock.sleep, transport_factory=factory)
            assert original.report.verdict == "confirmed_violation", original.report
            report, directory = await minimize_check(cfg, original.directory, tmp_path / "reduced", environ=ENV,
                clock=clock, sleep=clock.sleep, transport_factory=factory)
        return original, report, directory
    original, report, directory = asyncio.run(execute())
    assert report.status == "completed"
    assert report.smallest_verified_actions == report.original_actions - 2
    assert len(report.trials) == 2 and all(trial.accepted for trial in report.trials)
    report.scenario.validate_for(cfg)
    assert {node.id for node in report.scenario.nodes} >= {"transition", "wait_for_deadline", "probe_old", "probe_fresh"}
    assert report.total_requests == sum(trial.requests for trial in report.trials)
    assert json.loads((directory / "scenario.json").read_text()) == report.scenario.model_dump()
    assert original.report.verdict == "confirmed_violation"


def test_minimizer_retains_warmup_when_required_for_reproduction(tmp_path):
    cfg = configuration("sharing", "read")
    async def execute():
        clock = Clock()
        target = create_app(LabSettings(mode="stale_session"), clock=clock)
        reads, transitioned, subject_tokens = {}, False, set()
        async with target.router.lifespan_context(target):
            upstream = httpx.ASGITransport(app=target)
            async def handler(request):
                nonlocal reads, transitioned, subject_tokens
                if request.url.path == "/testing/reset": reads, transitioned, subject_tokens = {}, False, set()
                if request.method == "DELETE": transitioned = True
                response = await upstream.handle_async_request(request)
                if request.url.path == "/auth/login" and json.loads(request.content)["username"] == "bob":
                    await response.aread()
                    subject_tokens.add(f"Bearer {response.json()['access_token']}")
                if request.method == "GET" and request.url.path.startswith("/documents/"):
                    token = request.headers.get("authorization")
                    if not transitioned:
                        reads[token] = reads.get(token, 0) + 1
                    else:
                        # Expose stale access only after at least two pre-change
                        # reads. Owner controls are unaffected by this wrapper.
                        await response.aread()
                        if response.status_code == 200 and token in subject_tokens and token in reads and reads[token] < 2:
                            return httpx.Response(403, json={"detail": "denied"})
                return response
            factory = lambda: httpx.MockTransport(handler)
            original = await check_lab(cfg, tmp_path / "source", environ=ENV, clock=clock, sleep=clock.sleep, transport_factory=factory)
            assert original.report.verdict == "confirmed_violation", original.report
            report, _ = await minimize_check(cfg, original.directory, tmp_path / "small", environ=ENV, clock=clock, sleep=clock.sleep, transport_factory=factory)
        return report
    report = asyncio.run(execute())
    assert report.status == "completed"
    assert report.smallest_verified_actions == report.original_actions - 1
    assert "warmup_old" in {node.id for node in report.scenario.nodes}
    assert any(not trial.accepted and trial.removed_action == "warmup_old" for trial in report.trials)


def test_minimize_rejects_unconfirmed_or_outside_source_before_network(tmp_path):
    cfg = configuration()
    source = tmp_path / "bad"
    source.mkdir()
    (source / "check.json").write_text('{}')
    with pytest.raises(ValueError): source_scenario(cfg, source)


def test_write_configuration_requires_operation():
    data = configuration().model_dump(mode="json")
    data["workflow"]["operations"]["write_resource"] = None
    with pytest.raises(ValidationError): LifecycleConfig.model_validate(data)


def test_plan_cli_outputs_reusable_manifest():
    response = CliRunner().invoke(cli, ["plan", str(EXAMPLES / "lifecycle-role-write.yaml"), "--seed", "7"])
    assert response.exit_code == 0, response.output
    Scenario.model_validate_json(response.stdout).validate_for(configuration("role", "write"))
    schema = CliRunner().invoke(cli, ["schema", "--version", "2"])
    assert schema.exit_code == 0


def test_minimization_budget_keeps_last_verified_reduction(tmp_path):
    cfg = configuration("sharing", "write")
    cfg = cfg.model_copy(update={"budget": cfg.budget.model_copy(update={"max_requests": 63})})
    async def execute():
        clock = Clock()
        target = create_app(LabSettings(mode="stale_session"), clock=clock)
        async with target.router.lifespan_context(target):
            factory = lambda: httpx.ASGITransport(app=target)
            original = await check_lab(cfg, tmp_path / "source", environ=ENV, clock=clock, sleep=clock.sleep, transport_factory=factory)
            assert original.report.verdict == "confirmed_violation"
            return await minimize_check(cfg, original.directory, tmp_path / "small", environ=ENV,
                clock=clock, sleep=clock.sleep, transport_factory=factory)
    report, _ = asyncio.run(execute())
    assert report.status == "budget_exhausted"
    assert report.total_requests == 63
    assert report.smallest_verified_actions == report.original_actions - 1
    assert len(report.trials) == 2 and report.trials[0].accepted and not report.trials[1].accepted


def test_bad_minimizer_reset_credential_is_an_error_not_success(tmp_path):
    cfg = configuration("sharing", "read")
    async def execute():
        clock = Clock()
        target = create_app(LabSettings(mode="stale_session"), clock=clock)
        async with target.router.lifespan_context(target):
            factory = lambda: httpx.ASGITransport(app=target)
            original = await check_lab(cfg, tmp_path / "source", environ=ENV, clock=clock, sleep=clock.sleep, transport_factory=factory)
            return await minimize_check(cfg, original.directory, tmp_path / "small", environ={**ENV, "LAB_RESET_KEY": "wrong-key"},
                clock=clock, sleep=clock.sleep, transport_factory=factory)
    report, _ = asyncio.run(execute())
    assert report.status == "execution_error"
    assert report.smallest_verified_actions == report.original_actions
    assert not report.trials[0].accepted


@pytest.mark.parametrize("mode", ["immediate", "write_side_effect"])
def test_target_commits_denied_write_only_in_explicit_defect_mode(mode):
    # Direct API verification without the generator, runner or oracle.
    from fastapi.testclient import TestClient
    clock = Clock()
    with TestClient(create_app(LabSettings(mode=mode), clock=clock)) as client:
        def login(name):
            data = client.post('/auth/login', json={'username': name, 'password': f'{name}-demo-password'}).json()
            return data, {'Authorization': f"Bearer {data['access_token']}"}
        _, owner = login('alice')
        bob, subject = login('bob')
        doc = client.post('/documents', headers=owner, json={'content': 'original'}).json()['id']
        client.post(f'/documents/{doc}/shares', headers=owner, json={'subject_id': bob['user_id'], 'permission': 'read'})
        assert client.patch(f'/documents/{doc}', headers=subject, json={'content': 'unauthorized'}).status_code == 403
        observed = client.get(f'/documents/{doc}', headers=owner).json()['content']
        assert observed == ('unauthorized' if mode == 'write_side_effect' else 'original')


def test_non_admin_cannot_change_roles_or_steal_ownership():
    from fastapi.testclient import TestClient
    with TestClient(create_app(LabSettings())) as client:
        def login(name):
            data = client.post('/auth/login', json={'username': name, 'password': f'{name}-demo-password'}).json()
            return data, {'Authorization': f"Bearer {data['access_token']}"}
        alice, owner = login('alice')
        bob, outsider = login('bob')
        doc = client.post('/documents', headers=owner, json={'content': 'private', 'access_model': 'ownership'}).json()['id']
        assert client.post(f"/users/{bob['user_id']}/role", headers=outsider, json={'role': 'editor'}).status_code == 403
        assert client.post(f'/documents/{doc}/owner', headers=outsider, json={'new_owner_id': bob['user_id']}).status_code == 403
        assert client.get(f'/documents/{doc}', headers=owner).json()['owner_id'] == alice['user_id']
