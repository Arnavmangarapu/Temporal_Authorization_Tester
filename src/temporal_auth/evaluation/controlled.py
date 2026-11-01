"""Controlled runs reuse the production checker and independent target.

Transport overlays are explicit response fault injections, not natural defects.
Only the early diagnostic subclasses the collector, never the production oracle.
"""

import asyncio
from contextlib import asynccontextmanager
import json
import math
from pathlib import Path
from time import monotonic

import httpx
import yaml

from document_lab.app import create_app
from document_lab.settings import LabSettings
from temporal_auth.config import load_config
from temporal_auth.config.loader import parse_config
from temporal_auth.generator import Scenario, generate_scenario
from temporal_auth.generator.plans import Action, catalog
from temporal_auth.integrations.pilot import private_json
from temporal_auth.oracles import analyze_run
from temporal_auth.replay import check_lab
from temporal_auth.replay.minimize import minimize_check
from temporal_auth.runner.budget import ExecutionBudget
from temporal_auth.runner.generated import GeneratedRunner
from temporal_auth.web.execution import managed_lab

ENV = {"LAB_ALICE_PASSWORD": "alice-demo-password", "LAB_BOB_PASSWORD": "bob-demo-password", "LAB_RESET_KEY": "local-lab-reset-key"}


class LogicalClock:
    def __init__(self): self.now = 0.0
    def __call__(self): return self.now
    async def sleep(self, delay):
        self.now = math.nextafter(self.now + delay, math.inf)
        await asyncio.sleep(0)


def configuration(root, case, budget, origin=None):
    cfg = load_config(Path(root) / "examples" / f"lifecycle-{case['life']}-{case['action']}.yaml")
    data = cfg.model_dump(mode="json")
    data["budget"].update(budget)
    if origin: data["base_url"] = origin
    if case["overlay"] == "unknown_policy":
        data["policy"]["timing"] = {"mode": "unknown", "reason": "Frozen negative control: no timing policy available."}
    return parse_config(yaml.safe_dump(data))


def scenario(cfg, method, seed):
    if method not in ("seeded-dag", "canonical-dag", "seeded-minimal"): raise ValueError("Unknown evaluation method")
    if method != "canonical-dag": return generate_scenario(cfg, seed, warmups=method != "seeded-minimal")
    graph = catalog(cfg, {"warmup_old", "warmup_control"}, "old_first")
    nodes, done = [], set()
    while len(done) < len(graph):
        eligible = sorted(name for name, deps in graph.items() if name not in done and deps <= done)
        if not eligible: raise ValueError("Cyclic graph")
        name = eligible[0]; nodes.append(Action(id=name, depends_on=sorted(graph[name]))); done.add(name)
    plan = Scenario(seed=seed, lifecycle=cfg.policy.lifecycle, action=cfg.policy.action, nodes=nodes)
    plan.validate_for(cfg)
    return plan


@asynccontextmanager
async def target(case, clock):
    app = create_app(LabSettings(mode=case["mode"]), clock=clock)
    async with app.router.lifespan_context(app):
        upstream = httpx.ASGITransport(app=app)
        state = {"transitioned": False, "actors": {}}
        async def handle(request):
            if case["overlay"] == "unavailable": raise httpx.ConnectError("Frozen unavailable-target control", request=request)
            response = await upstream.handle_async_request(request)
            await response.aread()
            path = request.url.path
            if path == "/testing/reset" and response.status_code == 200:
                state["transitioned"], state["actors"] = False, {}
            if path == "/auth/login" and response.status_code == 200:
                state["actors"]["Bearer " + response.json()["access_token"]] = json.loads(request.content)["username"]
            if request.method == "DELETE" and response.status_code == 200: state["transitioned"] = True
            actor = state["actors"].get(request.headers.get("authorization"))
            if state["transitioned"] and request.method == "GET" and path.startswith("/documents/"):
                if actor == "bob" and case["overlay"] == "disclosure_403" and "content" in response.json():
                    return httpx.Response(403, json=response.json())
                if actor == "bob" and case["overlay"] == "public_metadata_200" and response.status_code == 403:
                    return httpx.Response(200, json={"id": path.rsplit("/", 1)[1], "public_metadata": True})
                if actor == "alice" and case["overlay"] == "control_failure":
                    return httpx.Response(503, json={"detail": "Frozen control outage"})
            return response
        try: yield lambda: httpx.MockTransport(handle)
        finally: await upstream.aclose()


def posthoc(attempts, directory):
    """Retrospective projections of valid paired traces; no query savings implied."""
    projections = {name: [] for name in ("old-only", "fresh-only", "status-only")}
    for attempt in attempts:
        analysis = attempt.analysis
        if analysis.verdict == "inconclusive":
            for values in projections.values(): values.append("inconclusive")
            continue
        for session in ("old", "fresh"):
            projections[session + "-only"].append("candidate" if session in analysis.exposed_sessions else "no_violation_observed")
        events = [json.loads(line) for line in (directory / attempt.evidence / "events.jsonl").read_text().splitlines()]
        accepted = any(200 <= e["status_code"] < 300 for e in events if e["step"] in ("probe_old", "probe_fresh"))
        projections["status-only"].append("candidate" if accepted else "no_violation_observed")
    result = {}
    for name, values in projections.items():
        if not values: verdict = "inconclusive"
        elif values[0] != "candidate": verdict = values[0]
        elif len(values) == 3 and values == ["candidate"] * 3: verdict = "confirmed_violation"
        else: verdict = "candidate"
        result[name] = {"verdict": verdict, "observed_attempts": len(values),
                        "scope": "Retrospective on paired traces; baseline did not execute its own searches or replays"}
    return result


def summary(result, start, timing, directory):
    report = result.report
    return {"status": report.status, "verdict": report.verdict, "confirmation": report.confirmation,
            "reproductions": report.reproductions, "attempts": len(report.attempts), "error": report.error_code,
            "requests": report.shared_total_requests, "fixture_requests": report.fixture_requests,
            "model_elapsed_seconds": report.shared_elapsed_seconds, "wall_seconds": monotonic() - start,
            "timing": timing, "check": str(result.directory.relative_to(directory)),
            "attempt_details": [{"phase": a.phase, "verdict": a.analysis.verdict, "reason": a.analysis.reason,
                                 "sessions": a.analysis.exposed_sessions,
                                 "collection_status": json.loads((result.directory / a.evidence / "run.json").read_text())["status"]}
                                for a in report.attempts],
            "posthoc": posthoc(report.attempts, result.directory)}


async def run_controlled(root, case, method, seed, budget, directory, *, tcp=False, reduce=False):
    directory = Path(directory)
    clock = LogicalClock()
    start = monotonic()
    async def execute(origin=None, env=ENV, factory=None, shared=None, real=False):
        cfg = configuration(root, case, budget, origin)
        plan = scenario(cfg, method, seed)
        (directory / "config.yaml").write_text(yaml.safe_dump(cfg.model_dump(mode="json")))
        (directory / "config.yaml").chmod(0o600)
        private_json(directory / "scenario.json", plan.model_dump(mode="json"))
        options = {} if real else {"clock": clock, "sleep": clock.sleep, "transport_factory": factory}
        result = await check_lab(cfg, directory / "evidence", environ=env, scenario=plan, shared_budget=shared, **options)
        row = summary(result, start, "real-monotonic" if real else "logical-clock", directory)
        if reduce:
            reduced, reduced_dir = await minimize_check(cfg, result.directory, directory / "reduction", environ=env, **options)
            row["reduction"] = {"status": reduced.status, "before_actions": reduced.original_actions,
                "after_actions": reduced.smallest_verified_actions, "search_requests": reduced.total_requests,
                "error": reduced.error_code, "trials": [t.model_dump() for t in reduced.trials],
                "evidence": str(reduced_dir.relative_to(directory))}
        return row
    if tcp:
        if case["overlay"] != "none": raise ValueError("Response overlays belong only to the logical track")
        shared = ExecutionBudget(**budget)
        async with managed_lab(case["mode"], lambda: False, shared, directory / "fixture.json") as (origin, env, readiness):
            row = await execute(origin, env, shared=shared, real=True)
            row["fixture_requests"] += readiness
        row["wall_seconds"] = monotonic() - start
        return row
    async with target(case, clock) as factory:
        return await execute(factory=factory)


class EarlyRunner(GeneratedRunner):
    async def wait_until(self, deadline):
        self.check_budget()  # diagnostic only: deliberately omit the valid wait


async def run_early(root, case, seed, budget, directory):
    clock = LogicalClock()
    cfg = configuration(root, case, budget)
    plan = scenario(cfg, "seeded-dag", seed)
    (directory / "config.yaml").write_text(yaml.safe_dump(cfg.model_dump(mode="json")))
    (directory / "config.yaml").chmod(0o600)
    async with target(case, clock) as factory:
        runner = EarlyRunner(cfg, directory / "evidence", environ=ENV, clock=clock, sleep=clock.sleep,
                             transport_factory=factory, scenario=plan)
        result = await runner.run()
    analysis = analyze_run(cfg, result.directory)
    private_json(result.directory / "analysis.json", analysis.model_dump(mode="json"))
    events = {e["step"]: e for e in (json.loads(line) for line in (result.directory / "events.jsonl").read_text().splitlines())}
    if cfg.policy.action == "read":
        marker = result.report.bindings["protected_marker"]
        effect = any(marker in json.dumps(events[f"probe_{role}"].get("response_json")) for role in ("old", "fresh"))
    else:
        effect = any(result.report.bindings[role + "_write_marker"] in json.dumps(events[f"readback_{role}"].get("response_json")) for role in ("old", "fresh"))
    return {"status": result.report.status, "verdict": analysis.verdict, "reason": analysis.reason,
            "unsafe_early_claim": "candidate" if effect else "no_violation_observed", "requests": result.report.request_count,
            "confirmation": "not_attempted", "scope": "Single early trace on a correct delayed fixture, not a confirmed defect",
            "timing": "logical-clock; no propagation wait", "run": str(result.directory.relative_to(directory))}
