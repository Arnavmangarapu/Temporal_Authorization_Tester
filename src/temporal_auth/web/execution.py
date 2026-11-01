"""Web and exported replays call the same CLI execution libraries."""

import asyncio
from contextlib import asynccontextmanager
import os
from pathlib import Path
import secrets
import socket
import sys
from time import monotonic

import httpx
import yaml

from temporal_auth.config.lifecycle import LifecycleConfig
from temporal_auth.generator import generate_scenario
from temporal_auth.integrations.pilot import private_json, run_pilot
from temporal_auth.replay import check_lab
from temporal_auth.runner.budget import ExecutionBudget
from temporal_auth.web.models import JobSpec, lab_config


def python_environment():
    environ = os.environ.copy()
    paths = [str(Path(p).resolve()) for p in sys.path if p and Path(p).is_dir()]
    targets = Path(__file__).resolve().parents[3] / "targets"
    if targets.is_dir(): paths.append(str(targets))
    environ["PYTHONPATH"] = os.pathsep.join(dict.fromkeys(paths))
    return environ


async def cancellable(awaitable, cancelled):
    task = asyncio.create_task(awaitable)
    try:
        while not task.done():
            if cancelled():
                task.cancel()
                break
            await asyncio.wait({task}, timeout=0.1)
        return await task
    finally:
        if not task.done():
            task.cancel()
            try: await task
            except asyncio.CancelledError: pass


@asynccontextmanager
async def managed_lab(mode, cancelled, budget, metadata_path):
    listener = socket.socket()
    process = None
    readiness_requests = 0
    started = monotonic()
    startup_seconds = None
    origin = None
    try:
        listener.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
        credentials = {f"LAB_{name}_PASSWORD": secrets.token_urlsafe(24) for name in ("ALICE", "BOB", "CHARLIE")}
        credentials["LAB_RESET_KEY"] = secrets.token_urlsafe(24)
        env = python_environment()
        # Only the worker needs the user's configured credentials. The managed
        # lab gets generated fixture credentials and basic runtime settings.
        target_env = {key: env[key] for key in ("PATH", "PYTHONPATH", "LANG") if key in env}
        target_env.update(credentials, LAB_MODE=mode)
        process = await asyncio.create_subprocess_exec(sys.executable, "-m", "temporal_auth.web.lab_process",
            str(listener.fileno()), pass_fds=(listener.fileno(),), env=target_env,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        listener.close()
        async with httpx.AsyncClient(trust_env=False, timeout=0.3) as client:
            for _ in range(100):
                if cancelled(): raise asyncio.CancelledError
                if budget.exhausted(): raise RuntimeError("managed_lab_start_budget_exhausted")
                if process.returncode is not None: raise RuntimeError("managed_lab_start_failed")
                budget.requests += 1
                readiness_requests += 1
                try:
                    if (await client.get(origin + "/health")).status_code == 200: break
                except httpx.HTTPError: pass
                await asyncio.sleep(0.05)
            else: raise RuntimeError("managed_lab_start_timeout")
        startup_seconds = monotonic() - started
        yield origin, credentials, readiness_requests
    finally:
        listener.close()
        if process and process.returncode is None:
            process.terminate()
            try: await asyncio.wait_for(process.wait(), 5)
            except TimeoutError:
                process.kill()
                await process.wait()
        private_json(metadata_path, {"origin": origin, "readiness_requests": readiness_requests,
            "startup_seconds": startup_seconds, "process_stopped": process is None or process.returncode is not None})


def check_summary(result):
    report = result.report
    return {"verdict": report.verdict, "confirmation": report.confirmation,
            "reproductions": report.reproductions, "requests": report.shared_total_requests,
            "fixture_requests": report.fixture_requests, "kind": report.kind,
            "engine_status": report.status, "error": report.error_code}


async def execute_spec(spec: JobSpec, directory: Path, tools: Path, cancelled=lambda: False):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_json(directory / "replay.json", {"schema_version": "web-replay-1", "job": spec.model_dump(mode="json")})
    if spec.target in ("gitea", "pocketbase"):
        result = await asyncio.to_thread(run_pilot, spec.target, tools, directory / "evidence",
            profile=spec.profile, seed=spec.seed, max_requests=spec.max_requests,
            max_runtime_seconds=spec.max_runtime_seconds, should_cancel=cancelled)
        report = result.report
        summary = {"verdict": report["verdict"], "confirmation": report.get("confirmation", "not_needed"),
                   "reproductions": report["reproductions"], "requests": report["total_requests"],
                   "fixture_requests": report["fixture_requests"], "kind": None,
                   "engine_status": report["status"], "error": report.get("error")}
    else:
        budget = ExecutionBudget(spec.max_requests, spec.max_runtime_seconds)
        async def run(origin=None, env=None):
            cfg = lab_config(spec, origin) if origin else lab_config(spec)
            config_path = directory / "config.yaml"
            config_path.write_text(yaml.safe_dump(cfg.model_dump(mode="json"), sort_keys=False))
            config_path.chmod(0o600)
            scenario = generate_scenario(cfg, spec.seed) if isinstance(cfg, LifecycleConfig) else None
            if scenario is not None: private_json(directory / "scenario.json", scenario.model_dump(mode="json"))
            return await cancellable(check_lab(cfg, directory / "evidence", environ=env,
                reset_key_env=spec.reset_key_env, scenario=scenario, shared_budget=budget), cancelled)
        if spec.target == "managed_lab":
            async with managed_lab(spec.fixture_mode, cancelled, budget, directory / "fixture.json") as (origin, env, readiness):
                env[spec.reset_key_env] = env["LAB_RESET_KEY"]
                result = await run(origin, env)
        else:
            result = await run()
        summary = check_summary(result)
        if spec.target == "managed_lab": summary["fixture_requests"] += readiness
    private_json(directory / "result.json", summary)
    return summary
