"""Greedy deletion with real clean confirmation and one shared search budget."""

import asyncio
from collections.abc import Awaitable, Callable, Mapping
import json
import os
from pathlib import Path
from time import monotonic
from typing import Literal
from uuid import uuid4

import httpx
from pydantic import BaseModel, Field

from temporal_auth.config.lifecycle import LifecycleConfig
from temporal_auth.generator import Scenario
from temporal_auth.generator.plans import OPTIONAL
from temporal_auth.oracles import analyze_run
from temporal_auth.replay.confirm import CheckReport, check_lab, write_json
from temporal_auth.runner.budget import ExecutionBudget
from temporal_auth.runner.evidence import utc_now


class ReductionTrial(BaseModel):
    removed_action: str
    accepted: bool
    reason: str
    check_path: str
    requests: int


class MinimizationReport(BaseModel):
    schema_version: Literal["1"] = "1"
    started_at_utc: str
    finished_at_utc: str | None = None
    status: Literal["running", "completed", "budget_exhausted", "interrupted", "execution_error"] = "running"
    source_check_id: str | None = None
    original_actions: int = 0
    smallest_verified_actions: int = 0
    total_requests: int = 0
    elapsed_seconds: float = 0
    error_code: str | None = None
    trials: list[ReductionTrial] = Field(default_factory=list)
    # The stored original confirmed scenario is a valid fallback if budget ends.
    scenario: Scenario | None = None


def source_scenario(config, source):
    if not isinstance(config, LifecycleConfig):
        raise ValueError("minimization_requires_version_two")
    report = CheckReport.model_validate_json((source / "check.json").read_text())
    if report.verdict != "confirmed_violation" or report.reproductions != 2 or len(report.attempts) != 3:
        raise ValueError("source_not_confirmed")
    manifests = []
    for attempt in report.attempts:
        directory = (source / attempt.evidence).resolve()
        if not directory.is_relative_to(source.resolve() / "attempts"):
            raise ValueError("invalid_source_path")
        analysis = analyze_run(config, directory)
        if analysis.verdict != "candidate" or analysis.kind != report.kind:
            raise ValueError("source_evidence_not_reproducible")
        raw = json.loads((directory / "run.json").read_text())
        manifests.append(Scenario.model_validate(raw["scenario"]))
    if any(plan != manifests[0] for plan in manifests[1:]):
        raise ValueError("source_scenarios_differ")
    manifests[0].validate_for(config)
    return report, manifests[0]


async def minimize_check(
    config, source: str | Path, output: str | Path, *, reset_key_env="LAB_RESET_KEY",
    environ: Mapping[str, str] | None = None, clock: Callable[[], float] = monotonic,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    transport_factory: Callable[[], httpx.AsyncBaseTransport] | None = None,
):
    # Validate the source before allocating a new search or resetting any target.
    source_report, best = source_scenario(config, Path(source))
    directory = Path(output) / f"minimize-{uuid4()}"
    directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    report = MinimizationReport(started_at_utc=utc_now(), source_check_id=source_report.check_id,
        original_actions=len(best.nodes), smallest_verified_actions=len(best.nodes), scenario=best)
    budget = ExecutionBudget(config.budget.max_requests, config.budget.max_runtime_seconds, clock)
    try:
        write_json(directory / "minimization.json", report)
        # Greedy restart after each successful reduction. A retained optional
        # action may become removable after another deletion.
        while True:
            accepted = False
            optional = sorted({node.id for node in best.nodes} & OPTIONAL)
            for node_id in optional:
                if budget.exhausted():
                    report.status, report.error_code = "budget_exhausted", budget.exhausted()
                    break
                trial = best.without(node_id, config)
                result = await check_lab(config, directory / "trials", reset_key_env=reset_key_env,
                    environ=os.environ if environ is None else environ, clock=clock, sleep=sleep,
                    transport_factory=transport_factory, scenario=trial, shared_budget=budget)
                keep = result.report.verdict == "confirmed_violation" and result.report.kind == source_report.kind
                report.trials.append(ReductionTrial(removed_action=node_id, accepted=keep,
                    reason=result.report.confirmation if keep else result.report.error_code or result.report.confirmation,
                    check_path=str(result.directory.relative_to(directory)), requests=result.report.total_requests))
                if keep:
                    best = trial
                    report.scenario, report.smallest_verified_actions = best, len(best.nodes)
                    accepted = True
                    break
                if result.report.status == "budget_exhausted":
                    report.status, report.error_code = "budget_exhausted", result.report.error_code
                    break
                if result.report.status in ("setup_failed", "execution_error"):
                    report.status, report.error_code = "execution_error", result.report.error_code
                    break
            if report.status != "running" or not accepted:
                break
        if report.status == "running": report.status = "completed"
    except asyncio.CancelledError:
        report.status, report.error_code = "interrupted", "cancelled"
        raise
    except Exception:
        report.status, report.error_code = "execution_error", "internal_error"
        raise
    finally:
        report.total_requests = budget.requests
        report.elapsed_seconds = clock() - budget.started
        report.finished_at_utc = utc_now()
        write_json(directory / "minimization.json", report)
        write_json(directory / "scenario.json", report.scenario)
    return report, directory
