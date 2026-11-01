"""Reset a dedicated lab before discovery and two independent replays."""

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
import json
import os
from pathlib import Path
from time import monotonic
from typing import Literal
from uuid import uuid4

import httpx
from pydantic import BaseModel, Field

from temporal_auth.config import TargetConfig
from temporal_auth.oracles import Analysis, analyze_run
from temporal_auth.runner.budget import ExecutionBudget
from temporal_auth.runner.engine import MAX_RESPONSE_BYTES, RunAborted, runner_class, run_experiment
from temporal_auth.runner.evidence import EvidenceWriter, Redactor, RequestEvent, utc_now


class Attempt(BaseModel):
    phase: Literal["discovery", "replay"]
    run_id: str
    evidence: str
    analysis: Analysis


class CheckReport(BaseModel):
    schema_version: Literal["1"] = "1"
    check_id: str
    started_at_utc: str
    finished_at_utc: str | None = None
    status: Literal["running", "completed", "setup_failed", "execution_error", "budget_exhausted", "interrupted"] = "running"
    verdict: Literal["confirmed_violation", "candidate", "no_violation_observed", "inconclusive"] = "inconclusive"
    confirmation: Literal["not_attempted", "not_needed", "confirmed", "flaky", "not_reproduced", "incomplete"] = "not_attempted"
    error_code: str | None = None
    kind: str | None = None
    required_replays: Literal[2] = 2
    reproductions: int = 0
    total_requests: int = 0
    fixture_requests: int = 0
    elapsed_seconds: float = 0
    shared_total_requests: int = 0
    shared_elapsed_seconds: float = 0
    max_requests: int
    max_runtime_seconds: float
    attempts: list[Attempt] = Field(default_factory=list)


@dataclass
class CheckResult:
    report: CheckReport
    directory: Path


def write_json(path: Path, model: BaseModel) -> None:
    """Atomically write a private derived report without editing observations."""
    temporary = path.with_name(f".{path.name}.tmp")
    fd = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(model.model_dump_json(indent=2) + "\n")
    temporary.replace(path)


async def reset_lab(config, budget, writer, report, key, transport_factory, clock):
    reason = budget.exhausted()
    if reason:
        raise RunAborted("budget_exhausted", reason)
    budget.requests += 1
    report.fixture_requests += 1
    started = clock()
    event = RequestEvent(sequence=budget.requests, step="reset_fixture", actor="fixture", generation=0,
        operation="reset_fixture", method="POST", path="/testing/reset", sent_at_utc=utc_now(), finished_at_utc=utc_now(),
        started_elapsed_seconds=started - budget.started, finished_elapsed_seconds=started - budget.started)
    remaining = budget.remaining()
    timeout = min(remaining, config.budget.request_timeout_seconds)
    try:
        transport = transport_factory() if transport_factory else None
        async with asyncio.timeout(timeout):
            async with httpx.AsyncClient(base_url=str(config.base_url), transport=transport, trust_env=False,
                                         follow_redirects=False) as client:
                async with client.stream("POST", "/testing/reset", headers={"X-Lab-Reset-Key": key}, timeout=timeout) as response:
                    event.status_code = response.status_code
                    body = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=4096):
                        if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                            event.body_truncated = True
                            raise RunAborted("execution_error", "reset_response_too_large")
                        body.extend(chunk)
                    try:
                        data = json.loads(body)
                    except (ValueError, UnicodeError, RecursionError):
                        data = None
                    status = data.get("status") if isinstance(data, dict) else None
                    # Never export arbitrary reset-response fields or headers.
                    event.response_json = {"status": status} if isinstance(status, str) else None
                    if not 200 <= response.status_code < 300 or status != "reset":
                        raise RunAborted("setup_failed", "reset_not_acknowledged")
        if budget.remaining() <= 0:
            raise RunAborted("budget_exhausted", "runtime_budget_exhausted")
    except TimeoutError:
        event.outcome, event.error_code = "error", "reset_timeout"
        raise RunAborted("budget_exhausted" if budget.remaining() <= 0 else "execution_error", "reset_timeout") from None
    except httpx.HTTPError:
        event.outcome, event.error_code = "error", "reset_transport_error"
        raise RunAborted("execution_error", "reset_transport_error") from None
    except RunAborted as exc:
        event.outcome, event.error_code = "error", exc.code
        raise
    except asyncio.CancelledError:
        event.outcome, event.error_code = "interrupted", "cancelled"
        raise
    finally:
        event.finished_at_utc = utc_now()
        event.finished_elapsed_seconds = clock() - budget.started
        writer.event(event)


async def check_lab(
    config: TargetConfig, output: str | Path, *, reset_key_env: str = "LAB_RESET_KEY",
    environ: Mapping[str, str] | None = None, clock: Callable[[], float] = monotonic,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    transport_factory: Callable[[], httpx.AsyncBaseTransport] | None = None,
    scenario=None, shared_budget: ExecutionBudget | None = None,
) -> CheckResult:
    """Destructive fixture check: resets the lab before every attempt.

    One shared request/runtime budget covers resets, discovery and confirmation.
    A candidate requires two matching clean replays to become confirmed.
    """
    environ = os.environ if environ is None else environ
    budget = shared_budget or ExecutionBudget(config.budget.max_requests, config.budget.max_runtime_seconds, clock)
    check_started, request_start = clock(), budget.requests
    report = CheckReport(check_id=f"check-{uuid4()}", started_at_utc=utc_now(),
        max_requests=budget.max_requests, max_runtime_seconds=budget.max_runtime_seconds)
    redactor = Redactor()
    writer = EvidenceWriter(Path(output), report.check_id, redactor)
    directory = writer.directory
    prior_identities: set[str] = set()
    prior_documents: set[str] = set()
    try:
        passwords = runner_class(config).validate_inputs(config, environ)
        if scenario is not None:
            try:
                scenario.validate_for(config)
            except ValueError:
                raise RunAborted("setup_failed", "invalid_scenario") from None
        for password in passwords.values():
            redactor.add(password)
        key = environ.get(reset_key_env)
        if not key:
            raise RunAborted("setup_failed", "missing_reset_key")
        if not key.isascii() or not all(33 <= ord(char) <= 126 for char in key):
            raise RunAborted("setup_failed", "invalid_reset_key")
        redactor.add(key)
        write_json(directory / "check.json", report)
        initial = None
        valid_replays = 0
        for number in range(3):
            await reset_lab(config, budget, writer, report, key, transport_factory, clock)
            result = await run_experiment(config, directory / "attempts", environ=environ,
                clock=clock, sleep=sleep, transport_factory=transport_factory, shared_budget=budget, scenario=scenario)
            analysis = analyze_run(config, result.directory)
            write_json(result.directory / "analysis.json", analysis)
            report.attempts.append(Attempt(phase="discovery" if number == 0 else "replay",
                run_id=result.report.run_id, evidence=str(result.directory.relative_to(directory)), analysis=analysis))
            if budget.remaining() <= 0:
                raise RunAborted("budget_exhausted", "runtime_budget_exhausted")
            # The document-lab reset contract regenerates all user IDs. Stable
            # IDs here indicate a noop/incorrect reset, not an independent run.
            if result.report.status == "completed":
                identities = {item["user_id"] for item in result.report.sessions.values()}
                document = result.report.bindings["document_id"]
                if identities & prior_identities or document in prior_documents:
                    raise RunAborted("setup_failed", "reset_not_clean")
                prior_identities.update(identities)
                prior_documents.add(document)
            if number == 0:
                initial = analysis
                report.verdict = analysis.verdict
                report.kind = analysis.kind
                if analysis.verdict != "candidate":
                    report.confirmation = "not_needed" if analysis.verdict == "no_violation_observed" else "not_attempted"
                    report.status = "completed" if result.report.status == "completed" else result.report.status if result.report.status in ("budget_exhausted", "execution_error", "setup_failed") else "setup_failed"
                    report.error_code = result.report.error_code or (analysis.reason if analysis.verdict == "inconclusive" else None)
                    break
                report.confirmation = "incomplete"
            else:
                if analysis.verdict != "inconclusive":
                    valid_replays += 1
                if analysis.verdict == "candidate" and analysis.kind == initial.kind and analysis.exposed_sessions == initial.exposed_sessions:
                    report.reproductions += 1
                if result.report.status == "budget_exhausted":
                    raise RunAborted("budget_exhausted", result.report.error_code)
                if number == 2:
                    report.status = "completed"
                    if valid_replays < 2:
                        report.confirmation = "incomplete"
                        report.status, report.error_code = "execution_error", "replay_inconclusive"
                    elif report.reproductions == 2:
                        report.verdict, report.confirmation = "confirmed_violation", "confirmed"
                    else:
                        report.confirmation = "flaky" if report.reproductions else "not_reproduced"
        if report.status == "running":
            report.status = "completed"
    except RunAborted as exc:
        report.status = exc.status if exc.status in ("setup_failed", "execution_error", "budget_exhausted") else "setup_failed"
        report.error_code = exc.code
        if report.verdict == "candidate":
            report.confirmation = "incomplete"
    except asyncio.CancelledError:
        report.status, report.error_code = "interrupted", "cancelled"
        raise
    except Exception:
        report.status, report.error_code = "execution_error", "internal_error"
        raise
    finally:
        report.total_requests = budget.requests - request_start
        report.elapsed_seconds = clock() - check_started
        report.shared_total_requests = budget.requests
        report.shared_elapsed_seconds = clock() - budget.started
        report.finished_at_utc = utc_now()
        try:
            write_json(directory / "check.json", report)
        finally:
            writer.close()
    return CheckResult(report, directory)
