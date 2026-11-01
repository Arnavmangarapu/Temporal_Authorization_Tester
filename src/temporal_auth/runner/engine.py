"""One bounded sharing-revocation sequence, with no security verdict or replay."""

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from contextlib import AsyncExitStack
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
from string import Formatter
from time import monotonic
from typing import Any
from urllib.parse import quote
from uuid import uuid4

import httpx

from temporal_auth import __version__
from temporal_auth.config.models import KnownTiming, TargetConfig
from temporal_auth.runner.budget import ExecutionBudget
from temporal_auth.runner.evidence import EvidenceWriter, Redactor, RequestEvent, RunReport, utc_now

MAX_RESPONSE_BYTES = 65_536


def finite_json_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Non-finite JSON number")
    return number


def reject_json_constant(value: str) -> None:
    raise ValueError("Non-standard JSON constant")


class RunAborted(Exception):
    def __init__(self, status: str, code: str):
        self.status = status
        self.code = code
        super().__init__(code)


@dataclass
class RunResult:
    report: RunReport
    directory: Path


@dataclass
class Session:
    actor: str
    generation: int
    client: httpx.AsyncClient
    token: str | None = None


@dataclass
class Observation:
    event: RequestEvent
    data: Any


def json_pointer(data: Any, pointer: str) -> Any:
    """Resolve a validated, non-root JSON Pointer, including array indices."""
    value = data
    for part in pointer.split("/")[1:]:
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict):
            value = value[part]
        elif isinstance(value, list) and part.isascii() and part.isdecimal() and (part == "0" or not part.startswith("0")):
            value = value[int(part)]
        else:
            raise KeyError("JSON pointer does not resolve")
    return value


class Runner:
    def __init__(
        self, config: TargetConfig, output: Path, *,
        environ: Mapping[str, str], clock: Callable[[], float],
        sleep: Callable[[float], Awaitable[None]],
        transport_factory: Callable[[], httpx.AsyncBaseTransport] | None,
        shared_budget: ExecutionBudget | None = None,
    ):
        self.config = config
        self.environ = environ
        self.clock = clock
        self.sleep = sleep
        self.transport_factory = transport_factory
        self.shared_budget = shared_budget
        self.started = clock()
        self.redactor = Redactor()
        self.generations: dict[str, int] = {}
        self.passwords: dict[str, str] = {}
        self.report = RunReport(
            run_id=str(uuid4()), tool_version=__version__,
            config_sha256=hashlib.sha256(config.model_dump_json().encode()).hexdigest(),
            target_name=config.name, target_origin=str(config.base_url), started_at_utc=utc_now(),
            policy=config.policy.model_dump(), budget=config.budget.model_dump(),
        )
        self.writer = EvidenceWriter(output, self.report.run_id, self.redactor)

    def elapsed(self) -> float:
        return self.clock() - self.started

    def remaining(self) -> float:
        local = self.config.budget.max_runtime_seconds - self.elapsed()
        return min(local, self.shared_budget.remaining()) if self.shared_budget else local

    def check_budget(self) -> None:
        if self.shared_budget and self.shared_budget.exhausted():
            raise RunAborted("budget_exhausted", self.shared_budget.exhausted())
        if self.report.request_count >= self.config.budget.max_requests:
            raise RunAborted("budget_exhausted", "request_budget_exhausted")
        if self.remaining() <= 0:
            raise RunAborted("budget_exhausted", "runtime_budget_exhausted")

    @staticmethod
    def validate_inputs(config: TargetConfig, environ: Mapping[str, str]) -> dict[str, str]:
        if not isinstance(config.policy.timing, KnownTiming):
            raise RunAborted("policy_unknown", "timing_policy_unknown")
        expected = {
            config.authentication.login_operation: ("POST", set()),
            config.workflow.operations.create_resource: ("POST", set()),
            config.workflow.operations.grant_access: ("POST", {"document_id"}),
            config.workflow.operations.revoke_access: ("DELETE", {"document_id", "subject_id"}),
            config.workflow.operations.read_resource: ("GET", {"document_id"}),
        }
        if len(expected) != 5:
            raise RunAborted("setup_failed", "unsupported_adapter_config")
        try:
            for operation_id, (method, fields) in expected.items():
                operation = config.operations[operation_id]
                parsed = list(Formatter().parse(operation.path))
                actual = {name for _, name, _, _ in parsed if name is not None}
                if operation.method != method or actual != fields:
                    raise ValueError
                if any(spec or conversion for _, _, spec, conversion in parsed):
                    raise ValueError
        except ValueError:
            raise RunAborted("setup_failed", "unsupported_adapter_config") from None
        workflow = config.workflow
        passwords = {}
        for actor in dict.fromkeys((workflow.owner, workflow.subject, workflow.control)):
            password = environ.get(config.actors[actor].password_env)
            if not password:
                raise RunAborted("setup_failed", "missing_credentials")
            passwords[actor] = password
        return passwords

    def preflight(self) -> None:
        self.passwords = self.validate_inputs(self.config, self.environ)
        for password in self.passwords.values():
            self.redactor.add(password)

    def path(self, operation_id: str) -> str:
        encoded = {key: quote(value, safe="") for key, value in self.report.bindings.items()}
        return self.config.operations[operation_id].path.format_map(encoded)

    async def request(self, session: Session, operation_id: str, step: str, body: Any = None, *, login: bool = False) -> Observation:
        self.check_budget()
        operation = self.config.operations[operation_id]
        path = self.path(operation_id)
        self.report.request_count += 1
        if self.shared_budget:
            self.shared_budget.requests += 1
        event = RequestEvent(
            sequence=self.report.request_count, step=step, actor=session.actor, generation=session.generation,
            operation=operation_id, method=operation.method, path=path, sent_at_utc=utc_now(),
            finished_at_utc=utc_now(), started_elapsed_seconds=self.elapsed(), finished_elapsed_seconds=self.elapsed(),
            request_json={"username": self.config.actors[session.actor].username, "password": "[REDACTED]"} if login else body,
        )
        data = None
        remaining = self.remaining()
        run_limited = remaining <= self.config.budget.request_timeout_seconds
        timeout = min(remaining, self.config.budget.request_timeout_seconds)
        failure = None
        try:
            async with asyncio.timeout(timeout):
                headers = {"Authorization": f"Bearer {session.token}"} if session.token else {}
                async with session.client.stream(operation.method, path, json=body, headers=headers, timeout=timeout) as response:
                    event.status_code = response.status_code
                    content = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=4096):
                        room = MAX_RESPONSE_BYTES - len(content)
                        content.extend(chunk[:room])
                        if len(chunk) > room:
                            event.body_truncated = True
                            failure = RunAborted("execution_error", "response_too_large")
                            break
                    text = content.decode("utf-8", errors="replace")
                    if not event.body_truncated:
                        try:
                            data = json.loads(text, parse_float=finite_json_float, parse_constant=reject_json_constant)
                        except (ValueError, RecursionError):
                            pass
                    if login:
                        token = None
                        try:
                            token = json_pointer(data, self.config.authentication.token_pointer)
                        except (KeyError, IndexError, TypeError):
                            pass
                        if isinstance(token, str):
                            self.redactor.add(token)
                        # Login bodies can contain credentials in arbitrary shapes.
                        # Only identity metadata is exported; raw login text is omitted.
                        event.response_json = {
                            key: data[key] for key in ("user_id", "username", "token_type")
                            if isinstance(data, dict) and key in data
                        }
                    elif data is not None:
                        event.response_json = data
                    else:
                        event.response_text = text
        except TimeoutError:
            failure = RunAborted("budget_exhausted" if run_limited else "execution_error", "runtime_budget_exhausted" if run_limited else "request_deadline_exceeded")
        except httpx.TimeoutException:
            failure = RunAborted("execution_error", "network_timeout")
        except httpx.HTTPError:
            failure = RunAborted("execution_error", "transport_error")
        except asyncio.CancelledError:
            event.outcome = "error" if self.remaining() <= 0 else "interrupted"
            event.error_code = "runtime_budget_exhausted" if self.remaining() <= 0 else "cancelled"
            raise
        finally:
            event.finished_at_utc = utc_now()
            event.finished_elapsed_seconds = self.elapsed()
            if failure:
                event.outcome = "error"
                event.error_code = failure.code
            self.writer.event(event)
        if failure:
            raise failure
        if self.remaining() <= 0:
            raise RunAborted("budget_exhausted", "runtime_budget_exhausted")
        return Observation(event, data)

    @staticmethod
    def require_success(observation: Observation) -> None:
        if observation.event.status_code is None or not 200 <= observation.event.status_code < 300:
            raise RunAborted("setup_failed", "setup_http_status")

    @staticmethod
    def require_string(data: Any, field: str) -> str:
        value = data.get(field) if isinstance(data, dict) else None
        if not isinstance(value, str) or not value:
            raise RunAborted("setup_failed", "invalid_response_binding")
        return value

    async def login(self, actor: str, role: str, stack: AsyncExitStack) -> tuple[Session, str]:
        generation = self.generations.get(actor, 0) + 1
        self.generations[actor] = generation
        transport = self.transport_factory() if self.transport_factory else None
        client = await stack.enter_async_context(httpx.AsyncClient(
            base_url=str(self.config.base_url), transport=transport, follow_redirects=False,
            trust_env=False, headers={"Cache-Control": "no-cache", "User-Agent": "temporal-auth/0.1"},
        ))
        session = Session(actor, generation, client)
        observation = await self.request(session, self.config.authentication.login_operation, f"login_{role}", {
            "username": self.config.actors[actor].username, "password": self.passwords[actor],
        }, login=True)
        self.require_success(observation)
        user_id = self.require_string(observation.data, "user_id")
        try:
            token = json_pointer(observation.data, self.config.authentication.token_pointer)
        except (KeyError, IndexError, TypeError):
            token = None
        if not isinstance(token, str) or not token or not token.isascii() or any(char.isspace() for char in token):
            raise RunAborted("setup_failed", "invalid_login_token")
        session.token = token
        self.report.sessions[role] = {"actor": actor, "generation": generation, "user_id": user_id}
        return session, user_id

    def require_marker(self, observation: Observation, marker: str) -> None:
        self.require_success(observation)
        try:
            value = json_pointer(observation.data, self.config.workflow.protected_field)
        except (KeyError, IndexError, TypeError):
            value = None
        if value != marker:
            raise RunAborted("setup_failed", "protected_marker_not_established")

    async def wait_until(self, deadline: float) -> None:
        while True:
            self.check_budget()
            delay = deadline - self.elapsed()
            if delay <= 0:
                return
            if delay >= self.remaining():
                raise RunAborted("budget_exhausted", "insufficient_time_for_probe")
            await self.sleep(min(delay, self.config.budget.poll_interval_seconds))

    async def workflow(self, stack: AsyncExitStack) -> None:
        cfg = self.config
        operations = cfg.workflow.operations
        owner, owner_id = await self.login(cfg.workflow.owner, "owner", stack)
        _, subject_id = await self.login(cfg.workflow.subject, "subject_discovery", stack)
        if owner_id == subject_id:
            raise RunAborted("setup_failed", "actor_identity_overlap")
        control = owner
        if cfg.workflow.control != cfg.workflow.owner:
            control, control_id = await self.login(cfg.workflow.control, "control", stack)
            if control_id == subject_id:
                raise RunAborted("setup_failed", "actor_identity_overlap")
        self.report.bindings["subject_id"] = subject_id
        marker = f"protected-{uuid4()}"
        self.report.bindings["protected_marker"] = marker
        created = await self.request(owner, operations.create_resource, "create_resource", {"content": marker})
        self.require_success(created)
        if self.require_string(created.data, "owner_id") != owner_id:
            raise RunAborted("setup_failed", "resource_owner_mismatch")
        self.report.bindings["document_id"] = self.require_string(created.data, "id")
        granted = await self.request(owner, operations.grant_access, "grant_access", {"subject_id": subject_id})
        self.require_success(granted)
        old, old_id = await self.login(cfg.workflow.subject, "subject_old", stack)
        if old_id != subject_id:
            raise RunAborted("setup_failed", "subject_identity_changed")
        self.require_marker(await self.request(old, operations.read_resource, "read_before_revoke"), marker)
        self.require_marker(await self.request(control, operations.read_resource, "control_before_revoke"), marker)
        revoked = await self.request(owner, operations.revoke_access, "revoke_access")
        self.require_success(revoked)
        ack = revoked.event.finished_elapsed_seconds
        self.report.transition_acknowledged_elapsed_seconds = ack
        timing = cfg.policy.timing
        assert isinstance(timing, KnownTiming)
        deadline = ack + timing.max_delay_seconds + timing.tolerance_seconds
        self.report.probe_not_before_elapsed_seconds = deadline
        fresh, fresh_id = await self.login(cfg.workflow.subject, "subject_fresh", stack)
        if fresh_id != subject_id:
            raise RunAborted("setup_failed", "subject_identity_changed")
        await self.wait_until(deadline)
        await self.request(old, operations.read_resource, "probe_old_session")
        await self.request(fresh, operations.read_resource, "probe_fresh_session")
        await self.request(control, operations.read_resource, "control_after_revoke")

    async def run(self) -> RunResult:
        try:
            self.preflight()
            self.writer.report(self.report)
            async with AsyncExitStack() as stack:
                async with asyncio.timeout(max(self.remaining(), 0)):
                    await self.workflow(stack)
            self.report.status = "completed"
        except RunAborted as exc:
            self.report.status = exc.status
            self.report.error_code = exc.code
        except TimeoutError:
            self.report.status = "budget_exhausted"
            self.report.error_code = "runtime_budget_exhausted"
        except asyncio.CancelledError:
            self.report.status = "interrupted"
            self.report.error_code = "cancelled"
            raise
        except Exception:
            self.report.status = "execution_error"
            self.report.error_code = "internal_error"
            raise
        finally:
            self.report.finished_at_utc = utc_now()
            self.report.elapsed_seconds = self.elapsed()
            try:
                self.writer.report(self.report)
            finally:
                self.writer.close()
        return RunResult(self.report, self.writer.directory)


async def run_experiment(
    config: TargetConfig, output: str | Path, *, environ: Mapping[str, str] | None = None,
    clock: Callable[[], float] = monotonic,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    transport_factory: Callable[[], httpx.AsyncBaseTransport] | None = None,
    shared_budget: ExecutionBudget | None = None,
    scenario=None,
) -> RunResult:
    """Collect one lab-contract workflow; never infer a security verdict.

    Injection hooks are for deterministic tests. Production defaults use real
    HTTP, a monotonic clock and asyncio deadlines. No automatic reset or retry.
    """
    cls = runner_class(config)
    kwargs = {"scenario": scenario} if cls is not Runner else {}
    runner = cls(config, Path(output), environ=os.environ if environ is None else environ,
                 clock=clock, sleep=sleep, transport_factory=transport_factory, shared_budget=shared_budget, **kwargs)
    return await runner.run()


def runner_class(config):
    from temporal_auth.config.lifecycle import LifecycleConfig
    if isinstance(config, LifecycleConfig):
        from temporal_auth.runner.generated import GeneratedRunner
        return GeneratedRunner
    return Runner
