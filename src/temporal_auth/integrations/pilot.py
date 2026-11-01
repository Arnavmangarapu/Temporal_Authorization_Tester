"""Bounded native-API pilots and transparent local comparison profiles.

This deliberately uses a separate evidence format from document_lab_v1/v2:
native endpoints and policies must not masquerade as document-lab observations.
"""

from dataclasses import dataclass
import json as jsonlib
import math
import os
from pathlib import Path
import random
import time
from uuid import uuid4

import httpx

from temporal_auth.integrations.adapters import ADAPTERS, AdapterError
from temporal_auth.integrations.fixtures import managed_fixture
from temporal_auth.runner.budget import ExecutionBudget
from temporal_auth.runner.evidence import Redactor, utc_now


PROFILES = ("temporal", "p4-single-event", "generic-valid-order")


class PilotBudget(ExecutionBudget):
    fixture_requests = 0

    def __init__(self, *args, should_cancel=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.should_cancel = should_cancel

    def remaining(self):
        if self.should_cancel and self.should_cancel():
            return 0.0
        return super().remaining()

    def reserve(self, *, fixture=False):
        if self.should_cancel and self.should_cancel():
            raise RuntimeError("cancelled")
        error = self.exhausted()
        if error:
            raise RuntimeError(error)
        self.requests += 1
        if fixture:
            self.fixture_requests += 1


def private_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        jsonlib.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")
    temporary.replace(path)


class Recorder:
    def __init__(self, origin, budget, path):
        self.origin, self.budget = origin, budget
        self.redactor = Redactor()
        self.events = []
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.stream = os.fdopen(fd, "w", encoding="utf-8")

    def request(self, step, method, path, *, headers=None, json=None, content=None, auth=None, secret=False):
        if not path.startswith("/") or path.startswith("//"):
            raise AdapterError("invalid_native_path")
        self.budget.reserve()
        event = {"sequence": self.budget.requests, "step": step, "method": method,
                 "path": path, "started": self.budget.clock() - self.budget.started,
                 "status": None, "body": None, "truncated": False,
                 "request_json": None if secret else self.redactor.clean(json),
                 "request_text": None if secret or content is None else self.redactor.clean(content.decode("utf-8", errors="replace")),
                 "credential_exchange_omitted": secret, "error": None}
        try:
            # A new client prevents ambient cookies from crossing actor sessions.
            with httpx.Client(base_url=self.origin, trust_env=False, follow_redirects=False,
                              timeout=min(5.0, self.budget.remaining())) as client:
                with client.stream(method, path, headers=headers, json=json, content=content, auth=auth) as response:
                    event["status"] = response.status_code
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        if self.budget.remaining() <= 0:
                            raise RuntimeError("runtime_budget_exhausted")
                        if len(body) + len(chunk) > 65536:
                            event["truncated"] = True
                            raise AdapterError("response_too_large")
                        body.extend(chunk)
                    result = httpx.Response(response.status_code, content=bytes(body),
                                            headers=response.headers, request=response.request)
                    if not secret:
                        event["body"] = self.redactor.clean(result.text)
                    return result
        except httpx.HTTPError:
            event["error"] = "http_error"
            raise AdapterError("http_error") from None
        except RuntimeError as exc:
            event["error"] = str(exc)
            raise
        finally:
            event["finished"] = self.budget.clock() - self.budget.started
            self.events.append(event)
            self.stream.write(jsonlib.dumps(event, allow_nan=False) + "\n")
            self.stream.flush()

    def close(self):
        self.stream.close()


def profile_probes(profile, seed):
    if profile not in PROFILES:
        raise ValueError("unsupported_comparison_profile")
    probes = ["old", "fresh"]
    rng = random.Random(seed)
    if profile == "p4-single-event":
        return [rng.choice(probes)]
    if profile == "generic-valid-order":
        rng.shuffle(probes)
    return probes


def analyze_observations(events, marker, probes, *, not_before, read_path):
    """Content/control oracle; never equate an HTTP success with disclosure."""
    def one(step):
        matches = [e for e in events if e["step"] == step]
        if len(matches) != 1:
            raise ValueError
        event = matches[0]
        if event.get("error") or event.get("truncated"):
            raise ValueError
        return event

    try:
        if not marker or not probes or len(set(probes)) != len(probes) or set(probes) - {"old", "fresh"}:
            raise ValueError
        transition = one("transition")
        for step in ("read_before", "control_before", "control_after"):
            e = one(step)
            if e["path"] != read_path or e["method"] != "GET" or e["status"] != 200 or marker not in (e["body"] or ""):
                raise ValueError
            if step != "control_after" and e["finished"] > transition["started"]:
                raise ValueError
        if transition["status"] not in (200, 204) or not_before < transition["finished"]:
            raise ValueError
        if (one("transition_control")["started"] < transition["finished"]
                or one("transition_control")["status"] not in (200, 404)):
            raise ValueError
        exposed = []
        for generation in probes:
            e = one("probe_" + generation)
            if e["path"] != read_path or e["method"] != "GET" or e["started"] < not_before:
                raise ValueError
            if one("control_after")["started"] < e["finished"]:
                raise ValueError
            if marker in (e["body"] or ""):
                exposed.append(generation)
            elif e["status"] not in (200, 401, 403, 404):
                raise ValueError
        return {"verdict": "candidate" if exposed else "no_violation_observed",
                "exposed_sessions": exposed, "reason": "protected_content" if exposed else "no_protected_content"}
    except (ValueError, KeyError, TypeError):
        return {"verdict": "inconclusive", "exposed_sessions": [], "reason": "invalid_controls_or_trace"}


@dataclass
class PilotResult:
    report: dict
    directory: Path


def run_pilot(target, tools, output, *, profile="temporal", seed=0,
              max_requests=500, max_runtime_seconds=180, fixture_factory=managed_fixture,
              should_cancel=None):
    if target not in ADAPTERS or profile not in PROFILES:
        raise ValueError("unsupported_target_or_profile")
    if isinstance(max_requests, bool) or not isinstance(max_requests, int) or max_requests < 1:
        raise ValueError("invalid_request_budget")
    if (isinstance(max_runtime_seconds, bool) or not isinstance(max_runtime_seconds, (int, float))
            or not math.isfinite(max_runtime_seconds) or max_runtime_seconds <= 0):
        raise ValueError("invalid_runtime_budget")
    directory = Path(output) / ("pilot-" + uuid4().hex)
    directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    budget = PilotBudget(max_requests, max_runtime_seconds, should_cancel=should_cancel)
    report = {"schema_version": "external-pilot-1", "target": target, "profile": profile,
              "seed": seed, "track": "existing_application", "started_at_utc": utc_now(),
              "status": "running", "verdict": "inconclusive", "reproductions": 0,
              "required_clean_reproductions": 2, "attempts": [],
              "max_requests": max_requests, "max_runtime_seconds": max_runtime_seconds,
              "policy_bound_seconds": 0, "probe_tolerance_seconds": 0.05,
              "policy_source": ADAPTERS[target].policy_source,
              "policy_basis": "annotated_local_fixture_contract",
              "scope": "protected read only; pilot, not frozen evaluation",
              "bootstrap_commands": 0, "bootstrap_seconds": 0,
              "error": None}
    probes = profile_probes(profile, seed)
    pattern = None
    private_json(directory / "pilot.json", report)
    try:
        for index in range(3):
            recorder = None
            attempt = {"id": uuid4().hex, "analysis": {"verdict": "inconclusive"},
                       "probes": probes, "isolation": "new_process_and_empty_temporary_database"}
            report["attempts"].append(attempt)
            attempt_dir = directory / attempt["id"]
            attempt_dir.mkdir(mode=0o700)
            try:
                with fixture_factory(target, Path(tools), budget=budget) as fixture:
                    report["version"] = fixture.version
                    report["binary_sha256"] = fixture.binary_sha256
                    report["bootstrap_commands"] += fixture.bootstrap_commands
                    report["bootstrap_seconds"] += fixture.bootstrap_seconds
                    attempt["origin"] = fixture.origin
                    recorder = Recorder(fixture.origin, budget, attempt_dir / "events.jsonl")
                    adapter = ADAPTERS[target](fixture, recorder)
                    adapter.setup()
                    old = adapter.login("old")
                    adapter.read("read_before", old)
                    adapter.read("control_before", adapter.owner)
                    if profile == "generic-valid-order":
                        # Same inputs and causal/evidence requirements; optional
                        # functional reads and probe order vary, not the oracle.
                        warmups = ["old", "control"]
                        random.Random(seed).shuffle(warmups)
                        for role in warmups:
                            adapter.read("warmup_" + role, old if role == "old" else adapter.owner)
                    adapter.transition()
                    ack = recorder.events[-1]["finished"]
                    adapter.verify_transition()
                    fresh = adapter.login("fresh") if "fresh" in probes else None
                    not_before = ack + 0.05
                    wait = not_before - (budget.clock() - budget.started)
                    if wait > 0:
                        if wait >= budget.remaining():
                            raise RuntimeError("runtime_budget_exhausted")
                        time.sleep(wait)
                    for generation in probes:
                        adapter.read("probe_" + generation, old if generation == "old" else fresh)
                    adapter.read("control_after", adapter.owner)
                    analysis = analyze_observations(recorder.events, adapter.marker, probes,
                                                   not_before=not_before, read_path=adapter.path)
                    attempt.update({"analysis": analysis, "marker": adapter.marker,
                                    "subject_id": adapter.subject_id, "resource_id": adapter.resource_id,
                                    "not_before": not_before, "read_path": adapter.path,
                                    "fresh_credential_matches_old": (adapter.sessions.get("old") == adapter.sessions.get("fresh")) if "fresh" in probes else None,
                                    "credential_generations": list(adapter.sessions)})
                if index == 0:
                    if analysis["verdict"] != "candidate":
                        report["verdict"] = analysis["verdict"]
                        break
                    pattern = analysis["exposed_sessions"]
                    report["verdict"] = "candidate"
                elif analysis["verdict"] == "candidate" and analysis["exposed_sessions"] == pattern:
                    report["reproductions"] += 1
                else:
                    report["confirmation"] = "not_reproduced"
                    break
                if report["reproductions"] == 2:
                    report["verdict"] = "confirmed_violation"
                    report["confirmation"] = "reproduced_under_fixture_policy"
            finally:
                if recorder is not None:
                    recorder.close()
                private_json(attempt_dir / "attempt.json", attempt)
        report["status"] = "completed"
    except (RuntimeError, ValueError, KeyError, httpx.HTTPError) as exc:
        report["status"] = "execution_error"
        # Only allow known codes; foreign exceptions can contain secrets/URLs.
        code = str(exc)
        allowed = {"unexpected_api_status", "invalid_api_json", "http_error", "response_too_large",
                   "cancelled",
                   "request_budget_exhausted", "runtime_budget_exhausted", "fixture_bootstrap_failed",
                   "fixture_start_failed", "fixture_start_timeout", "missing_target_binary",
                   "unexpected_target_version", "transition_not_acknowledged", "transition_state_mismatch",
                   "unexpected_binary_digest",
                   "subject_identity_mismatch", "subject_must_be_ordinary_user",
                   "resource_not_private_or_wrong_owner"}
        report["error"] = code if code in allowed else "adapter_execution_failed"
    except KeyboardInterrupt:
        report["status"] = "interrupted"
        raise
    finally:
        report["total_requests"] = budget.requests
        report["fixture_requests"] = budget.fixture_requests
        report["workflow_requests"] = budget.requests - budget.fixture_requests
        report["elapsed_seconds"] = budget.clock() - budget.started
        report["finished_at_utc"] = utc_now()
        private_json(directory / "pilot.json", report)
    return PilotResult(report, directory)
