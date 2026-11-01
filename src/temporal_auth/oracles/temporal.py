"""Conservative document-lab oracle; raw observations remain unchanged."""

import hashlib
import json
import math
from pathlib import Path
from typing import Literal
from urllib.parse import quote

from pydantic import BaseModel, ValidationError

from temporal_auth.config.models import KnownTiming, TargetConfig
from temporal_auth.runner.engine import finite_json_float, json_pointer, reject_json_constant
from temporal_auth.runner.evidence import RequestEvent, RunReport


class Analysis(BaseModel):
    schema_version: Literal["1"] = "1"
    run_id: str | None = None
    verdict: Literal["candidate", "no_violation_observed", "inconclusive"] = "inconclusive"
    reason: str
    kind: Literal["stale_session_access", "fresh_session_access", "revocation_enforcement", "stale_session_write", "fresh_session_write", "unauthorized_write"] | None = None
    exposed_sessions: list[str] = []
    evidence_sequences: list[int] = []


class EvidenceInvalid(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise EvidenceInvalid(reason)


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def load_json(text: str):
    return json.loads(text, object_pairs_hook=unique_keys,
                      parse_float=finite_json_float, parse_constant=reject_json_constant)


def successful(event: RequestEvent) -> bool:
    return event.status_code is not None and 200 <= event.status_code < 300


def field(event: RequestEvent, name: str):
    return event.response_json.get(name) if isinstance(event.response_json, dict) else None


def marker_at_pointer(event: RequestEvent, pointer: str, marker: str) -> bool:
    try:
        return json_pointer(event.response_json, pointer) == marker
    except (KeyError, IndexError, TypeError):
        return False


def contains_marker(value, marker: str) -> bool:
    if isinstance(value, str):
        return marker in value
    if isinstance(value, list):
        return any(contains_marker(item, marker) for item in value)
    if isinstance(value, dict):
        return any(marker in key or contains_marker(item, marker) for key, item in value.items())
    return False


def disclosure(event: RequestEvent, marker: str) -> bool:
    if contains_marker(event.response_json, marker) or marker in (event.response_text or ""):
        # A 403/500 response can still disclose the protected content.
        return True
    require(event.status_code in (200, 201, 202, 204, 401, 403, 404), "uninterpretable_probe")
    require(isinstance(event.response_json, dict) or event.status_code in (204, 401, 403, 404), "uninterpretable_probe")
    return False


def evaluate(config: TargetConfig, report: RunReport, events: list[RequestEvent]) -> Analysis:
    timing = config.policy.timing
    require(isinstance(timing, KnownTiming), "timing_policy_unknown")
    require(report.schema_version == "1" and all(e.schema_version == "1" for e in events), "unsupported_evidence_version")
    require(report.adapter == "document_lab_v1", "unsupported_adapter")
    require(report.config_sha256 == hashlib.sha256(config.model_dump_json().encode()).hexdigest(), "configuration_mismatch")
    require(report.target_origin == str(config.base_url), "target_mismatch")
    require(report.policy == config.policy.model_dump(), "policy_mismatch_or_redaction")
    require(report.status == "completed" and report.error_code is None, "collection_incomplete")
    require(report.request_count == len(events) and len(events) <= config.budget.max_requests, "request_count_mismatch")
    require(math.isfinite(report.elapsed_seconds) and 0 <= report.elapsed_seconds <= config.budget.max_runtime_seconds, "invalid_run_timing")
    workflow = config.workflow
    operations = workflow.operations
    roles = report.sessions
    expected_roles = {"owner", "subject_discovery", "subject_old", "subject_fresh"}
    separate_control = workflow.control != workflow.owner
    if separate_control:
        expected_roles.add("control")
    require(set(roles) == expected_roles, "session_roles_mismatch")
    for role, session in roles.items():
        actor = workflow.subject if role.startswith("subject_") else workflow.control if role == "control" else workflow.owner
        require(session.get("actor") == actor, "session_actor_mismatch")
        require(type(session.get("generation")) is int and session["generation"] > 0, "invalid_session_generation")
        require(isinstance(session.get("user_id"), str) and bool(session["user_id"]), "invalid_session_identity")
    subject = roles["subject_discovery"]["user_id"]
    owner = roles["owner"]["user_id"]
    control_role = "control" if separate_control else "owner"
    require(owner != subject and roles[control_role]["user_id"] != subject, "actor_identity_overlap")
    require(roles["subject_old"]["user_id"] == roles["subject_fresh"]["user_id"] == subject, "subject_identity_changed")
    require(roles["subject_discovery"]["generation"] < roles["subject_old"]["generation"] < roles["subject_fresh"]["generation"], "sessions_not_distinct")
    require(report.bindings.get("subject_id") == subject, "subject_binding_mismatch")
    document = report.bindings.get("document_id")
    marker = report.bindings.get("protected_marker")
    require(isinstance(document, str) and bool(document), "resource_binding_missing")
    require(isinstance(marker, str) and len(marker) >= 16 and "[REDACTED]" not in marker, "protected_marker_missing_or_redacted")
    require("[REDACTED]" not in document and "[REDACTED]" not in subject, "identity_redacted")

    expected = [
        ("login_owner", "owner", config.authentication.login_operation),
        ("login_subject_discovery", "subject_discovery", config.authentication.login_operation),
    ]
    if separate_control:
        expected.append(("login_control", "control", config.authentication.login_operation))
    expected += [
        ("create_resource", "owner", operations.create_resource),
        ("grant_access", "owner", operations.grant_access),
        ("login_subject_old", "subject_old", config.authentication.login_operation),
        ("read_before_revoke", "subject_old", operations.read_resource),
        ("control_before_revoke", control_role, operations.read_resource),
        ("revoke_access", "owner", operations.revoke_access),
        ("login_subject_fresh", "subject_fresh", config.authentication.login_operation),
        ("probe_old_session", "subject_old", operations.read_resource),
        ("probe_fresh_session", "subject_fresh", operations.read_resource),
        ("control_after_revoke", control_role, operations.read_resource),
    ]
    require(len(events) == len(expected), "workflow_events_missing_or_extra")
    previous_finish = 0.0
    encoded = {key: quote(value, safe="") for key, value in report.bindings.items()}
    for index, (event, (step, role, operation_id)) in enumerate(zip(events, expected), 1):
        require(event.sequence == index and event.step == step, "workflow_order_mismatch")
        session = roles[role]
        require(event.actor == session["actor"] and event.generation == session["generation"], "event_session_mismatch")
        operation = config.operations[operation_id]
        require(event.operation == operation_id and event.method == operation.method, "operation_mismatch")
        require(event.path == operation.path.format_map(encoded), "resource_path_mismatch_or_redaction")
        require(event.outcome == "response" and event.error_code is None and not event.body_truncated, "incomplete_response")
        require(event.status_code is not None and 100 <= event.status_code <= 599, "invalid_http_status")
        start, finish = event.started_elapsed_seconds, event.finished_elapsed_seconds
        require(math.isfinite(start) and math.isfinite(finish) and previous_finish <= start <= finish <= report.elapsed_seconds, "invalid_event_timing")
        previous_finish = finish
        if step.startswith("login_"):
            require(successful(event) and field(event, "user_id") == session["user_id"], "login_identity_mismatch")
            require(isinstance(event.request_json, dict) and event.request_json.get("username") == config.actors[event.actor].username, "login_actor_mismatch")
    by_step = {event.step: event for event in events}
    created, granted, revoked = (by_step[name] for name in ("create_resource", "grant_access", "revoke_access"))
    require(successful(created) and field(created, "id") == document and field(created, "owner_id") == owner, "resource_creation_mismatch")
    require(isinstance(created.request_json, dict) and created.request_json.get("content") == marker, "marker_creation_mismatch")
    require(successful(granted) and field(granted, "status") == "granted" and field(granted, "document_id") == document and field(granted, "subject_id") == subject, "grant_not_acknowledged")
    require(isinstance(granted.request_json, dict) and granted.request_json.get("subject_id") == subject, "grant_subject_mismatch")
    for step in ("read_before_revoke", "control_before_revoke", "control_after_revoke"):
        event = by_step[step]
        require(successful(event) and field(event, "id") == document and marker_at_pointer(event, workflow.protected_field, marker), "control_or_precondition_failed")
    require(successful(revoked) and field(revoked, "status") == "revoked" and field(revoked, "document_id") == document and field(revoked, "subject_id") == subject, "revocation_not_acknowledged")
    advertised = field(revoked, "max_delay_seconds")
    require(type(advertised) in (int, float) and math.isfinite(advertised) and 0 <= advertised <= timing.max_delay_seconds, "acknowledged_policy_conflict")
    ack = revoked.finished_elapsed_seconds
    deadline = ack + timing.max_delay_seconds + timing.tolerance_seconds
    require(report.transition_acknowledged_elapsed_seconds == ack and report.probe_not_before_elapsed_seconds == deadline, "timing_anchor_mismatch")
    probes = [by_step[name] for name in ("probe_old_session", "probe_fresh_session")]
    require(all(event.started_elapsed_seconds >= deadline for event in [*probes, by_step["control_after_revoke"]]), "probe_before_deadline")
    # Probe requests must not carry the marker themselves (reflection control).
    require(all(event.request_json is None and marker not in event.path for event in probes), "probe_contains_marker")
    exposed = [name for name, event in zip(("old", "fresh"), probes) if disclosure(event, marker)]
    if not exposed:
        return Analysis(run_id=report.run_id, verdict="no_violation_observed", reason="no_protected_marker_in_observed_probes")
    kind = "revocation_enforcement" if len(exposed) == 2 else "stale_session_access" if exposed == ["old"] else "fresh_session_access"
    return Analysis(run_id=report.run_id, verdict="candidate", reason="protected_content_after_revocation_bound",
                    kind=kind, exposed_sessions=exposed,
                    evidence_sequences=[event.sequence for name, event in zip(("old", "fresh"), probes) if name in exposed])


def analyze_run(config: TargetConfig, directory: str | Path) -> Analysis:
    """Evaluate local evidence; malformed or incomplete input is inconclusive."""
    run_id = None
    try:
        directory = Path(directory)
        require((directory / "run.json").stat().st_size <= 2_000_000, "report_too_large")
        report = RunReport.model_validate(load_json((directory / "run.json").read_text(encoding="utf-8")))
        run_id = report.run_id
        rows = []
        with (directory / "events.jsonl").open(encoding="utf-8") as stream:
            while line := stream.readline(2_000_001):
                require(len(line) <= 2_000_000 and len(rows) < 10_000, "events_too_large")
                rows.append(RequestEvent.model_validate(load_json(line)))
        if report.adapter == "document_lab_v2":
            from temporal_auth.oracles.generated import evaluate_generated
            return evaluate_generated(config, report, rows)
        require(config.schema_version == "1", "unsupported_adapter")
        return evaluate(config, report, rows)
    except EvidenceInvalid as exc:
        return Analysis(run_id=run_id, reason=str(exc))
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, IndexError, RecursionError, ValidationError):
        return Analysis(run_id=run_id, reason="invalid_or_unreadable_evidence")
