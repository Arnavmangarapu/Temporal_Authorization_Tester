"""Verify graph execution and protected effects independently of HTTP status."""

import hashlib
import math
from urllib.parse import quote

from temporal_auth.config.lifecycle import LifecycleConfig
from temporal_auth.config.models import KnownTiming
from temporal_auth.generator import Scenario
from temporal_auth.oracles.temporal import (
    Analysis, disclosure, field, marker_at_pointer, require, successful,
)
from temporal_auth.runner.generated import action_contract


def evaluate_generated(config, report, events):
    require(isinstance(config, LifecycleConfig), "configuration_version_mismatch")
    require(isinstance(config.policy.timing, KnownTiming), "timing_policy_unknown")
    require(report.schema_version == "1" and all(e.schema_version == "1" for e in events), "unsupported_evidence_version")
    require(report.config_sha256 == hashlib.sha256(config.model_dump_json().encode()).hexdigest(), "configuration_mismatch")
    require(report.target_origin == str(config.base_url) and report.policy == config.policy.model_dump(), "policy_or_target_mismatch")
    require(report.status == "completed" and report.error_code is None, "collection_incomplete")
    scenario = Scenario.model_validate(report.scenario)
    scenario.validate_for(config)
    expected = [node.id for node in scenario.nodes if node.id != "wait_for_deadline"]
    require(len(events) == report.request_count == len(expected) <= config.budget.max_requests, "event_count_mismatch")
    require(math.isfinite(report.elapsed_seconds) and 0 <= report.elapsed_seconds <= config.budget.max_runtime_seconds, "invalid_run_timing")
    cfg = config.workflow
    roles = report.sessions
    expected_roles = {name.removeprefix("login_") for name in expected if name.startswith("login_")}
    require(set(roles) == expected_roles, "session_roles_mismatch")
    for role, session in roles.items():
        actor = cfg.subject if role.startswith("subject_") else cfg.control if role == "control" else cfg.owner
        require(session.get("actor") == actor and type(session.get("generation")) is int and session["generation"] > 0, "invalid_session")
        require(isinstance(session.get("user_id"), str) and bool(session["user_id"]) and "[REDACTED]" not in session["user_id"], "identity_redacted")
    control_role = "owner" if cfg.control == cfg.owner else "control"
    owner, subject = roles["owner"]["user_id"], roles["subject_discovery"]["user_id"]
    require(owner != subject and roles[control_role]["user_id"] != subject, "actor_identity_overlap")
    require(roles["subject_old"]["user_id"] == roles["subject_fresh"]["user_id"] == subject, "subject_identity_changed")
    require(roles["subject_discovery"]["generation"] < roles["subject_old"]["generation"] < roles["subject_fresh"]["generation"], "sessions_not_distinct")
    bindings = report.bindings
    require(bindings.get("subject_id") == subject and bindings.get("owner_id") == owner, "identity_binding_mismatch")
    keys = ["document_id", "protected_marker"] + ([f"{role}_write_marker" for role in ("setup", "old", "fresh")] if config.policy.action == "write" else [])
    for key in keys:
        require(isinstance(bindings.get(key), str) and len(bindings[key]) >= 16 and "[REDACTED]" not in bindings[key], "binding_missing_or_redacted")
    require(len({bindings[key] for key in keys}) == len(keys), "markers_not_distinct")
    document, content = bindings["document_id"], bindings["protected_marker"]
    encoded = {key: quote(value, safe="") for key, value in bindings.items()}
    previous = 0.0
    by_step = {}
    for event, name in zip(events, expected):
        role, operation_id = action_contract(config, name)
        session = roles[role]
        operation = config.operations[operation_id]
        require(event.sequence == len(by_step) + 1 and event.step == name, "workflow_order_mismatch")
        require(event.actor == session["actor"] and event.generation == session["generation"], "event_session_mismatch")
        require(event.operation == operation_id and event.method == operation.method and event.path == operation.path.format_map(encoded), "operation_or_resource_mismatch")
        require(event.outcome == "response" and event.error_code is None and not event.body_truncated, "incomplete_response")
        require(event.status_code is not None and 100 <= event.status_code <= 599, "invalid_http_status")
        start, finish = event.started_elapsed_seconds, event.finished_elapsed_seconds
        require(math.isfinite(start) and math.isfinite(finish) and previous <= start <= finish <= report.elapsed_seconds, "invalid_event_timing")
        previous = finish
        if name.startswith("login_"):
            require(successful(event) and field(event, "user_id") == session["user_id"], "login_identity_mismatch")
            require(isinstance(event.request_json, dict) and event.request_json.get("username") == config.actors[event.actor].username, "login_actor_mismatch")
        elif name == "create_resource":
            model = {"sharing_revocation": "sharing", "role_downgrade": "role", "ownership_transfer": "ownership"}[config.policy.lifecycle]
            require(event.request_json == {"content": content, "access_model": model} and successful(event) and field(event, "id") == document and field(event, "owner_id") == owner, "resource_creation_mismatch")
        elif name == "setup_write":
            content = bindings["setup_write_marker"]
            require(event.request_json == {"content": content} and successful(event), "authorized_write_not_established")
        elif name in ("read_before_transition", "setup_write_readback", "control_before_transition", "warmup_old", "warmup_control"):
            expected_owner = subject if config.policy.lifecycle == "ownership_transfer" else owner
            require(successful(event) and field(event, "id") == document and field(event, "owner_id") == expected_owner and marker_at_pointer(event, cfg.protected_field, content), "precondition_or_control_failed")
        by_step[name] = event
    establish, transition = by_step["establish_access"], by_step["transition"]
    require(successful(establish) and successful(transition), "transition_not_acknowledged")
    life = config.policy.lifecycle
    if life == "sharing_revocation":
        permission = "write" if config.policy.action == "write" else "read"
        require(establish.request_json == {"subject_id": subject, "permission": permission} and field(establish, "status") == "granted", "access_not_established")
        require(field(establish, "document_id") == document and field(establish, "subject_id") == subject, "grant_binding_mismatch")
        require(transition.request_json is None and field(transition, "status") == "revoked" and field(transition, "document_id") == document and field(transition, "subject_id") == subject, "transition_not_acknowledged")
    elif life == "role_downgrade":
        require(establish.request_json == {"role": "editor"} and field(establish, "role") == "editor" and field(establish, "status") == "role_changed" and field(establish, "subject_id") == subject, "access_not_established")
        require(transition.request_json == {"role": "viewer"} and field(transition, "role") == "viewer" and field(transition, "status") == "role_changed" and field(transition, "subject_id") == subject, "transition_not_acknowledged")
    else:
        require(establish.request_json == {"new_owner_id": subject} and field(establish, "new_owner_id") == subject and field(establish, "document_id") == document and field(establish, "status") == "ownership_transferred", "access_not_established")
        require(transition.request_json == {"new_owner_id": owner} and field(transition, "new_owner_id") == owner and field(transition, "document_id") == document and field(transition, "status") == "ownership_transferred", "transition_not_acknowledged")
    advertised = field(transition, "max_delay_seconds")
    timing = config.policy.timing
    require(type(advertised) in (int, float) and math.isfinite(advertised) and 0 <= advertised <= timing.max_delay_seconds, "policy_conflict")
    ack = transition.finished_elapsed_seconds
    deadline = ack + timing.max_delay_seconds + timing.tolerance_seconds
    require(report.transition_acknowledged_elapsed_seconds == ack and report.probe_not_before_elapsed_seconds == deadline, "timing_anchor_mismatch")
    after = expected[expected.index("login_subject_fresh") + 1:]
    require(all(by_step[name].started_elapsed_seconds >= deadline for name in after), "probe_before_deadline")
    exposed = []
    evidence = []
    if config.policy.action == "read":
        control = by_step["control_after_transition"]
        require(successful(control) and field(control, "id") == document and field(control, "owner_id") == owner and marker_at_pointer(control, cfg.protected_field, content), "control_failed")
        for role in ("old", "fresh"):
            event = by_step[f"probe_{role}"]
            require(event.request_json is None and content not in event.path, "probe_contains_marker")
            if disclosure(event, content):
                exposed.append(role)
                evidence.append(event.sequence)
    else:
        for role in (("old", "fresh") if scenario.write_order == "old_first" else ("fresh", "old")):
            baseline, probe, readback = (by_step[f"{prefix}_{role}"] for prefix in ("baseline", "probe", "readback"))
            for observer in (baseline, readback):
                require(successful(observer) and field(observer, "id") == document and field(observer, "owner_id") == owner, "write_observer_failed")
            require(marker_at_pointer(baseline, cfg.protected_field, content), "write_baseline_changed")
            mutation = bindings[f"{role}_write_marker"]
            require(probe.request_json == {"content": mutation} and mutation != content, "write_marker_mismatch")
            if marker_at_pointer(readback, cfg.protected_field, mutation):
                exposed.append(role)
                evidence.extend([probe.sequence, readback.sequence])
                content = mutation
            else:
                require(marker_at_pointer(readback, cfg.protected_field, content), "unexpected_write_effect")
        control = by_step["control_after_transition"]
        require(successful(control) and field(control, "id") == document and field(control, "owner_id") == owner and marker_at_pointer(control, cfg.protected_field, content), "control_failed")
    if not exposed:
        return Analysis(run_id=report.run_id, verdict="no_violation_observed", reason="no_unauthorized_effect_observed")
    exposed.sort(key=lambda item: ("old", "fresh").index(item))
    if config.policy.action == "read":
        kind = "revocation_enforcement" if len(exposed) == 2 else "stale_session_access" if exposed == ["old"] else "fresh_session_access"
    else:
        kind = "unauthorized_write" if len(exposed) == 2 else "stale_session_write" if exposed == ["old"] else "fresh_session_write"
    return Analysis(run_id=report.run_id, verdict="candidate", reason="protected_effect_after_transition", kind=kind,
                    exposed_sessions=exposed, evidence_sequences=sorted(evidence))
