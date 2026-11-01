"""Execute a validated action DAG with live lifecycle state and write readbacks."""

from string import Formatter
from uuid import uuid4

from temporal_auth.config.models import KnownTiming
from temporal_auth.generator import generate_scenario
from temporal_auth.runner.engine import RunAborted, Runner


def operation_contracts(config):
    ops = config.workflow.operations
    life = config.policy.lifecycle
    establish_fields = {"subject_id"} if life == "role_downgrade" else {"document_id"}
    transition_fields = {"document_id", "subject_id"} if life == "sharing_revocation" else establish_fields
    return [
        (config.authentication.login_operation, "POST", set()),
        (ops.create_resource, "POST", set()), (ops.read_resource, "GET", {"document_id"}),
        (ops.establish_access, "POST", establish_fields),
        (ops.transition, "DELETE" if life == "sharing_revocation" else "POST", transition_fields),
        *([(ops.write_resource, "PATCH", {"document_id"})] if config.policy.action == "write" else []),
    ]


def action_contract(config, name):
    """Independent event names map to one annotated role/operation contract."""
    ops = config.workflow.operations
    control = "owner" if config.workflow.control == config.workflow.owner else "control"
    if name.startswith("login_"):
        return name.removeprefix("login_"), config.authentication.login_operation
    if name == "create_resource": return "owner", ops.create_resource
    if name == "establish_access": return "owner", ops.establish_access
    if name == "transition": return ("subject_old" if config.policy.lifecycle == "ownership_transfer" else "owner"), ops.transition
    if name in ("setup_write", "probe_old", "probe_fresh"):
        role = "subject_fresh" if name == "probe_fresh" else "subject_old"
        operation = ops.write_resource if name == "setup_write" or config.policy.action == "write" else ops.read_resource
        return role, operation
    if name in ("read_before_transition", "warmup_old"): return "subject_old", ops.read_resource
    return control, ops.read_resource


class GeneratedRunner(Runner):
    def __init__(self, *args, scenario=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.scenario = scenario or generate_scenario(self.config)
        self.report.adapter = "document_lab_v2"
        self.report.scenario = self.scenario.model_dump(mode="json")

    @staticmethod
    def validate_inputs(config, environ):
        if not isinstance(config.policy.timing, KnownTiming):
            raise RunAborted("policy_unknown", "timing_policy_unknown")
        try:
            for name, method, fields in operation_contracts(config):
                operation = config.operations[name]
                parts = list(Formatter().parse(operation.path))
                if operation.method != method or {field for _, field, _, _ in parts if field is not None} != fields:
                    raise ValueError
                if any(spec or conversion for _, _, spec, conversion in parts): raise ValueError
        except (ValueError, KeyError):
            raise RunAborted("setup_failed", "unsupported_adapter_config") from None
        passwords = {}
        for actor in (config.workflow.owner, config.workflow.subject, config.workflow.control):
            value = environ.get(config.actors[actor].password_env)
            if not value: raise RunAborted("setup_failed", "missing_credentials")
            passwords[actor] = value
        return passwords

    def preflight(self):
        super().preflight()
        try:
            self.scenario.validate_for(self.config)
        except ValueError:
            raise RunAborted("setup_failed", "invalid_scenario") from None

    async def workflow(self, stack):
        cfg = self.config
        sessions = {}
        content = f"protected-{uuid4()}"
        self.report.bindings["protected_marker"] = content
        if cfg.policy.action == "write":
            for role in ("setup", "old", "fresh"):
                self.report.bindings[f"{role}_write_marker"] = f"write-{role}-{uuid4()}"
        life = cfg.policy.lifecycle
        for node in self.scenario.nodes:
            name = node.id
            if name.startswith("login_"):
                role = name.removeprefix("login_")
                actor = cfg.workflow.subject if role.startswith("subject_") else cfg.workflow.control if role == "control" else cfg.workflow.owner
                session, user_id = await self.login(actor, role, stack)
                sessions[role] = session
                if role == "subject_discovery": self.report.bindings["subject_id"] = user_id
                if role == "owner": self.report.bindings["owner_id"] = user_id
                if role in ("subject_old", "subject_fresh") and user_id != self.report.bindings["subject_id"]:
                    raise RunAborted("setup_failed", "subject_identity_changed")
                if "owner" in sessions and "subject_discovery" in sessions and self.report.bindings["owner_id"] == self.report.bindings["subject_id"]:
                    raise RunAborted("setup_failed", "actor_identity_overlap")
                if "control" in self.report.sessions and "subject_id" in self.report.bindings and self.report.sessions["control"]["user_id"] == self.report.bindings["subject_id"]:
                    raise RunAborted("setup_failed", "actor_identity_overlap")
                continue
            if name == "wait_for_deadline":
                await self.wait_until(self.report.probe_not_before_elapsed_seconds)
                continue
            role, operation = action_contract(cfg, name)
            body = None
            if name == "create_resource":
                body = {"content": content, "access_model": {"sharing_revocation": "sharing", "role_downgrade": "role", "ownership_transfer": "ownership"}[life]}
            elif name == "establish_access":
                subject = self.report.bindings["subject_id"]
                body = {"subject_id": subject, "permission": "write" if cfg.policy.action == "write" else "read"} if life == "sharing_revocation" else {"role": "editor"} if life == "role_downgrade" else {"new_owner_id": subject}
            elif name == "transition":
                body = None if life == "sharing_revocation" else {"role": "viewer"} if life == "role_downgrade" else {"new_owner_id": self.report.bindings["owner_id"]}
            elif name == "setup_write": body = {"content": self.report.bindings["setup_write_marker"]}
            elif name in ("probe_old", "probe_fresh") and cfg.policy.action == "write":
                body = {"content": self.report.bindings[f"{name.removeprefix('probe_')}_write_marker"]}
            observation = await self.request(sessions[role], operation, name, body)
            if name == "create_resource":
                self.require_success(observation)
                if self.require_string(observation.data, "owner_id") != self.report.bindings["owner_id"]:
                    raise RunAborted("setup_failed", "resource_owner_mismatch")
                self.report.bindings["document_id"] = self.require_string(observation.data, "id")
            elif name in ("establish_access", "transition"):
                self.require_success(observation)
                if name == "transition":
                    ack = observation.event.finished_elapsed_seconds
                    self.report.transition_acknowledged_elapsed_seconds = ack
                    timing = cfg.policy.timing
                    self.report.probe_not_before_elapsed_seconds = ack + timing.max_delay_seconds + timing.tolerance_seconds
            elif name == "setup_write":
                self.require_success(observation)
                content = self.report.bindings["setup_write_marker"]
            elif name in ("read_before_transition", "setup_write_readback", "control_before_transition", "warmup_old", "warmup_control"):
                self.require_marker(observation, content)
