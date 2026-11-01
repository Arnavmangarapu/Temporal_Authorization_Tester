"""Browser input contract. Credentials are environment references, never form fields."""

from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator
import yaml

from temporal_auth.config.loader import parse_config
from temporal_auth.config.lifecycle import LifecycleConfig
from temporal_auth.runner.engine import RunAborted, runner_class


class JobSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    title: str = Field(default="Untitled experiment", min_length=1, max_length=100)
    target: Literal["managed_lab", "configured_lab", "gitea", "pocketbase"] = "managed_lab"
    lifecycle: Literal["sharing_revocation", "role_downgrade", "ownership_transfer"] = "sharing_revocation"
    action: Literal["read", "write"] = "read"
    fixture_mode: Literal["immediate", "delayed", "stale_session", "write_side_effect"] = "stale_session"
    profile: Literal["temporal", "p4-single-event", "generic-valid-order"] = "temporal"
    seed: int = Field(default=7, strict=True, ge=0, le=2**31-1)
    max_requests: int = Field(default=500, strict=True, ge=1, le=5000)
    max_runtime_seconds: float = Field(default=600, gt=0, le=3600, allow_inf_nan=False, strict=True)
    config_yaml: str | None = Field(default=None, max_length=65536)
    reset_authorized: bool = False
    reset_key_env: str = Field(default="LAB_RESET_KEY", pattern=r"^[A-Z_][A-Z0-9_]*$")

    @model_validator(mode="after")
    def validate_scope(self):
        self.title = self.title.strip()
        if not self.title:
            raise ValueError("Enter a name for the experiment.")
        if self.target == "configured_lab":
            if not self.reset_authorized:
                raise ValueError("Acknowledge the dedicated lab reset before starting.")
            if not self.config_yaml:
                raise ValueError("Provide the dedicated lab configuration.")
            cfg = parse_config(self.config_yaml)
            if urlsplit(str(cfg.base_url)).hostname not in ("127.0.0.1", "localhost", "::1"):
                raise ValueError("The local workspace accepts only loopback lab targets.")
            # Store canonical, validated fields, not unknown YAML tags/values.
            self.config_yaml = yaml.safe_dump(cfg.model_dump(mode="json"), sort_keys=False)
            self.lifecycle = cfg.policy.lifecycle
            self.action = getattr(cfg.policy, "action", "read")
        elif self.config_yaml is not None:
            raise ValueError("Custom YAML is available only for a configured lab.")
        if self.target in ("gitea", "pocketbase") and self.action != "read":
            raise ValueError("Existing-application pilots currently support reads only.")
        if self.target in ("managed_lab", "configured_lab") and self.profile != "temporal":
            raise ValueError("Comparison profiles are available for native application pilots.")
        return self


def lab_config(spec: JobSpec, origin="http://127.0.0.1:8001"):
    if spec.target == "configured_lab":
        cfg = parse_config(spec.config_yaml)
        data = cfg.model_dump(mode="json")
    else:
        transitions = {"sharing_revocation": "revoke_share", "role_downgrade": "change_role", "ownership_transfer": "transfer_owner"}
        establish = {"sharing_revocation": "grant_share", "role_downgrade": "change_role", "ownership_transfer": "transfer_owner"}
        paths = {"login": ("POST", "/auth/login"), "create_document": ("POST", "/documents"),
                 "grant_share": ("POST", "/documents/{document_id}/shares"),
                 "revoke_share": ("DELETE", "/documents/{document_id}/shares/{subject_id}"),
                 "read_document": ("GET", "/documents/{document_id}"),
                 "write_document": ("PATCH", "/documents/{document_id}"),
                 "change_role": ("POST", "/users/{subject_id}/role"),
                 "transfer_owner": ("POST", "/documents/{document_id}/owner")}
        operations = {"create_resource": "create_document", "establish_access": establish[spec.lifecycle],
                      "transition": transitions[spec.lifecycle], "read_resource": "read_document"}
        if spec.action == "write":
            operations["write_resource"] = "write_document"
        data = {"schema_version": "2", "name": "managed-document-lab",
            "base_url": origin, "actors": {name: {"username": name, "password_env": f"LAB_{name.upper()}_PASSWORD"}
                                           for name in ("alice", "bob")},
            "operations": {key: {"method": method, "path": path} for key, (method, path) in paths.items()},
            "authentication": {"kind": "bearer_login", "login_operation": "login", "token_pointer": "/access_token"},
            "policy": {"lifecycle": spec.lifecycle, "action": spec.action, "expected_access_after_transition": "denied",
                "timing": {"mode": "bounded", "anchor": "transition_acknowledged", "max_delay_seconds": 5.0,
                           "tolerance_seconds": 0.05, "source": "Document-lab contract: changes enforced within 5 seconds of acknowledgement."}},
            "workflow": {"owner": "alice", "subject": "bob", "control": "alice", "operations": operations,
                         "protected_field": "/content"}}
    budget = data.setdefault("budget", {})
    budget.update(max_requests=spec.max_requests, max_runtime_seconds=float(spec.max_runtime_seconds))
    budget["request_timeout_seconds"] = min(budget.get("request_timeout_seconds", 10.0), spec.max_runtime_seconds)
    cfg = parse_config(yaml.safe_dump(data, sort_keys=False))
    if isinstance(cfg, LifecycleConfig):
        return cfg
    return cfg


def preview(spec: JobSpec, environ: dict):
    if spec.target in ("gitea", "pocketbase"):
        return {"valid": True, "track": "Existing application", "policy": "Annotated local native read policy",
                "missing_credentials": [], "notice": "Starts a disposable native application. Tool binaries must be installed."}
    cfg = lab_config(spec)
    required = {cfg.actors[name].password_env for name in (cfg.workflow.owner, cfg.workflow.subject, cfg.workflow.control)} | {spec.reset_key_env}
    missing = sorted(key for key in required if not environ.get(key)) if spec.target == "configured_lab" else []
    if cfg.policy.timing.mode == "unknown": missing = []
    # Validate adapter contracts without resolving real credentials or doing I/O.
    if cfg.policy.timing.mode != "unknown":
        try:
            runner_class(cfg).validate_inputs(cfg, {key: "validation-placeholder" for key in required})
        except RunAborted:
            raise ValueError("The configured operations do not match a supported lab adapter.") from None
    return {"valid": True, "track": "Controlled lab", "policy": cfg.policy.model_dump(),
            "missing_credentials": missing,
            "notice": "Timing is unknown: this check will be inconclusive without target requests." if cfg.policy.timing.mode == "unknown"
            else "Discovery is followed by two clean replays only when a candidate is found."}
