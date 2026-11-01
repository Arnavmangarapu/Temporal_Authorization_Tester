"""Version-one contract for an annotated sharing-revocation experiment.

These models describe intent; they neither execute requests nor infer policy.
Unsupported lifecycle types are rejected until their semantics are implemented.
"""

from typing import Annotated, Literal, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator

Identifier = Annotated[str, Field(min_length=1, pattern=r"^[a-z][a-z0-9_]*$")]
NonEmpty = Annotated[str, Field(min_length=1)]
Seconds = Annotated[float, Field(ge=0, allow_inf_nan=False, strict=True)]
PositiveSeconds = Annotated[float, Field(gt=0, allow_inf_nan=False, strict=True)]
PositiveCount = Annotated[int, Field(gt=0, strict=True)]
JsonPointer = Annotated[str, Field(pattern=r"^(?:/(?:[^~/]|~[01])*)+$")]


class ConfigModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_default=True,
        hide_input_in_errors=True,
    )


class Actor(ConfigModel):
    username: NonEmpty
    password_env: Annotated[str, Field(pattern=r"^[A-Z_][A-Z0-9_]*$")]


class Operation(ConfigModel):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    path: NonEmpty

    @field_validator("path")
    @classmethod
    def require_application_path(cls, value: str) -> str:
        parts = urlsplit(value)
        if not value.startswith("/") or parts.scheme or parts.netloc:
            raise ValueError("operation path must be an application-relative path starting with /")
        if parts.query or parts.fragment or "?" in value or "#" in value:
            raise ValueError("operation path must not contain a query or fragment")
        return value


class Authentication(ConfigModel):
    kind: Literal["bearer_login"] = "bearer_login"
    login_operation: Identifier
    token_pointer: JsonPointer = "/access_token"


class KnownTiming(ConfigModel):
    mode: Literal["bounded"] = "bounded"
    anchor: Literal["transition_acknowledged"] = "transition_acknowledged"
    max_delay_seconds: Seconds
    tolerance_seconds: Seconds = 0.05
    source: NonEmpty


class UnknownTiming(ConfigModel):
    mode: Literal["unknown"] = "unknown"
    reason: NonEmpty


class RevocationPolicy(ConfigModel):
    lifecycle: Literal["sharing_revocation"] = "sharing_revocation"
    expected_access_after_transition: Literal["denied"] = "denied"
    timing: Annotated[KnownTiming | UnknownTiming, Field(discriminator="mode")]


class WorkflowOperations(ConfigModel):
    create_resource: Identifier
    grant_access: Identifier
    revoke_access: Identifier
    read_resource: Identifier


class SharingWorkflow(ConfigModel):
    owner: Identifier
    subject: Identifier
    control: Identifier
    operations: WorkflowOperations
    protected_field: JsonPointer = "/content"

    @model_validator(mode="after")
    def require_distinct_subject(self) -> Self:
        if self.subject in (self.owner, self.control):
            raise ValueError("subject must differ from both owner and control")
        return self


class Budget(ConfigModel):
    max_requests: PositiveCount = 500
    max_runtime_seconds: PositiveSeconds = 600.0
    request_timeout_seconds: PositiveSeconds = 10.0
    poll_interval_seconds: PositiveSeconds = 0.25

    @model_validator(mode="after")
    def bound_request_timeout(self) -> Self:
        if self.request_timeout_seconds > self.max_runtime_seconds:
            raise ValueError("request timeout must not exceed the run budget")
        return self


class TargetConfig(ConfigModel):
    schema_version: Literal["1"] = "1"
    name: NonEmpty
    base_url: HttpUrl
    actors: Annotated[dict[Identifier, Actor], Field(min_length=2)]
    operations: Annotated[dict[Identifier, Operation], Field(min_length=1)]
    authentication: Authentication
    policy: RevocationPolicy
    workflow: SharingWorkflow
    budget: Budget = Field(default_factory=Budget)

    @field_validator("base_url")
    @classmethod
    def require_origin(cls, value: HttpUrl) -> HttpUrl:
        if value.username is not None or value.password is not None:
            raise ValueError("base_url must not contain credentials")
        if value.path not in (None, "", "/") or value.query is not None or value.fragment is not None:
            raise ValueError("base_url must be an origin; put API prefixes in operation paths")
        return value

    @model_validator(mode="after")
    def validate_references_and_budget(self) -> Self:
        usernames = [actor.username for actor in self.actors.values()]
        if len(set(usernames)) != len(usernames):
            raise ValueError("actors must identify different usernames")
        for name in (self.workflow.owner, self.workflow.subject, self.workflow.control):
            if name not in self.actors:
                raise ValueError("workflow references an undefined actor")
        operation_ids = self.workflow.operations.model_dump()
        for operation_id in (*operation_ids.values(), self.authentication.login_operation):
            if operation_id not in self.operations:
                raise ValueError("workflow or authentication references an undefined operation")
        if self.operations[self.authentication.login_operation].method != "POST":
            raise ValueError("bearer login must reference a POST operation")
        if self.operations[self.workflow.operations.read_resource].method != "GET":
            raise ValueError("read_resource must reference a GET operation")
        for role in ("create_resource", "grant_access", "revoke_access"):
            if self.operations[operation_ids[role]].method == "GET":
                raise ValueError("create, grant and revoke operations must change state")
        timing = self.policy.timing
        if isinstance(timing, KnownTiming):
            deadline = timing.max_delay_seconds + timing.tolerance_seconds
            if self.budget.max_runtime_seconds <= deadline:
                raise ValueError("run budget must allow a probe after the policy deadline and tolerance")
        return self
