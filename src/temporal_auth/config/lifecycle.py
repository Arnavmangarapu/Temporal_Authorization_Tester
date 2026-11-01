"""Version-two, explicitly annotated lifecycle experiments; v1 stays unchanged."""

from typing import Annotated, Literal, Self

from pydantic import Field, HttpUrl, field_validator, model_validator

from temporal_auth.config.models import (
    Actor, Authentication, Budget, ConfigModel, Identifier, JsonPointer,
    KnownTiming, NonEmpty, Operation, RevocationPolicy, TargetConfig,
)


class LifecyclePolicy(RevocationPolicy):
    lifecycle: Literal["sharing_revocation", "role_downgrade", "ownership_transfer"]
    action: Literal["read", "write"]


class LifecycleOperations(ConfigModel):
    create_resource: Identifier
    establish_access: Identifier
    transition: Identifier
    read_resource: Identifier
    write_resource: Identifier | None = None


class LifecycleWorkflow(ConfigModel):
    owner: Identifier
    subject: Identifier
    control: Identifier
    operations: LifecycleOperations
    protected_field: JsonPointer = "/content"


class LifecycleConfig(ConfigModel):
    schema_version: Literal["2"]
    name: NonEmpty
    base_url: HttpUrl
    actors: Annotated[dict[Identifier, Actor], Field(min_length=2)]
    operations: Annotated[dict[Identifier, Operation], Field(min_length=1)]
    authentication: Authentication
    policy: LifecyclePolicy
    workflow: LifecycleWorkflow
    budget: Budget = Field(default_factory=Budget)

    @field_validator("base_url")
    @classmethod
    def require_origin(cls, value):
        return TargetConfig.require_origin(value)

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Self:
        workflow = self.workflow
        if workflow.subject in (workflow.owner, workflow.control):
            raise ValueError("subject must differ from owner and control")
        if len({actor.username for actor in self.actors.values()}) != len(self.actors):
            raise ValueError("actors must identify different usernames")
        if any(actor not in self.actors for actor in (workflow.owner, workflow.subject, workflow.control)):
            raise ValueError("workflow references an undefined actor")
        references = [self.authentication.login_operation, *workflow.operations.model_dump().values()]
        if any(name is not None and name not in self.operations for name in references):
            raise ValueError("workflow references an undefined operation")
        if self.policy.action == "write" and workflow.operations.write_resource is None:
            raise ValueError("write experiments require write_resource")
        if isinstance(self.policy.timing, KnownTiming):
            if self.budget.max_runtime_seconds <= self.policy.timing.max_delay_seconds + self.policy.timing.tolerance_seconds:
                raise ValueError("run budget must extend beyond the policy deadline")
        return self
