"""Explicit lab modes and fixture credentials; no tester dependencies."""

import os
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, SecretStr

POLICY_BOUND_SECONDS = 5.0


class LabSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_default=True, hide_input_in_errors=True, frozen=True)

    mode: Literal["immediate", "delayed", "stale_session", "write_side_effect"] = "immediate"
    revocation_delay_seconds: Annotated[
        float, Field(ge=0, le=POLICY_BOUND_SECONDS, allow_inf_nan=False, strict=True)
    ] = POLICY_BOUND_SECONDS
    alice_password: SecretStr = Field(default="alice-demo-password", min_length=1)
    bob_password: SecretStr = Field(default="bob-demo-password", min_length=1)
    charlie_password: SecretStr = Field(default="charlie-demo-password", min_length=1)
    reset_key: SecretStr = Field(default="local-lab-reset-key", min_length=1)

    @classmethod
    def from_env(cls) -> Self:
        values = {}
        for field in ("mode", "alice_password", "bob_password", "charlie_password", "reset_key"):
            value = os.environ.get(f"LAB_{field.upper()}")
            if value is not None:
                values[field] = value
        if "LAB_REVOCATION_DELAY_SECONDS" in os.environ:
            values["revocation_delay_seconds"] = float(os.environ["LAB_REVOCATION_DELAY_SECONDS"])
        return cls.model_validate(values)
