"""Versioned evidence with credential redaction and incremental event storage."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RequestEvent(BaseModel):
    schema_version: str = "1"
    sequence: int
    step: str
    actor: str
    generation: int
    operation: str
    method: str
    path: str
    sent_at_utc: str
    finished_at_utc: str
    started_elapsed_seconds: float
    finished_elapsed_seconds: float
    status_code: int | None = None
    outcome: str = "response"
    request_json: Any = None
    response_json: Any = None
    response_text: str | None = None
    body_truncated: bool = False
    error_code: str | None = None


class RunReport(BaseModel):
    schema_version: str = "1"
    run_id: str
    tool_version: str
    adapter: str = "document_lab_v1"
    scenario: dict | None = None
    config_sha256: str
    target_name: str
    target_origin: str
    started_at_utc: str
    finished_at_utc: str | None = None
    elapsed_seconds: float = 0
    status: Literal[
        "running", "completed", "setup_failed", "execution_error",
        "budget_exhausted", "policy_unknown", "interrupted",
    ] = "running"
    verdict: Literal["not_evaluated"] = "not_evaluated"
    error_code: str | None = None
    request_count: int = 0
    policy: dict = Field(default_factory=dict)
    budget: dict = Field(default_factory=dict)
    bindings: dict[str, str] = Field(default_factory=dict)
    sessions: dict[str, dict] = Field(default_factory=dict)
    transition_acknowledged_elapsed_seconds: float | None = None
    probe_not_before_elapsed_seconds: float | None = None


class Redactor:
    def __init__(self):
        self.secrets: set[str] = set()

    def add(self, value: str) -> None:
        if value:
            self.secrets.add(value)

    def clean(self, value: Any) -> Any:
        if isinstance(value, str):
            for secret in sorted(self.secrets, key=len, reverse=True):
                value = value.replace(secret, "[REDACTED]")
            return value
        if isinstance(value, list):
            return [self.clean(item) for item in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                key = str(key)
                if any(word in key.lower() for word in ("password", "token", "authorization", "cookie", "secret")):
                    result[key] = "[REDACTED]"
                else:
                    result[key] = self.clean(item)
            return result
        return value


class EvidenceWriter:
    def __init__(self, root: Path, run_id: str, redactor: Redactor):
        self.directory = root / run_id
        self.directory.mkdir(parents=True, mode=0o700, exist_ok=False)
        self.redactor = redactor
        fd = os.open(self.directory / "events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.events = os.fdopen(fd, "w", encoding="utf-8")

    def event(self, event: RequestEvent) -> None:
        data = event.model_dump(mode="json")
        # Keep schema/status/timing metadata stable even for a very short
        # password that happens to occur in a protocol identifier.
        for key in ("path", "request_json", "response_json", "response_text"):
            data[key] = self.redactor.clean(data[key])
        self.events.write(json.dumps(data, ensure_ascii=True, allow_nan=False) + "\n")
        self.events.flush()

    def report(self, report: RunReport) -> None:
        temporary = self.directory / ".run.json.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            data = report.model_dump(mode="json")
            for key in ("target_name", "target_origin", "bindings"):
                data[key] = self.redactor.clean(data[key])
            timing = data["policy"].get("timing", {})
            for key in ("source", "reason"):
                if key in timing:
                    timing[key] = self.redactor.clean(timing[key])
            for session in data["sessions"].values():
                session["user_id"] = self.redactor.clean(session["user_id"])
            json.dump(data, stream, indent=2, allow_nan=False)
            stream.write("\n")
        temporary.replace(self.directory / "run.json")

    def close(self) -> None:
        self.events.close()
