"""Optional shared budget for fixture requests and several clean executions."""

from collections.abc import Callable
from time import monotonic


class ExecutionBudget:
    def __init__(self, max_requests: int, max_runtime_seconds: float, clock: Callable[[], float] = monotonic):
        self.max_requests = max_requests
        self.max_runtime_seconds = max_runtime_seconds
        self.clock = clock
        self.started = clock()
        self.requests = 0

    def remaining(self) -> float:
        return self.max_runtime_seconds - (self.clock() - self.started)

    def exhausted(self) -> str | None:
        if self.requests >= self.max_requests:
            return "request_budget_exhausted"
        if self.remaining() <= 0:
            return "runtime_budget_exhausted"
        return None
