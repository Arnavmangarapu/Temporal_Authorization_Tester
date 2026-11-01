"""Optional worker-owned exporter, reconstructed from authoritative local evidence.

No imports from this module occur when monitoring is disabled. Scrapes only read
the workspace. Complete JSONL lines are consumed once per exporter lifetime;
after a restart history is rebuilt, rather than incrementing a second ledger.
"""

from collections import Counter
import hashlib
import json
import math
import threading
import time

from prometheus_client import CollectorRegistry, start_http_server
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily, HistogramMetricFamily

from temporal_auth.web.store import ACTIVE

BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, float("inf"))
STATES = ("queued", "running", "cancelling", "completed", "cancelled", "interrupted", "failed")
VERDICTS = ("confirmed_violation", "candidate", "no_violation_observed", "inconclusive", "not_evaluated")
TARGETS = ("managed_lab", "configured_lab", "gitea", "pocketbase")
LIFECYCLES = ("sharing_revocation", "role_downgrade", "ownership_transfer")


def bounded(value, choices):
    return value if value in choices else "other"


def read_json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


class EvidenceCollector:
    def __init__(self, store):
        self.store = store
        self.lock = threading.Lock()
        self.started = time.monotonic()
        self.offsets = {}
        self.frozen = set()
        self.requests = Counter()
        self.buckets = Counter()
        self.duration_sums = Counter()
        self.sequences = Counter()
        self.probes = Counter()
        self.invalid_lines = 0

    def safe_files(self, directory, name):
        # Never follow a symlink out of the private evidence tree.
        if not directory.exists(): return []
        return sorted(p for p in directory.rglob(name)
                      if p.is_file() and not p.is_symlink() and p.resolve() == p.absolute()
                      and p.resolve().is_relative_to(self.store.root))

    def ingest(self, path, labels):
        previous = self.offsets.get(path, 0)
        if path.stat().st_size < previous:
            # Evidence is append-only. Refuse a rewritten file instead of
            # silently counting its requests twice.
            raise ValueError("Evidence file was truncated; restart exporter after restoring evidence.")
        with path.open("rb") as stream:
            stream.seek(previous)
            while line := stream.readline():
                if not line.endswith(b"\n"): break  # writer may be mid-flush
                self.offsets[path] = stream.tell()
                try:
                    event = json.loads(line)
                    start = float(event.get("started_elapsed_seconds", event.get("started")))
                    finish = float(event.get("finished_elapsed_seconds", event.get("finished")))
                    duration = finish - start
                    if not math.isfinite(duration) or duration < 0: raise ValueError
                    error = event.get("error_code") or event.get("error")
                    outcome = ("http_error" if error == "http_error" else "execution_error") if error else "response"
                    # Non-response outcomes such as a cancelled request must
                    # remain visible even without an explicit error code.
                    if not error and event.get("outcome", "response") != "response": outcome = "execution_error"
                    self.requests[(*labels, outcome)] += 1
                    self.duration_sums[labels] += duration
                    for boundary in BUCKETS:
                        if duration <= boundary: self.buckets[(*labels, boundary)] += 1
                except (ValueError, TypeError, AttributeError):
                    self.invalid_lines += 1

    def completed_sequences(self, directory, labels):
        for path in self.safe_files(directory, "run.json"):
            report = read_json(path)
            if report.get("status") != "completed": continue
            analysis = read_json(path.with_name("analysis.json"))
            self.sequences[(*labels, bounded(analysis.get("verdict", "not_evaluated"), VERDICTS))] += 1
            deadline = report.get("probe_not_before_elapsed_seconds")
            if isinstance(deadline, (int, float)) and math.isfinite(deadline):
                events = path.with_name("events.jsonl")
                if events in self.safe_files(path.parent, "events.jsonl"):
                    with events.open() as stream:
                        for line in stream:
                            try:
                                event = json.loads(line)
                                step = event.get("step")
                                start = event.get("started_elapsed_seconds")
                                if step in ("probe_old", "probe_fresh") and isinstance(start, (int, float)):
                                    self.probes[(*labels, step.removeprefix("probe_"),
                                                 "after_deadline" if start >= deadline else "before_deadline")] += 1
                            except ValueError: pass
        for path in self.safe_files(directory, "pilot.json"):
            for attempt in read_json(path).get("attempts", []):
                if "analysis" in attempt:
                    verdict = bounded(attempt["analysis"].get("verdict"), VERDICTS)
                    self.sequences[(*labels, verdict)] += 1

    def collect(self):
        with self.lock:
            yield from self.snapshot()

    def snapshot(self):
        with self.store.connection() as db:
            jobs = [self.store.decode(row) for row in db.execute("SELECT * FROM jobs ORDER BY created")]
        states, finished, findings = Counter(), Counter(), set()
        budget_requests = fixture_requests = errors = 0
        for job in jobs:
            spec, result = job["spec"], job["result"]
            labels = (bounded(spec.get("target"), TARGETS), bounded(spec.get("lifecycle"), LIFECYCLES))
            state = bounded(job["status"], STATES)
            states[state] += 1
            terminal = job["status"] not in ACTIVE
            if job["id"] not in self.frozen:
                directory = self.store.root / "jobs" / job["id"] / "evidence"
                for path in self.safe_files(directory, "events.jsonl"):
                    self.ingest(path, labels)
                if terminal:
                    self.completed_sequences(directory, labels)
                    self.frozen.add(job["id"])
            if not terminal: continue
            verdict = bounded(result.get("verdict", "not_evaluated"), VERDICTS)
            finished[(*labels, state, verdict)] += 1
            budget_requests += max(0, int(result.get("requests") or 0))
            fixture_requests += max(0, int(result.get("fixture_requests") or 0))
            errors += state == "failed"
            if verdict == "confirmed_violation":
                # Logical fixture/policy/effect signature, not resource UUIDs.
                # A configured target's complete policy is hashed internally;
                # its origin, YAML and hash are never exported as labels.
                policy = hashlib.sha256((spec.get("config_yaml") or "").encode()).hexdigest()
                findings.add((*labels, spec.get("fixture_mode"), spec.get("action"),
                              policy, bounded(result.get("kind"), ("stale_session_access", "fresh_session_access", "revocation_enforcement", "stale_session_write", "fresh_session_write", "unauthorized_write"))))

        gauge = GaugeMetricFamily("temporal_auth_jobs", "Durable jobs by queue state.", labels=["state"])
        for state in STATES: gauge.add_metric([state], states[state])
        yield gauge
        for name, help_text, counts, label_names in (
            ("jobs_finished", "Terminal jobs including cancellations; retained workspace history.", finished, ["target", "lifecycle", "state", "verdict"]),
            ("sequences_completed", "Completed lab workflows or analyzed native attempts, including confirmation replays.", self.sequences, ["target", "lifecycle", "outcome"]),
            ("requests", "Complete stored HTTP events, including recorded fixture requests; excludes unrecorded readiness probes.", self.requests, ["target", "lifecycle", "outcome"]),
            ("sampled_probes", "Completed lab read/write probe samples relative to the configured deadline; not enforcement latency.", self.probes, ["target", "lifecycle", "session", "boundary"]),
        ):
            family = CounterMetricFamily("temporal_auth_" + name, help_text, labels=label_names)
            for labels, count in sorted(counts.items()): family.add_metric(list(labels), count)
            yield family
        histogram = HistogramMetricFamily("temporal_auth_request_duration_seconds",
            "Observed HTTP-event duration; same coverage as requests_total.", labels=["target", "lifecycle"])
        for labels, total in sorted(self.duration_sums.items()):
            histogram.add_metric(list(labels), [(str(b) if math.isfinite(b) else "+Inf", self.buckets[(*labels, b)]) for b in BUCKETS], total)
        yield histogram
        for name, help_text, value in (
            ("confirmed_finding_signatures", "Distinct confirmed target/policy/action/effect signatures; seeded fixtures included. Not vulnerability IDs.", len(findings)),
            ("worker_uptime_seconds", "Uptime of the exporter-owning execution worker.", time.monotonic() - self.started),
            ("evidence_invalid_lines", "Skipped malformed complete evidence lines; investigate raw evidence if nonzero.", self.invalid_lines),
        ):
            yield GaugeMetricFamily("temporal_auth_" + name, help_text, value=value)
        for name, help_text, value in (
            ("execution_errors", "Jobs ending failed; budget/setup/execution failures included.", errors),
            ("terminal_job_budget_requests", "Terminal job stored request totals, including readiness and resets; partial summaries may omit requests.", budget_requests),
            ("terminal_job_fixture_requests", "Terminal job stored fixture request totals; not all have latency events.", fixture_requests),
        ):
            yield CounterMetricFamily("temporal_auth_" + name, help_text, value=value)


class WorkerExporter:
    def __init__(self, store, port):
        if not 1024 <= port <= 65535: raise ValueError("Invalid metrics port")
        self.registry = CollectorRegistry()
        self.collector = EvidenceCollector(store)
        self.registry.register(self.collector)
        self.server, self.thread = start_http_server(port, addr="127.0.0.1", registry=self.registry)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
