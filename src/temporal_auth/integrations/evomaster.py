"""A native EvoMaster smoke runner, explicitly separate from matched comparisons."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import hashlib
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from threading import Lock, Thread
import time
from uuid import uuid4

from temporal_auth.integrations.adapters import ADAPTERS
from temporal_auth.integrations.fixtures import managed_fixture
from temporal_auth.integrations.pilot import PilotBudget, Recorder, private_json
from temporal_auth.integrations import matched
from temporal_auth.runner.evidence import utc_now


def native_schema(adapter, origin):
    """Curated native endpoint slice with fixed fixture IDs; never rewrite auth."""
    errors = {str(status): {"description": name, "content": {"application/json": {
              "schema": {"type": "object", "additionalProperties": True}}}}
              for status, name in [(400, "Bad request"), (401, "Unauthenticated"),
                                   (403, "Forbidden"), (404, "Not found"), (422, "Validation error")]}
    content = ({"text/plain": {"schema": {"type": "string"}}} if adapter.fixture.target == "gitea"
               else {"application/json": {"schema": {"type": "object", "additionalProperties": True}}})
    paths = {adapter.path: {"get": {"operationId": "readProtectedResource",
             "responses": {"200": {"description": "Protected resource", "content": content}, **errors}}}}
    if adapter.fixture.target == "gitea":
        paths[adapter.collaborator] = {
            "delete": {"operationId": "revokeAccess", "responses": {"204": {"description": "Removed"}, **errors}},
            "put": {"operationId": "grantAccess", "requestBody": {"required": True,
                    "content": {"application/json": {"schema": {"type": "object", "required": ["permission"],
                    "properties": {"permission": {"type": "string", "enum": ["read"]}}}}}},
                    "responses": {"204": {"description": "Granted"}, **errors}}}
    else:
        path = f"/api/collections/{adapter.users}/records/{adapter.subject_id}"
        paths[path] = {"patch": {"operationId": "changeRole", "requestBody": {"required": True,
            "content": {"application/json": {"schema": {"type": "object", "required": ["role"],
            "properties": {"role": {"type": "string", "enum": ["editor", "viewer"]}}}}}},
            "responses": {"200": {"description": "Role updated", "content": {
                           "application/json": {"schema": {"type": "object", "additionalProperties": True}}}}, **errors}}}
    return {"openapi": "3.0.3", "info": {"title": "Annotated native lifecycle pilot slice", "version": "1"},
            "servers": [{"url": origin}], "paths": paths}


@contextmanager
def recording_proxy(recorder, sessions):
    lock = Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def dispatch(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400)
                return
            # Keep a fixed upstream origin. HTTP-security oracles also use HEAD,
            # OPTIONS and unusual verbs; forward those rather than manufacturing
            # proxy-generated 501 responses. Preserve raw bodies and test headers.
            if length < 0 or length > 65536 or not self.path.startswith("/api/"):
                self.send_error(400)
                return
            body = self.rfile.read(length) if length else None
            authorization = self.headers.get("Authorization")
            actor = next((name for name, headers in sessions.items()
                          if authorization and headers.get("Authorization") == authorization), "anonymous_or_other")
            try:
                with lock:
                    headers = {key: value for key, value in self.headers.items()
                               if key.lower() not in {"host", "connection", "transfer-encoding", "content-length"}}
                    response = recorder.request(f"native_{actor}_{self.command.lower()}", self.command, self.path,
                                                headers=headers, content=body)
                self.send_response(response.status_code)
                for key, value in response.headers.items():
                    if key.lower() not in {"content-length", "content-encoding", "connection", "transfer-encoding"}:
                        self.send_header(key, value)
                self.send_header("Content-Length", response.headers.get("content-length", "0")
                                 if self.command == "HEAD" else str(len(response.content)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(response.content)
            except (RuntimeError, OSError):
                self.send_error(503)

        def __getattr__(self, name):
            if name.startswith("do_"):
                return self.dispatch
            raise AttributeError(name)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def run_evomaster(target, tools, output, *, seed=0, seconds=10, max_requests=500,
                  comparison=None, generation="old"):
    matched.validate_comparison(comparison, generation)
    if target not in ADAPTERS or not isinstance(seconds, int) or not 1 <= seconds <= 60:
        raise ValueError("invalid_native_pilot_parameters")
    tools = Path(tools).resolve()
    jar = tools / "evomaster.jar"
    if not jar.is_file():
        raise ValueError("missing_evomaster_jar")
    with jar.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != "93f9c4a0de88b01395d2a1009776aa739973e9f64343778d2fd49c212fd17915":
            raise ValueError("unexpected_evomaster_digest")
    directory = Path(output).resolve() / ("evomaster-" + uuid4().hex)
    directory.mkdir(parents=True, mode=0o700)
    budget = PilotBudget(max_requests, 180 if comparison else 90 + seconds)
    report = {"schema_version": "native-tool-pilot-1", "tool": "EvoMaster", "version": "6.2.0",
              "target": target, "seed": seed, "search_seconds": seconds, "security": True,
              "started_at_utc": utc_now(), "status": "running", "verdict": "not_evaluated",
              "comparison": "native compatibility smoke; not an input-matched effectiveness benchmark",
              "inputs": "curated native endpoint slice, fixed resource IDs, owner and old-subject bearer tokens",
              "limitations": ["No fresh-login lifecycle annotation or propagation bound consumed by native tool",
                              "No per-test reset; fixture isolated once per invocation",
                              "Native fault labels are not clean-confirmed authorization findings"],
              "error": None}
    recorder = None
    private_json(directory / "native.json", report)
    try:
        with managed_fixture(target, tools, budget=budget) as fixture:
            report["target_version"] = fixture.version
            report["target_binary_sha256"] = fixture.binary_sha256
            report["bootstrap_seconds"] = fixture.bootstrap_seconds
            report["bootstrap_commands"] = fixture.bootstrap_commands
            recorder = Recorder(fixture.origin, budget, directory / "events.jsonl")
            adapter = ADAPTERS[target](fixture, recorder)
            adapter.setup()
            if comparison:
                sessions, contract = matched.prepare(adapter, budget, generation)
                old = sessions[generation]
                report.update(comparison=matched.COMPARISON, input_contract=contract,
                    inputs="fixed protected GET, post-transition owner and selected recipient credentials",
                    limitations=["Lifecycle and bound are prepared by the common harness, not generated by the native tool",
                                 "Read-only slice; no per-test reset or held-out defective application",
                                 "Native fault labels are separate from independent trace content observations"])
            else:
                old = adapter.login("old")
                before = adapter.read("native_setup_control", old)
                if before.status_code != 200 or adapter.marker not in before.text:
                    raise RuntimeError("native_setup_failed")
            before_requests = budget.requests
            schema = matched.read_schema(adapter, fixture.origin) if comparison else native_schema(adapter, fixture.origin)
            with recording_proxy(recorder, {"owner": adapter.owner, "subject" if comparison else "subject_old": old}) as origin:
                schema["servers"] = [{"url": origin}]
                private_json(directory / "schema.json", schema)
                with TemporaryDirectory(prefix="temporal-evomaster-") as temp:
                    root = Path(temp)
                    config = {"auth": [{"name": name, "fixedHeaders": [
                               {"name": "Authorization", "value": headers["Authorization"]}]}
                               for name, headers in (("owner", adapter.owner), ("subject", old))]}
                    private_json(root / "em.json", config)
                    # EvoMaster requires YAML/TOML; JSON is valid YAML, but the
                    # extension must be .yaml for its configuration loader.
                    (root / "em.json").rename(root / "em.yaml")
                    command = ["java", "-jar", str(jar), "--blackBox", "true", "--schema",
                        str(directory / "schema.json"), "--base", origin, "--configPath", str(root / "em.yaml"),
                        "--seed", str(seed), "--maxTime", f"{seconds}s", "--security", "true",
                        "--ratePerMinute", "600",
                        "--outputFormat", "JAVA_JUNIT_5", "--outputFolder", str(root / "generated"),
                        "--writeStatistics", "true", "--statisticsFile", str(root / "statistics.csv"),
                        "--writeWFCReportExcludeWebApp", "true"]
                    report["command_template"] = [value.replace(str(root), "<private-temp>") for value in command]
                    with (root / "native.log").open("wb") as log:
                        process = subprocess.Popen(command, cwd=root, stdout=log, stderr=log,
                                                   stdin=subprocess.DEVNULL)
                        try:
                            report["exit_code"] = process.wait(timeout=max(1, budget.remaining()))
                        except (subprocess.TimeoutExpired, KeyboardInterrupt):
                            process.kill()
                            process.wait(timeout=5)
                            raise
                    # Export text only, redacting all credentials known to the
                    # harness. Never export the raw authentication configuration.
                    for source in root.rglob("*"):
                        if (source.is_file() and source.name != "em.yaml" and source.stat().st_size <= 10_000_000
                                and source.suffix in (".log", ".java", ".json", ".csv", ".txt")):
                            try:
                                value = source.read_text(encoding="utf-8")
                            except UnicodeError:
                                continue
                            destination = directory / "native-output" / source.relative_to(root)
                            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                            destination.write_text(recorder.redactor.clean(value), encoding="utf-8")
                            destination.chmod(0o600)
            report["native_forwarded_requests"] = budget.requests - before_requests
            if comparison:
                report["independent_observations"] = matched.finish(adapter, sessions, contract)
                report["harness_postcheck_requests"] = budget.requests - before_requests - report["native_forwarded_requests"]
            report["status"] = "completed" if report["exit_code"] == 0 else "tool_failed"
            report["request_cap_reached"] = budget.requests >= budget.max_requests
            if report["request_cap_reached"]:
                report["status"] = "budget_exhausted"
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired):
        report["status"] = "execution_error"
        report["error"] = "native_execution_failed"
    except KeyboardInterrupt:
        report["status"] = "interrupted"
        raise
    finally:
        if recorder:
            recorder.close()
        report["total_requests"] = budget.requests
        report["fixture_requests"] = budget.fixture_requests
        report["elapsed_seconds"] = budget.clock() - budget.started
        report["finished_at_utc"] = utc_now()
        private_json(directory / "native.json", report)
    return report, directory
