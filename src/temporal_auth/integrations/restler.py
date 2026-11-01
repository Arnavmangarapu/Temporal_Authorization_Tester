"""Run the actual RESTler compiler and selected checkers in the pinned image."""

import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from uuid import uuid4

from temporal_auth.integrations.adapters import ADAPTERS
from temporal_auth.integrations.evomaster import native_schema, recording_proxy
from temporal_auth.integrations.fixtures import managed_fixture
from temporal_auth.integrations.pilot import PilotBudget, Recorder, private_json
from temporal_auth.runner.evidence import utc_now


RESTLER_COMMIT = "6d984deedbc54aad957fa3da0c7e9e5df23a2aee"
RESTLER_IMAGE = "temporal-auth-restler:6d984dee"


def run_restler(target, tools, output, *, seed=0, max_requests=500):
    if target not in ADAPTERS:
        raise ValueError("unsupported_native_target")
    directory = Path(output).resolve() / ("restler-" + uuid4().hex)
    directory.mkdir(parents=True, mode=0o700)
    budget = PilotBudget(max_requests, 180)
    report = {"schema_version": "native-tool-pilot-1", "tool": "RESTler", "commit": RESTLER_COMMIT,
              "image": RESTLER_IMAGE, "target": target, "seed": seed, "started_at_utc": utc_now(),
              "status": "running", "verdict": "not_evaluated", "telemetry_opt_out": True,
              "checkers": ["NameSpaceRule", "UseAfterFree"], "mode": "fuzz-lean",
              "comparison": "native compatibility smoke; not an input-matched effectiveness benchmark",
              "inputs": "native endpoint slice, fixed resource IDs, primary owner and unrelated unauthorized attacker",
              "limitations": ["Old/fresh recipient lifecycle and timing annotations are not consumed by native tool",
                              "UseAfterFree is enabled; collaborator removal does not delete the protected repository",
                              "No per-test reset; fixture isolated once per invocation",
                              "Native bug buckets are not clean-confirmed authorization findings"],
              "error": None}
    private_json(directory / "native.json", report)
    recorder = None
    try:
        inspection = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", RESTLER_IMAGE],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
        if inspection.returncode:
            raise RuntimeError("missing_restler_image")
        report["image_id"] = inspection.stdout.decode().strip()
        with managed_fixture(target, Path(tools), budget=budget) as fixture:
            report["target_version"] = fixture.version
            report["target_binary_sha256"] = fixture.binary_sha256
            report["bootstrap_commands"] = fixture.bootstrap_commands
            report["bootstrap_seconds"] = fixture.bootstrap_seconds
            recorder = Recorder(fixture.origin, budget, directory / "events.jsonl")
            adapter = ADAPTERS[target](fixture, recorder)
            adapter.setup()
            subject = adapter.login("old")
            attacker = adapter.create_attacker()
            positive = adapter.read("native_setup_subject", subject)
            negative = adapter.read("native_setup_attacker", attacker)
            if (positive.status_code != 200 or adapter.marker not in positive.text
                    or negative.status_code not in (401, 403, 404) or adapter.marker in negative.text):
                raise RuntimeError("invalid_native_controls")
            before_requests = budget.requests
            schema = native_schema(adapter, fixture.origin)
            with recording_proxy(recorder, {"owner": adapter.owner, "attacker": attacker}) as origin:
                schema["servers"] = [{"url": origin}]
                private_json(directory / "schema.json", schema)
                with TemporaryDirectory(prefix="temporal-restler-") as temp:
                    root = Path(temp)
                    private_json(root / "schema.json", schema)
                    private_json(root / "settings.json", {"target_ip": "127.0.0.1",
                        "target_port": int(origin.rsplit(":", 1)[1]), "no_ssl": True,
                        "max_sequence_length": 3, "time_budget": 0.005,
                        "request_throttle_ms": 100, "random_seed": seed,
                        "authentication": {"token": {"location": "/work/tokens.txt", "token_refresh_interval": 3600}},
                        "checkers": {"namespacerule": {"trigger_on_dynamic_objects": True,
                                     "trigger_objects": [adapter.path]}}})
                    (root / "tokens.txt").write_text("{'owner': {}, 'attacker': {}}\n"
                        + "Authorization: " + adapter.owner["Authorization"] + "\n"
                        + "Authorization: " + attacker["Authorization"] + "\n", encoding="utf-8")
                    (root / "tokens.txt").chmod(0o600)
                    for phase, arguments in (
                        ("compile", ["compile", "--api_spec", "/work/schema.json"]),
                        ("fuzz", ["fuzz-lean", "--grammar_file", "/work/Compile/grammar.py", "--dictionary_file",
                                  "/work/Compile/dict.json", "--settings", "/work/settings.json",
                                  "--enable_checkers", "namespacerule,useafterfree"])):
                        name = "temporal-restler-" + uuid4().hex
                        command = ["docker", "run", "--rm", "--name", name, "--network", "host",
                            "--user", f"{os.getuid()}:{os.getgid()}", "--volume", f"{root}:/work:Z", "--workdir", "/work",
                            "--env", "RESTLER_TELEMETRY_OPTOUT=1", RESTLER_IMAGE, "/RESTler/restler/Restler", *arguments]
                        with (root / f"{phase}.log").open("wb") as log:
                            process = subprocess.Popen(command, stdout=log, stderr=log, stdin=subprocess.DEVNULL)
                            try:
                                report[phase + "_exit_code"] = process.wait(timeout=max(1, budget.remaining()))
                            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                                subprocess.run(["docker", "rm", "--force", name], stdout=subprocess.DEVNULL,
                                               stderr=subprocess.DEVNULL, timeout=10)
                                process.kill()
                                process.wait(timeout=5)
                                raise
                        if report[phase + "_exit_code"]:
                            break
                    for source in root.rglob("*"):
                        if (source.is_file() and source.name != "tokens.txt" and source.stat().st_size <= 10_000_000
                                and source.suffix in (".log", ".txt", ".json", ".py")):
                            try:
                                content = source.read_text(encoding="utf-8")
                            except UnicodeError:
                                continue
                            destination = directory / "native-output" / source.relative_to(root)
                            destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                            destination.write_text(recorder.redactor.clean(content), encoding="utf-8")
                            destination.chmod(0o600)
            report["native_forwarded_requests"] = budget.requests - before_requests
            report["status"] = "completed" if report.get("fuzz_exit_code") == 0 else "tool_failed"
            if budget.requests >= budget.max_requests:
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
