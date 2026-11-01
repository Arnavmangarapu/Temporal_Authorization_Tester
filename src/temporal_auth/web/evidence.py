"""Bounded, read-only evidence previews and credential-free replay exports."""

import io
import json
import math
from pathlib import Path
import zipfile


def read_json(path, limit=1_000_000):
    try:
        if path.stat().st_size > limit: return {}
        data = json.loads(path.read_text(), parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, RecursionError): return {}


def number(value):
    return float(value) if isinstance(value, (float, int)) and math.isfinite(value) else 0.0


def inspect_evidence(directory, job):
    groups, truncated, scanned = [], False, 0
    root = directory / "evidence"
    files = sorted(root.rglob("events.jsonl"), key=lambda p: (0 if p.parent.name.startswith("check-") else 1, p.stat().st_mtime)) if root.exists() else []
    for path in files[:30]:
        if path.is_symlink() or not path.resolve().is_relative_to(directory.resolve()): continue
        meta = read_json(path.parent / "run.json") or read_json(path.parent / "attempt.json")
        events = []
        with path.open("rb") as stream:
            while True:
                line = stream.readline(1_000_001)
                if not line: break
                scanned += len(line)
                if scanned > 4_000_000 or len(line) > 1_000_000:
                    truncated = True
                    break
                if not line.endswith(b"\n"): break  # A request may be flushing.
                try:
                    raw = json.loads(line, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
                    if not isinstance(raw, dict): continue
                    start = number(raw.get("started_elapsed_seconds", raw.get("started")))
                    finish = number(raw.get("finished_elapsed_seconds", raw.get("finished")))
                    step = str(raw.get("step", "unknown"))[:150]
                    role = "Old session" if "old" in step else "Fresh session" if "fresh" in step else "Other setup"
                    if any(word in step for word in ("owner", "control", "create_resource", "establish_access", "grant_access", "revoke_access")):
                        role = "Owner / control"
                    for name, session in meta.get("sessions", {}).items():
                        if session.get("actor") == raw.get("actor") and session.get("generation") == raw.get("generation"):
                            if "old" in name: role = "Old session"
                            elif "fresh" in name: role = "Fresh session"
                            elif name in ("owner", "control"): role = "Owner / control"
                    body = {key: raw[key] for key in ("request_json", "request_text", "response_json", "response_text", "body", "error_code", "error") if raw.get(key) is not None}
                    events.append({"sequence": raw.get("sequence"), "step": step, "label": step.replace("_", " ").capitalize(),
                        "method": str(raw.get("method", "")), "path": str(raw.get("path", "")),
                        "status": raw.get("status_code", raw.get("status")), "start": start, "finish": finish,
                        "duration_ms": max(0, finish-start)*1000, "role": role,
                        "body": json.dumps(body, indent=2, ensure_ascii=True)[:12000]})
                except (ValueError, TypeError, RecursionError): continue
        if events:
            transition = next((e for e in events if e["step"] in ("revoke_access", "transition")), None)
            timing = meta.get("policy", {}).get("timing", {})
            ack = number(meta.get("transition_acknowledged_elapsed_seconds")) or (transition["finish"] if transition else None)
            deadline = meta.get("probe_not_before_elapsed_seconds", meta.get("not_before"))
            if deadline is None and ack is not None and timing.get("mode") == "bounded":
                deadline = ack + number(timing.get("max_delay_seconds")) + number(timing.get("tolerance_seconds"))
            end = max(max(e["finish"] for e in events), number(deadline)) or 1
            for event in events: event["x"] = 160 + 640*event["start"]/end
            groups.append({"id": path.parent.name, "events": events[-100:], "count": len(events), "ack": ack,
                "deadline": deadline, "ack_x": 160+640*ack/end if ack is not None else None,
                "deadline_x": min(800,160+640*number(deadline)/end) if deadline is not None else None,
                "end": end, "fixture": all(e["step"] == "reset_fixture" for e in events)})
        if truncated: break
    report = {}
    for pattern in ("check.json", "pilot.json"):
        paths = list(root.rglob(pattern)) if root.exists() else []
        if paths: report = read_json(paths[0]); break
    result = dict(job.get("result") or {})
    fixture = read_json(directory / "fixture.json")
    if not result and report:
        result = {"verdict": report.get("verdict", "inconclusive"), "confirmation": report.get("confirmation", "not_attempted"),
                  "requests": report.get("shared_total_requests", report.get("total_requests", 0)),
                  "reproductions": report.get("reproductions", 0), "kind": report.get("kind"),
                  "engine_status": report.get("status"), "error": report.get("error_code", report.get("error"))}
    if (not job.get("result") and report.get("status") != "completed"
            and result.get("verdict") != "candidate" and root.exists()):
        for path in root.rglob("analysis.json"):
            analysis = read_json(path)
            if analysis.get("verdict") == "candidate":
                result.update(verdict="candidate", kind=analysis.get("kind"), confirmation="incomplete")
                break
    if job["status"] in ("queued", "running", "cancelling"):
        result["verdict"] = "pending"
        result["requests"] = sum(g["count"] for g in groups) + fixture.get("readiness_requests", 0)
    result.setdefault("verdict", "not_evaluated")
    result.setdefault("requests", sum(g["count"] for g in groups) + fixture.get("readiness_requests", 0))
    result.setdefault("reproductions", 0)
    startup_requests = fixture.get("readiness_requests", 0) or (report.get("fixture_requests", 0) if "target" in report else 0)
    return {"groups": groups, "truncated": truncated, "result": result, "report": report,
            "startup_requests": startup_requests}


REPLAY_SCRIPT = '''"""Replay with newly acquired credentials; requires temporal-auth-tester[web]."""
import asyncio
import json
import os
from pathlib import Path
import sys
from temporal_auth.web.models import JobSpec
from temporal_auth.web.execution import execute_spec

root = Path(__file__).resolve().parent
spec = JobSpec.model_validate(json.loads((root / "replay.json").read_text())["job"])
output = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "replayed-evidence"
tools = Path(os.environ.get("TEMPORAL_AUTH_TOOLS", "artifacts/tools"))
result = asyncio.run(execute_spec(spec, output, tools))
print(json.dumps(result, indent=2))
raise SystemExit({"no_violation_observed": 0, "confirmed_violation": 3, "candidate": 4}.get(result["verdict"], 1))
'''


def export_bundle(directory, job):
    memory = io.BytesIO()
    total = 0
    with zipfile.ZipFile(memory, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("replay.json", json.dumps({"schema_version": "web-replay-1", "job": job["spec"]}, indent=2))
        archive.writestr("replay.py", REPLAY_SCRIPT)
        archive.writestr("README.txt", "Run python replay.py [OUTPUT_DIRECTORY] with this project's web dependencies installed.\n"
            "Managed labs acquire new generated credentials. Configured labs require the environment references in replay.json and are reset before each attempt.\n"
            "Native applications require pinned binaries; set TEMPORAL_AUTH_TOOLS to their directory.\n"
            "Captured credentials are not included. Exit 3 signals a confirmed fixture-policy finding, not execution failure.\n")
        archive.writestr("job.json", json.dumps(job, indent=2))
        files = list(directory.rglob("*")) if directory.exists() else []
        for path in files:
            if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(directory.resolve()): continue
            if path.suffix not in (".json", ".jsonl", ".yaml") or path.name == "replay.json": continue
            total += path.stat().st_size
            if total > 64_000_000 or len(archive.namelist()) > 512:
                raise ValueError("Evidence exceeds the browser export limit. Use the private workspace directory.")
            archive.write(path, path.relative_to(directory).as_posix())
    return memory.getvalue()
