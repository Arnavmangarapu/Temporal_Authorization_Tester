"""Freeze/run/audit the shared post-transition GET pilot, separately from 9A."""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import random
from statistics import median
from uuid import uuid4

import typer

from temporal_auth.evaluation.protocol import canonical_digest, digest, environment, source_inventory
from temporal_auth.integrations import matched
from temporal_auth.integrations.adapters import ADAPTERS
from temporal_auth.integrations.evomaster import run_evomaster
from temporal_auth.integrations.fixtures import managed_fixture
from temporal_auth.integrations.pilot import PilotBudget, Recorder, private_json
from temporal_auth.integrations.restler import run_restler


ROOT = Path(__file__).resolve().parents[3]
app = typer.Typer(no_args_is_help=True, pretty_exceptions_show_locals=False)


def freeze(root, destination):
    destination = Path(destination)
    if destination.exists():
        raise ValueError("Protocol already exists")
    value = {"schema_version": "native-read-comparison-1", "comparison": matched.COMPARISON,
             "targets": ["gitea", "pocketbase"], "generations": ["old", "fresh"],
             "drivers": ["scripted", "evomaster", "restler"], "seeds": [1000, 1001, 1002],
             "order_seed": 20261102, "max_requests": 500, "max_runtime_seconds": 180,
             "evomaster_search_seconds": 10, "monitoring": False,
             "scope": "common post-transition inputs and coverage; no known defective target or recall denominator",
             "native_fault_labels": "retained as native output; not relabeled as confirmed authorization findings",
             "source_sha256": source_inventory(root), "environment": environment()}
    value["protocol_sha256"] = canonical_digest(value)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2); stream.write("\n")
    return value


def load_protocol(path, root):
    value = json.loads(Path(path).read_text())
    if (value.get("schema_version") != "native-read-comparison-1" or
            canonical_digest({k: v for k, v in value.items() if k != "protocol_sha256"}) != value.get("protocol_sha256")):
        raise ValueError("Protocol hash/schema mismatch")
    if value["source_sha256"] != source_inventory(root) or value["environment"] != environment():
        raise ValueError("Source/environment changed; use the frozen source or a new protocol")
    return value


def work_items(protocol):
    items = [(target, generation, driver, seed) for target in protocol["targets"]
             for generation in protocol["generations"] for driver in protocol["drivers"]
             for seed in protocol["seeds"]]
    random.Random(protocol["order_seed"]).shuffle(items)
    return items


def scripted(target, tools, output, generation, protocol):
    directory = Path(output) / ("scripted-" + uuid4().hex)
    directory.mkdir(mode=0o700, parents=True)
    budget = PilotBudget(protocol["max_requests"], protocol["max_runtime_seconds"])
    report = {"schema_version": "native-tool-pilot-1", "tool": "scripted", "target": target,
              "comparison": matched.COMPARISON, "status": "running", "verdict": "not_evaluated",
              "description": "Two deterministic GETs using the same eligible owner/recipient inputs; no search-efficiency claim"}
    recorder = None
    try:
        with managed_fixture(target, tools, budget=budget) as fixture:
            report.update(target_version=fixture.version, target_binary_sha256=fixture.binary_sha256)
            recorder = Recorder(fixture.origin, budget, directory / "events.jsonl")
            adapter = ADAPTERS[target](fixture, recorder)
            adapter.setup()
            sessions, contract = matched.prepare(adapter, budget, generation)
            report["input_contract"] = contract
            before = budget.requests
            adapter.read("native_owner_get", adapter.owner)
            adapter.read("native_subject_get", sessions[generation])
            report["native_forwarded_requests"] = budget.requests - before
            report["independent_observations"] = matched.finish(adapter, sessions, contract)
            report["harness_postcheck_requests"] = budget.requests - before - report["native_forwarded_requests"]
            report["status"] = "completed"
    except (RuntimeError, ValueError, OSError):
        report.update(status="execution_error", error="scripted_execution_failed")
    finally:
        if recorder: recorder.close()
        report.update(total_requests=budget.requests, fixture_requests=budget.fixture_requests,
                      elapsed_seconds=budget.clock() - budget.started)
        private_json(directory / "native.json", report)
    return report, directory


def evidence_index(directory):
    paths = sorted(directory.rglob("*"))
    if any(p.is_symlink() for p in paths):
        raise ValueError("Symlink in comparison evidence")
    return {str(p.relative_to(directory)): digest(p) for p in paths if p.is_file()}


def read_rows(output, protocol):
    path = output / "rows.jsonl"
    if not path.exists(): return []
    rows, seen = [], set()
    expected = set(work_items(protocol))
    for line in path.read_text().splitlines():
        row = json.loads(line)
        key = tuple(row["key"])
        if (key in seen or key not in expected or row["protocol_sha256"] != protocol["protocol_sha256"]
                or canonical_digest({k: v for k, v in row.items() if k != "row_sha256"}) != row["row_sha256"]):
            raise ValueError("Invalid/duplicate comparison row")
        relative = Path(row["directory"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Invalid evidence directory")
        directory = output / relative
        if not directory.is_dir() or directory.is_symlink() or evidence_index(directory) != row["evidence_sha256"]:
            raise ValueError("Comparison evidence changed")
        seen.add(key); rows.append(row)
    return rows


@contextmanager
def campaign_lock(output):
    with (output / ".campaign.lock").open("a") as stream:
        try: fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise ValueError("Campaign already running") from None
        try: yield
        finally: fcntl.flock(stream, fcntl.LOCK_UN)


def run(protocol, output, tools):
    output, tools = Path(output).resolve(), Path(tools).resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    with campaign_lock(output):
        snapshot = output / "protocol.json"
        if snapshot.exists() and json.loads(snapshot.read_text()) != protocol:
            raise ValueError("Output belongs to another protocol")
        if not snapshot.exists(): private_json(snapshot, protocol)
        rows = read_rows(output, protocol)
        done = {tuple(r["key"]) for r in rows}
        for target, generation, driver, seed in work_items(protocol):
            key = (target, generation, driver, seed)
            if key in done: continue
            base = output / "runs" / ("__".join(map(str, key)) + "__" + uuid4().hex[:8])
            kwargs = {"seed": seed, "max_requests": protocol["max_requests"],
                      "comparison": matched.COMPARISON, "generation": generation}
            if driver == "scripted": report, directory = scripted(target, tools, base, generation, protocol)
            elif driver == "evomaster":
                report, directory = run_evomaster(target, tools, base, seconds=protocol["evomaster_search_seconds"], **kwargs)
            else: report, directory = run_restler(target, tools, base, **kwargs)
            row = {"key": list(key), "protocol_sha256": protocol["protocol_sha256"],
                   "directory": str(directory.relative_to(output)), "report": report,
                   "evidence_sha256": evidence_index(directory)}
            row["row_sha256"] = canonical_digest(row)
            with (output / "rows.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(row, allow_nan=False) + "\n"); stream.flush()
                os.fsync(stream.fileno())
            print(f"{len(done) + 1}/{len(work_items(protocol))} {'/'.join(map(str, key))}: {report['status']}", flush=True)
            done.add(key)


def analyze(protocol, output):
    rows = read_rows(Path(output), protocol)
    summaries = []
    for target in protocol["targets"]:
        for generation in protocol["generations"]:
            for driver in protocol["drivers"]:
                selected = [r["report"] for r in rows if r["key"][:3] == [target, generation, driver]]
                complete = [r for r in selected if r["status"] == "completed"]
                observed = [r.get("independent_observations", {}) for r in complete]
                summaries.append({"target": target, "generation": generation, "driver": driver,
                    "recorded": len(selected), "completed": len(complete),
                    "exercised": sum(o.get("valid_subject_get_requests", 0) > 0 for o in observed),
                    "trace_candidates": sum(o.get("native_trace_content_verdict") == "candidate" for o in observed),
                    "trace_no_violation": sum(o.get("native_trace_content_verdict") == "no_violation_observed" for o in observed),
                    "inconclusive": sum(o.get("native_trace_content_verdict") == "inconclusive" for o in observed),
                    "controls_valid": sum(o.get("harness_controls", {}).get("verdict") in ("candidate", "no_violation_observed") for o in observed),
                    "credential_generations_equal": sum(r.get("input_contract", {}).get("old_and_fresh_credentials_equal", False) for r in complete),
                    "median_native_forwarded_requests": median([r["native_forwarded_requests"] for r in complete]) if complete else None,
                    "median_total_requests": median([r["total_requests"] for r in complete]) if complete else None})
    return {"schema_version": "native-read-comparison-results-1", "protocol_sha256": protocol["protocol_sha256"],
            "expected": len(work_items(protocol)), "recorded": len(rows),
            "all_rows_recorded": len(rows) == len(work_items(protocol)), "summaries": summaries,
            "defective_target_denominator": None, "recall": None, "native_fault_labels_evaluated": False,
            "claims": {"lifecycle_generation": False, "relative_effectiveness": False, "novelty": False},
            "limitations": ["Only annotated fixed-resource protected reads on two supported applications",
                            "Fresh processes and resource IDs per invocation; same semantic contract, not byte-identical inputs",
                            "Same HTTP/runtime ceilings; different search/stopping rules, so request counts are descriptive",
                            "Independent trace observations are not the tools' native fault labels",
                            "No independently defective application or clean-confirmed native finding"]}


@app.command("freeze")
def freeze_command(destination: Path, root: Path = ROOT):
    typer.echo(freeze(root, destination)["protocol_sha256"])


@app.command("run")
def run_command(protocol_path: Path, output: Path = typer.Option(...), tools: Path = typer.Option(...), root: Path = ROOT):
    run(load_protocol(protocol_path, root), output, tools)


@app.command("analyze")
def analyze_command(protocol_path: Path, output: Path = typer.Option(...), root: Path = ROOT):
    protocol = load_protocol(protocol_path, root)
    report = analyze(protocol, output)
    private_json(output / "analysis.json", report)
    typer.echo(json.dumps(report, indent=2))


if __name__ == "__main__":
    try: app()
    except (OSError, ValueError) as error:
        typer.echo(f"Comparison rejected: {error}", err=True); raise SystemExit(2) from None
