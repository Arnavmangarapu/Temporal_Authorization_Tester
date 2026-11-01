"""Serial, resumable campaigns with immutable evidence indexes and explicit scope."""

import asyncio
from collections import Counter
import fcntl
import json
import os
from pathlib import Path
import random
from time import monotonic
from uuid import uuid4

from temporal_auth.evaluation.controlled import run_controlled, run_early
from temporal_auth.evaluation.protocol import digest
from temporal_auth.integrations.evomaster import run_evomaster
from temporal_auth.integrations.pilot import private_json, run_pilot
from temporal_auth.integrations.restler import run_restler
from temporal_auth.runner.evidence import utc_now

TRACKS = ("logical", "early", "tcp", "minimize", "external", "native")


def work_items(protocol, track):
    spec = protocol["tracks"][track]
    if track in ("logical", "tcp"):
        items = [{"track": track, "case": case, "method": method, "seed": seed}
                 for case in spec["cases"] for seed in spec["seeds"] for method in spec["methods"]]
    elif track in ("early", "minimize"):
        items = [{"track": track, "case": case, "method": "early-diagnostic" if track == "early" else "seeded-dag", "seed": seed}
                 for case in spec["cases"] for seed in spec["seeds"]]
    elif track == "external":
        items = [{"track": track, "case": target, "method": profile, "seed": seed}
                 for target in spec["targets"] for seed in spec["seeds"] for profile in spec["profiles"]]
    elif track == "native":
        items = [{"track": track, "case": target, "method": tool, "seed": spec["seed"]}
                 for target in spec["targets"] for tool in spec["tools"]]
    else: raise ValueError("Unknown evaluation track")
    random.Random(protocol["execution_order_seed"]).shuffle(items)
    for item in items: item["key"] = ":".join(str(item[k]) for k in ("track", "case", "method", "seed"))
    return items


def evidence_index(directory):
    directory = Path(directory).resolve()
    result = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink(): raise ValueError("Evidence symlinks are unsupported")
        if path.is_file(): result[str(path.relative_to(directory))] = digest(path)
    return result


def load_rows(output, protocol):
    output = Path(output)
    header = output / "campaign.json"
    if not header.exists():
        if (output / "rows.jsonl").exists(): raise ValueError("Rows lack a campaign header")
        return []
    if json.loads(header.read_text())["protocol_sha256"] != protocol["protocol_sha256"]:
        raise ValueError("Output directory belongs to another protocol")
    path = output / "rows.jsonl"
    if not path.exists(): return []
    rows, keys = [], set()
    allowed = {item["key"]: item for track in TRACKS for item in work_items(protocol, track)}
    for line in path.read_text().splitlines():
        # A torn final line is a visible failure. Never silently drop it and
        # report the campaign as complete or append another JSON object to it.
        row = json.loads(line)
        key = row["key"]
        if key in keys or key not in allowed: raise ValueError("Duplicate or unexpected evaluation row")
        if any(row[name] != allowed[key][name] for name in ("track", "case", "method", "seed")):
            raise ValueError("Row metadata differs from frozen workload")
        directory = (output / row["evidence"]).resolve()
        if not directory.is_relative_to(output.resolve() / "runs"): raise ValueError("Evidence path escapes campaign")
        if evidence_index(directory) != row["evidence_sha256"]: raise ValueError("Evidence changed since its row was committed")
        if row.get("row_sha256") != row_digest(row): raise ValueError("Evaluation row changed")
        rows.append(row); keys.add(key)
    return rows


def row_digest(row):
    from temporal_auth.evaluation.protocol import canonical_digest
    return canonical_digest({key: value for key, value in row.items() if key != "row_sha256"})


def append_row(output, row):
    row["row_sha256"] = row_digest(row)
    fd = os.open(Path(output) / "rows.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")
        stream.flush(); os.fsync(stream.fileno())


async def execute_item(root, protocol, item, directory, tools):
    track, method, seed = item["track"], item["method"], item["seed"]
    if track in ("logical", "early", "tcp", "minimize"):
        case = next(case for case in protocol["cases"] if case["id"] == item["case"])
        if track == "early": return await run_early(root, case, seed, protocol["budget"], directory)
        return await run_controlled(root, case, method, seed, protocol["budget"], directory,
                                    tcp=track == "tcp", reduce=track == "minimize")
    if track == "external":
        result = await asyncio.to_thread(run_pilot, item["case"], tools, directory, profile=method, seed=seed,
                                        max_requests=protocol["budget"]["max_requests"],
                                        max_runtime_seconds=protocol["budget"]["max_runtime_seconds"])
        return {key: result.report.get(key) for key in ("status", "verdict", "confirmation", "reproductions", "total_requests",
                "fixture_requests", "workflow_requests", "elapsed_seconds", "error", "version", "binary_sha256")}
    if method == "evomaster":
        report, _ = await asyncio.to_thread(run_evomaster, item["case"], tools, directory, seed=seed,
                                           seconds=protocol["tracks"]["native"]["evomaster_search_seconds"], max_requests=500)
    else:
        report, _ = await asyncio.to_thread(run_restler, item["case"], tools, directory, seed=seed, max_requests=500)
    return {key: report.get(key) for key in ("tool", "status", "verdict", "comparison", "inputs", "limitations",
            "total_requests", "fixture_requests", "native_forwarded_requests", "elapsed_seconds", "error",
            "request_cap_reached", "exit_code", "compile_exit_code", "fuzz_exit_code")}


async def run_campaign(root, protocol, output, *, track="all", tools=None, progress=print):
    output = Path(output).resolve(); output.mkdir(parents=True, exist_ok=True, mode=0o700)
    tools = Path(tools or Path(root) / "artifacts/tools").resolve()
    if track != "all" and track not in TRACKS: raise ValueError("Unknown evaluation track")
    with (output / "campaign.lock").open("a") as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise ValueError("Another process owns this campaign") from None
        existing = load_rows(output, protocol)
        if not (output / "campaign.json").exists():
            private_json(output / "campaign.json", {"protocol_sha256": protocol["protocol_sha256"],
                "started_at_utc": utc_now(), "scope": protocol["scope"], "environment": protocol["environment"]})
            private_json(output / "protocol.json", protocol)
        done = {row["key"] for row in existing}
        items = [item for name in (TRACKS if track == "all" else (track,)) for item in work_items(protocol, name)]
        for index, item in enumerate(items):
            if item["key"] in done: continue
            directory = output / "runs" / (item["key"].replace(":", "__") + "__" + uuid4().hex[:8])
            directory.mkdir(parents=True, mode=0o700)
            start = monotonic()
            try:
                observation = await execute_item(root, protocol, item, directory, tools)
            except Exception as error:
                # Retain setup/infrastructure failure as a row. No arbitrary
                # exception text, environment or response bodies go to stdout.
                observation = {"status": "harness_error", "verdict": "inconclusive", "error": type(error).__name__}
                private_json(directory / "harness-error.json", observation)
            row = {**item, "observed": observation, "finished_at_utc": utc_now(),
                   "harness_wall_seconds": monotonic() - start, "evidence": str(directory.relative_to(output)),
                   "evidence_sha256": evidence_index(directory)}
            append_row(output, row); done.add(item["key"])
            progress(json.dumps({"progress": f"{index + 1}/{len(items)}", "key": item["key"],
                                 "status": observation.get("status"), "verdict": observation.get("verdict")}), flush=True)
            if observation.get("status") == "harness_error":
                raise ValueError("Harness error retained in rows.jsonl; investigate before collecting further results")
        counts = Counter(key.split(":", 1)[0] for key in done)
        private_json(output / "coverage.json", {name: {"recorded": counts[name], "required": len(work_items(protocol, name))} for name in TRACKS})
