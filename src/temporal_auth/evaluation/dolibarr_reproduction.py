"""Separate frozen, repeated-instance reproduction of a known static REST bug."""

import json
import os
from pathlib import Path
import random
from statistics import median
from uuid import uuid4

import typer

from temporal_auth.evaluation.native_comparison import campaign_lock, evidence_index
from temporal_auth.evaluation.protocol import canonical_digest, digest, environment, source_inventory
from temporal_auth.integrations.dolibarr import REVISIONS, analyze_static, run_reproduction
from temporal_auth.integrations.pilot import private_json


ROOT = Path(__file__).resolve().parents[3]
app = typer.Typer(no_args_is_help=True, pretty_exceptions_show_locals=False)


def inventory(root):
    root = Path(root)
    items = source_inventory(root)
    for path in [*(root / "integrations/dolibarr").iterdir(),
                 root / "scripts/build_dolibarr_reproduction.py", root / "scripts/audit_dolibarr_reproduction.py"]:
        if path.is_file(): items[str(path.relative_to(root))] = digest(path)
    return dict(sorted(items.items()))


def freeze(root, destination):
    root, destination = Path(root).resolve(), Path(destination)
    if destination.exists(): raise ValueError("Protocol already exists")
    build = json.loads((root / "artifacts/tools/dolibarr-26066/build.json").read_text())
    for name, value in build["fixture_sha256"].items():
        if digest(root / name) != value: raise ValueError("Rebuild images after changing fixture templates")
    value = {"schema_version": "dolibarr-26066-protocol-1", "case": "Dolibarr/dolibarr#26066",
             "revisions": REVISIONS, "source_lock": build["source_lock"], "images": build["images"],
             "source_difference_verified": build["source_difference_verified"],
             "pairs": [1, 2, 3], "order_seed": 26066,
             "max_requests": 100, "max_seconds": 300, "monitoring": False,
             "expected": {"buggy": "protected_data_disclosed", "fixed": "access_denied"},
             "pair_inputs": "Same owner/allowed/restricted roles, product/category read rights, XTS currency and pair marker; fresh databases and credentials each invocation",
             "scope": "Known static authorization reproduction with explicit endpoint; not automatic discovery, temporal enforcement or held-out generalization",
             "source_sha256": inventory(root), "environment": environment()}
    value["protocol_sha256"] = canonical_digest(value)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x") as stream: json.dump(value, stream, indent=2); stream.write("\n")
    return value


def load_protocol(path, root):
    value = json.loads(Path(path).read_text())
    if (value.get("schema_version") != "dolibarr-26066-protocol-1" or
            canonical_digest({k: v for k, v in value.items() if k != "protocol_sha256"}) != value.get("protocol_sha256")):
        raise ValueError("Protocol hash/schema mismatch")
    if value["source_sha256"] != inventory(root) or value["environment"] != environment():
        raise ValueError("Source/environment changed; use frozen source or a new protocol")
    return value


def work_items(protocol):
    rows = [(v, p) for p in protocol["pairs"] for v in protocol["revisions"]]
    random.Random(protocol["order_seed"]).shuffle(rows)
    return rows


def read_rows(output, protocol):
    output = Path(output); path = output / "rows.jsonl"
    if not path.exists(): return []
    rows, seen = [], set()
    for line in path.read_text().splitlines():
        row = json.loads(line); key = tuple(row["key"])
        if (key in seen or key not in work_items(protocol) or row["protocol_sha256"] != protocol["protocol_sha256"]
                or canonical_digest({k: v for k, v in row.items() if k != "row_sha256"}) != row["row_sha256"]):
            raise ValueError("Invalid/duplicate reproduction row")
        relative = Path(row["directory"])
        if relative.is_absolute() or ".." in relative.parts: raise ValueError("Invalid evidence path")
        directory = output / relative
        if not directory.is_dir() or directory.is_symlink() or evidence_index(directory) != row["evidence_sha256"]:
            raise ValueError("Reproduction evidence changed")
        saved = json.loads((directory / "reproduction.json").read_text())
        if saved != row["report"] or saved["variant"] != key[0] or saved["revision"] != protocol["revisions"][key[0]]:
            raise ValueError("Reproduction report/key mismatch")
        if saved["status"] == "completed":
            events = [json.loads(e) for e in (directory / "events.jsonl").read_text().splitlines()]
            recalculated = analyze_static(events, marker=saved["marker"], state=saved["fixture"]["state"])
            if recalculated != saved["analysis"] or saved["verdict"] != recalculated["verdict"]:
                raise ValueError("Saved oracle result differs from raw evidence")
            if saved["marker"] != "TAT-protected-currency-pair-" + str(key[1]): raise ValueError("Pair input mismatch")
        seen.add(key); rows.append(row)
    return rows


def run(protocol, output):
    output = Path(output).resolve(); output.mkdir(mode=0o700, parents=True, exist_ok=True)
    with campaign_lock(output):
        snapshot = output / "protocol.json"
        if snapshot.exists() and json.loads(snapshot.read_text()) != protocol: raise ValueError("Output belongs to another protocol")
        if not snapshot.exists(): private_json(snapshot, protocol)
        done = {tuple(r["key"]) for r in read_rows(output, protocol)}
        for variant, pair in work_items(protocol):
            if (variant, pair) in done: continue
            base = output / "runs" / (f"{variant}__{pair}__" + uuid4().hex[:8])
            report, directory = run_reproduction(variant, base,
                expected_image_id=protocol["images"][variant]["id"], marker="TAT-protected-currency-pair-" + str(pair),
                max_requests=protocol["max_requests"], max_seconds=protocol["max_seconds"])
            row = {"key": [variant, pair], "protocol_sha256": protocol["protocol_sha256"],
                   "directory": str(directory.relative_to(output)), "report": report,
                   "evidence_sha256": evidence_index(directory)}
            row["row_sha256"] = canonical_digest(row)
            with (output / "rows.jsonl").open("a") as stream:
                stream.write(json.dumps(row, allow_nan=False) + "\n"); stream.flush(); os.fsync(stream.fileno())
            done.add((variant, pair))
            print(f"{len(done)}/{len(work_items(protocol))}: {variant}/{pair} {report['status']} {report['verdict']}", flush=True)


def analyze(protocol, output):
    rows = read_rows(output, protocol)
    by_key = {tuple(r["key"]): r["report"] for r in rows}
    pairs = [{"pair": pair, "reproduced": all(
        (report := by_key.get((variant, pair), {})).get("status") == "completed"
        and report.get("verdict") == protocol["expected"][variant]
        and report.get("fixture", {}).get("cleaned_up") is True for variant in protocol["revisions"])}
             for pair in protocol["pairs"]]
    summaries = []
    for variant in protocol["revisions"]:
        selected = [r["report"] for r in rows if r["key"][0] == variant]
        summaries.append({"variant": variant, "recorded": len(selected),
            "completed": sum(r["status"] == "completed" for r in selected),
            "expected_outcome": protocol["expected"][variant],
            "expected_outcome_observed": sum(r["verdict"] == protocol["expected"][variant] and r["status"] == "completed" for r in selected),
            "median_http_requests": median([r["requests"] for r in selected]) if selected else None,
            "median_elapsed_seconds": median([r["elapsed_seconds"] for r in selected]) if selected else None})
    return {"schema_version": "dolibarr-26066-results-1", "protocol_sha256": protocol["protocol_sha256"],
            "expected_runs": len(work_items(protocol)), "recorded_runs": len(rows),
            "all_rows_recorded": len(rows) == len(work_items(protocol)), "summaries": summaries,
            "pairs": pairs, "reproduced_pairs": sum(p["reproduced"] for p in pairs),
            "independent_known_defects": 1, "applications": 1, "source_revisions": 2,
            "blind_held_out": False, "temporal_claim": False, "automatic_discovery_claim": False,
            "competitor_effectiveness_measured": False, "population_recall": None,
            "interpretation": "Repeated clean-instance reproduction of one previously reported static permission defect and its upstream fix; repetitions are not additional defects"}


@app.command("freeze")
def freeze_command(destination: Path, root: Path = ROOT):
    typer.echo(freeze(root, destination)["protocol_sha256"])


@app.command("run")
def run_command(protocol_path: Path, output: Path = typer.Option(...), root: Path = ROOT):
    run(load_protocol(protocol_path, root), output)


@app.command("analyze")
def analyze_command(protocol_path: Path, output: Path = typer.Option(...), root: Path = ROOT):
    report = analyze(load_protocol(protocol_path, root), output)
    private_json(output / "analysis.json", report)
    typer.echo(json.dumps(report, indent=2))


if __name__ == "__main__":
    try: app()
    except (OSError, ValueError) as error:
        typer.echo(f"Reproduction rejected: {error}", err=True); raise SystemExit(2) from None
