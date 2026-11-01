"""Freeze the corpus, seeds, budgets and implementation before a campaign."""

import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform

from temporal_auth.integrations.pilot import private_json
from temporal_auth.runner.evidence import utc_now

METHODS = ("seeded-dag", "canonical-dag", "seeded-minimal")
LIVES = ("sharing", "role", "ownership")
MODES = ("immediate", "delayed", "stale_session", "write_side_effect")
SEEDS = tuple(range(1000, 1010))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def corpus():
    cases = []
    for life in LIVES:
        for action in ("read", "write"):
            for mode in MODES:
                defect = mode == "stale_session" or (mode == "write_side_effect" and action == "write")
                cases.append({"id": f"{life}-{action}-{mode}", "life": life, "action": action, "mode": mode,
                    "overlay": "none", "truth": "violation" if defect else "correct",
                    "root_cause": "stale_snapshot" if mode == "stale_session" else "commit_before_denial" if defect else None})
    for overlay, mode, truth, cause in (
        ("disclosure_403", "stale_session", "violation", "stale_snapshot"),
        ("public_metadata_200", "immediate", "correct", None),
        ("control_failure", "immediate", "inconclusive", None),
        ("unknown_policy", "immediate", "inconclusive", None),
        ("unavailable", "immediate", "inconclusive", None),
    ):
        cases.append({"id": "sharing-read-" + overlay, "life": "sharing", "action": "read", "mode": mode,
                      "overlay": overlay, "truth": truth, "root_cause": cause})
    return cases


def source_inventory(root):
    root = Path(root).resolve()
    files = [root / "pyproject.toml", root / "integrations/tools.lock.json"]
    for name in ("src", "targets", "examples", "tests"):
        files.extend(p for p in (root / name).rglob("*") if p.is_file()
                     and "__pycache__" not in p.parts and p.suffix in (".py", ".yaml", ".yml"))
    return {str(p.relative_to(root)): digest(p) for p in sorted(files)}


def environment():
    return {"python": platform.python_version(), "platform": platform.platform(),
            "dependencies": {name: importlib.metadata.version(name) for name in ("pydantic", "httpx", "fastapi", "uvicorn", "PyYAML")}}


def freeze(root, destination):
    root, destination = Path(root).resolve(), Path(destination)
    if destination.exists(): raise ValueError("Protocol already exists; create a new version rather than overwrite a freeze.")
    cases = corpus()
    protocol = {"schema_version": "artifact-evaluation-1", "frozen_at_utc": utc_now(),
        "scope": "Known-fixture artifact evaluation, not held-out effectiveness or a cleared novelty claim",
        "corpus_status": "These modes were used in development. New seeds hold out action orders only, not applications or defect families.",
        "review": "Single-author source review plus independent target tests; no independent human mutation review claimed.",
        "seeds": list(SEEDS), "methods": list(METHODS), "cases": cases,
        "execution_order_seed": 20261101,
        "budget": {"max_requests": 500, "max_runtime_seconds": 600.0}, "monitoring": False,
        "tracks": {
            "logical": {"transport": "in-process ASGI", "clock": "controlled logical clock", "seeds": list(SEEDS),
                        "cases": [c["id"] for c in cases], "methods": list(METHODS)},
            "early": {"transport": "in-process ASGI", "clock": "controlled logical clock; wait deliberately omitted",
                      "seeds": list(SEEDS), "cases": [c["id"] for c in cases if c["mode"] == "delayed"],
                      "claim": "Unsafe early-probe diagnostic, not the production oracle or a confirmed-finding baseline"},
            "tcp": {"transport": "real loopback HTTP", "clock": "real monotonic wall time", "seeds": list(SEEDS[:3]),
                    "cases": ["sharing-read-immediate", "sharing-read-delayed", "sharing-read-stale_session", "role-write-write_side_effect"],
                    "methods": list(METHODS), "claim": "Operational validation; three repeats are not a powered performance study"},
            "minimize": {"seeds": list(SEEDS[:3]), "cases": ["sharing-read-stale_session", "role-write-write_side_effect", "ownership-write-stale_session"]},
            "external": {"targets": ["gitea", "pocketbase"], "profiles": ["temporal", "p4-single-event", "generic-valid-order"],
                         "seeds": list(SEEDS), "claim": "Matched local native-read profile instantiations, not exact P4 reproduction or generic-fuzzer superiority"},
            "native": {"targets": ["gitea", "pocketbase"], "tools": ["evomaster", "restler"], "seed": SEEDS[0], "evomaster_search_seconds": 10,
                       "claim": "Compatibility/applicability audit only; inputs and native oracles are not lifecycle-matched"},
        },
        "analysis_units": {"cases": "Finite corpus configurations; repeated seeds are not new defects",
                           "root_causes": ["stale_snapshot", "commit_before_denial"],
                           "existing_apps": "Two codebases, unknown natural defect denominator; no recall estimate",
                           "uncertainty": "Report exact finite-corpus counts and per-seed outcomes; no population confidence interval from correlated fixtures"},
        "source_sha256": source_inventory(root), "environment": environment()}
    protocol["protocol_sha256"] = canonical_digest(protocol)
    destination.parent.mkdir(parents=True, exist_ok=True)
    private_json(destination, protocol)
    return protocol


def load_protocol(path, root):
    value = json.loads(Path(path).read_text())
    expected = value.pop("protocol_sha256")
    if canonical_digest(value) != expected: raise ValueError("Protocol hash mismatch")
    value["protocol_sha256"] = expected
    if value["schema_version"] != "artifact-evaluation-1": raise ValueError("Unsupported protocol")
    root = Path(root).resolve()
    if source_inventory(root) != value["source_sha256"]: raise ValueError("Source changed after freeze; use the frozen snapshot or start a new protocol")
    if environment() != value["environment"]: raise ValueError("Runtime differs from frozen environment; start a separately labeled protocol")
    return value
