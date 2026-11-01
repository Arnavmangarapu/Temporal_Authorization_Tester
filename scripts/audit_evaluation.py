"""Verify and reanalyze a completed campaign without executing a target.

Unlike a new run, offline analysis can happen on another machine. It verifies
the frozen executable files and compares regenerated tables with the saved
analysis. Raw records and original derived outputs are never modified.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
from tempfile import TemporaryDirectory


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True, help="Extracted frozen source checkout")
    parser.add_argument("--campaign", type=Path, required=True, help="Extracted campaign directory")
    args = parser.parse_args()
    source, campaign = args.source.resolve(), args.campaign.resolve()
    protocol = json.loads((campaign / "protocol.json").read_text())
    expected = protocol["protocol_sha256"]
    unsigned = {key: value for key, value in protocol.items() if key != "protocol_sha256"}
    actual = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    if actual != expected: raise SystemExit("Protocol hash mismatch")
    for name, value in protocol["source_sha256"].items():
        path = (source / name).resolve()
        if not path.is_relative_to(source) or hashlib.sha256(path.read_bytes()).hexdigest() != value:
            raise SystemExit(f"Frozen source mismatch: {name}")
    sys.path[:0] = [str(source / "src"), str(source / "targets")]
    from temporal_auth.evaluation.analysis import analyze
    import temporal_auth.evaluation.analysis as module
    if Path(module.__file__).resolve() != source / "src/temporal_auth/evaluation/analysis.py":
        raise SystemExit("Analysis was imported from a different source checkout")
    reference = json.loads((campaign / "analysis.json").read_text())
    with TemporaryDirectory(prefix="temporal-evaluation-audit-") as temp:
        copy = Path(temp) / "campaign"
        copy.mkdir()
        for name in ("campaign.json", "protocol.json", "rows.jsonl"):
            shutil.copyfile(campaign / name, copy / name)
        shutil.copytree(campaign / "runs", copy / "runs")
        regenerated = analyze(protocol, copy)
        if regenerated != reference: raise SystemExit("Regenerated analysis differs from the saved report")
        if (copy / "runs.csv").read_bytes() != (campaign / "runs.csv").read_bytes():
            raise SystemExit("Regenerated CSV differs from the saved table")
    print(f"Offline audit passed: {sum(v['recorded'] for v in reference['coverage'].values())} rows, source/evidence hashes and regenerated analysis/CSV match.")
    print("No target executed. Original execution environment remains the one recorded in the protocol.")


if __name__ == "__main__": main()
