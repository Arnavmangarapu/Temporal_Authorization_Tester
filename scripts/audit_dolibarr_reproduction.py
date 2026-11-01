"""Offline source/evidence/oracle audit; no Docker, PHP or target execution."""

import argparse
import hashlib
import json
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--campaign", type=Path, required=True)
    args = parser.parse_args()
    source, campaign = args.source.resolve(), args.campaign.resolve()
    protocol = json.loads((campaign / "protocol.json").read_text())
    unsigned = {k: v for k, v in protocol.items() if k != "protocol_sha256"}
    actual = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    if protocol["schema_version"] != "dolibarr-26066-protocol-1" or actual != protocol["protocol_sha256"]:
        raise SystemExit("Protocol mismatch")
    for name, expected in protocol["source_sha256"].items():
        path = (source / name).resolve()
        if not path.is_relative_to(source) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit("Frozen source mismatch: " + name)
    sys.path[:0] = [str(source / "src"), str(source / "targets")]
    from temporal_auth.evaluation.dolibarr_reproduction import analyze
    import temporal_auth.evaluation.dolibarr_reproduction as module
    if Path(module.__file__).resolve() != source / "src/temporal_auth/evaluation/dolibarr_reproduction.py":
        raise SystemExit("Imported a different source checkout")
    regenerated = analyze(protocol, campaign)
    if regenerated != json.loads((campaign / "analysis.json").read_text()):
        raise SystemExit("Saved analysis differs from raw evidence")
    print(f"Offline audit passed: {regenerated['recorded_runs']} rows; source, evidence, static oracles and analysis match.")


if __name__ == "__main__": main()
