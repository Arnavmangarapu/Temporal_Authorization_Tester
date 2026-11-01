"""Small development pilot; seeds/budgets here are not a frozen evaluation."""

import argparse
import json
from pathlib import Path

from temporal_auth.integrations.pilot import PROFILES, private_json, run_pilot


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tools", type=Path, default=Path("artifacts/tools"))
    parser.add_argument("--output", type=Path, default=Path("artifacts/external-matrix"))
    options = parser.parse_args()
    rows = []
    for target in ("gitea", "pocketbase"):
        for profile in PROFILES:
            for seed in (0, 1):
                result = run_pilot(target, options.tools, options.output, profile=profile, seed=seed)
                report = result.report
                row = {key: report[key] for key in ("target", "version", "profile", "seed", "status", "verdict",
                    "workflow_requests", "fixture_requests", "total_requests", "elapsed_seconds", "reproductions") if key in report}
                row["evidence"] = str(result.directory.resolve())
                rows.append(row)
                private_json(options.output / "matrix.json", {"scope": "development pilot; no effectiveness ranking", "runs": rows})
                print(json.dumps(row), flush=True)
    if any(row["status"] != "completed" for row in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
