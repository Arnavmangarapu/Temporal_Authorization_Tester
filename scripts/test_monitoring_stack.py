"""Reconcile a real optional stack and record a small paired overhead pilot.

Requires two owned, idle serve processes (one monitored) and the Compose profile.
Does not start/stop services or delete evidence. Results are functional smoke
evidence, not final effectiveness measurements or a statistically powered study.
"""

import argparse
import json
from pathlib import Path
import re
import statistics
import time

import httpx
from prometheus_client.parser import text_string_to_metric_families


def total(text, name):
    return sum(s.value for f in text_string_to_metric_families(text) for s in f.samples if s.name == name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--monitored", default="http://127.0.0.1:8088")
    parser.add_argument("--disabled", default="http://127.0.0.1:8089")
    parser.add_argument("--data", type=Path, default=Path("artifacts/step8-monitoring/workspace"))
    parser.add_argument("--output", type=Path, default=Path("artifacts/step8-monitoring/report.json"))
    args = parser.parse_args()
    with httpx.Client(trust_env=False, timeout=10) as client:
        csrf = {}
        for origin in (args.monitored, args.disabled):
            csrf[origin] = re.search(r'name="csrf-token" content="([^"]+)"', client.get(origin).text).group(1)
            assert client.get(origin + "/health").json()["worker"]
            assert client.get(origin + "/api/jobs").json() == [], "Use fresh workspaces for this fixed-total smoke."
        for origin, path in (("http://127.0.0.1:19090", "/-/ready"),
                             ("http://127.0.0.1:3000", "/api/dashboards/uid/temporal-auth-worker")):
            client.get(origin + path).raise_for_status()
        def run(origin, **spec):
            start = time.perf_counter()
            response = client.post(origin + "/api/jobs", json=spec, headers={"X-CSRF-Token": csrf[origin]})
            response.raise_for_status()
            identifier = response.json()["id"]
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                job = client.get(origin + "/api/jobs/" + identifier).json()
                if job["status"] not in ("queued", "running", "cancelling"): break
                time.sleep(0.1)
            assert job["status"] == "completed", job
            return {"id": identifier, "wall_seconds": time.perf_counter() - start,
                    "result": job["result"], "spec": job["spec"]}

        pairs = []
        for index in range(3):
            pair = {}
            # Alternate order to reduce a simple warm-up/order confound.
            for label in (("disabled", "monitored") if index % 2 == 0 else ("monitored", "disabled")):
                pair[label] = run(getattr(args, label), fixture_mode="immediate", seed=index,
                                  title=f"Monitoring overhead pair {index + 1} · {label}")
                assert pair[label]["result"]["verdict"] == "no_violation_observed"
            pairs.append(pair)
        findings = [run(args.monitored, fixture_mode="stale_session", title=f"Deduplication check {i}") for i in range(2)]
        assert all(j["result"]["verdict"] == "confirmed_violation" and j["result"]["reproductions"] == 2 for j in findings)
        writing = run(args.monitored, fixture_mode="write_side_effect", lifecycle="role_downgrade", action="write",
                      title="Monitor confirmed write effect")
        assert writing["result"]["verdict"] == "confirmed_violation"
        jobs = client.get(args.monitored + "/api/jobs").json()
        text = client.get("http://127.0.0.1:9464/metrics").text
        events = [json.loads(line) for p in args.data.glob("jobs/**/events.jsonl") for line in p.read_text().splitlines()]
        expected = {
            "temporal_auth_requests_total": len(events),
            "temporal_auth_request_duration_seconds_count": len(events),
            "temporal_auth_request_duration_seconds_sum": sum(e["finished_elapsed_seconds"] - e["started_elapsed_seconds"] for e in events),
            "temporal_auth_jobs_finished_total": len(jobs),
            "temporal_auth_terminal_job_budget_requests_total": sum(j["result"]["requests"] for j in jobs),
            "temporal_auth_terminal_job_fixture_requests_total": sum(j["result"]["fixture_requests"] for j in jobs),
            "temporal_auth_confirmed_finding_signatures": 2,
            "temporal_auth_sequences_completed_total": 12,
        }
        for name, value in expected.items(): assert abs(total(text, name) - value) < 1e-8, (name, total(text, name), value)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.with_suffix(".prom").write_text(text)
        # Wait for one genuine scrape after the final workflow.
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            response = client.get("http://127.0.0.1:19090/api/v1/query", params={"query": "temporal_auth_confirmed_finding_signatures"})
            values = response.json()["data"]["result"]
            if values and float(values[0]["value"][1]) == 2: break
            time.sleep(0.3)
        assert values and float(values[0]["value"][1]) == 2
        target = client.get("http://127.0.0.1:19090/api/v1/targets").json()["data"]["activeTargets"]
        assert len(target) == 1 and target[0]["health"] == "up"
        provisioned = client.get("http://127.0.0.1:3000/api/dashboards/uid/temporal-auth-worker")
        provisioned.raise_for_status()
        dashboard = provisioned.json()["dashboard"]
        queries = []
        for panel in dashboard["panels"]:
            for query in panel.get("targets", []):
                response = client.get("http://127.0.0.1:19090/api/v1/query", params={"query": query["expr"]})
                assert response.status_code == 200 and response.json()["status"] == "success", response.text
                queries.append(query["expr"])
        proxy = client.get("http://127.0.0.1:3000/api/datasources/proxy/uid/temporal-prometheus/api/v1/query",
                           params={"query": "temporal_auth_confirmed_finding_signatures"})
        proxy.raise_for_status()
        assert float(proxy.json()["data"]["result"][0]["value"][1]) == 2
        on = [p["monitored"]["wall_seconds"] for p in pairs]
        off = [p["disabled"]["wall_seconds"] for p in pairs]
        report = {"scope": "Step 8 monitoring smoke; seeded fixtures; three paired wall-time pilot samples, not final research evaluation",
                  "pairs": pairs, "finding_jobs": findings + [writing], "expected_metrics": expected,
                  "actual_metrics": {name: total(text, name) for name in expected},
                  "prometheus_target": {"health": target[0]["health"], "scrapeUrl": target[0]["scrapeUrl"]},
                  "grafana": {"uid": dashboard["uid"], "queries_validated": len(queries), "datasource_proxy_verified": True},
                  "overhead": {"samples_per_setting": 3, "disabled_median_seconds": statistics.median(off),
                               "monitored_median_seconds": statistics.median(on),
                               "median_relative_difference_percent": 100 * (statistics.median(on) / statistics.median(off) - 1),
                               "limitations": "Small local wall-time pilot includes five-second policy wait, startup and polling. No claim of negligible overhead or statistical significance."}}
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"report": str(args.output), "metrics": expected, "overhead": report["overhead"]}, indent=2))


if __name__ == "__main__": main()
