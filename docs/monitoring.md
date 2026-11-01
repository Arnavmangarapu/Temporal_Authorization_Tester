**Optional local monitoring — Step 8**

Prometheus and Grafana monitor the persistent web worker. They do not change request generation, budgets, policy deadlines, confirmation or verdicts. Ordinary CLI commands continue to write complete evidence without a monitoring service or dependency.

Install and launch the workspace:

```bash
python -m pip install -e '.[web,monitoring]'
temporal-auth serve --metrics-port 9464
```

In another terminal, from the repository root:

```bash
docker compose --profile monitoring up -d --build
```

Open [the experiment workspace](http://127.0.0.1:8080), [the provisioned Grafana dashboard](http://127.0.0.1:3000/d/temporal-auth-worker), [Prometheus](http://127.0.0.1:19090) or [worker metrics](http://127.0.0.1:9464/metrics). Grafana grants local anonymous **Viewer** access; login forms and basic authentication are disabled. The dashboard is provisioned from versioned files. No cloud account is needed.

The tested Compose configuration uses Linux host networking so containers can reach the exporter's loopback address. All three monitoring listeners bind to 127.0.0.1. Docker Desktop requires compatible host-networking support; other operating systems were not exercised. The public configuration is copied into local images with pinned upstream bases: this avoids bind-mount access failures on the mounted workspace filesystem under SELinux. Only monitoring files enter the Docker build context; private experiment evidence is excluded. Rebuild after changing provisioning files. Prometheus uses port 19090 to avoid a pre-existing service on this machine. Use one project stack and one exporter per workspace; choose free ports before starting. A metrics port conflict becomes a visible worker error rather than an endless restart loop. If changing 9464, update monitoring/prometheus.yml too; if changing 19090, update Compose and the provisioned data source together.

To stop containers while retaining their time-series/dashboard databases:

```bash
docker compose --profile monitoring down
```

Monitoring is disabled by default. Start `temporal-auth serve` without --metrics-port to run the website and worker normally; no monitoring module is imported. Adding the flag starts a separate HTTP exporter **inside the execution worker**, not the UI server. Worker shutdown closes the exporter. A rejected second worker never starts another exporter.

**Metrics and meaning**

| Metric | Meaning and coverage |
|---|---|
| temporal_auth_jobs{state} | Durable SQLite job counts for queued, running, cancelling and terminal states. This is progress by state, not an invented completion percentage. |
| temporal_auth_jobs_finished_total{target,lifecycle,state,verdict} | Terminal jobs in retained workspace history, including cancellations and interruptions. |
| temporal_auth_sequences_completed_total{target,lifecycle,outcome} | Completed lab workflows or analyzed native attempts. Discovery and clean replays count separately; their outcomes can be candidate while the containing job is confirmed. |
| temporal_auth_requests_total{target,lifecycle,outcome} | Complete JSONL HTTP events, including recorded reset requests and native workflow/setup requests. Readiness probes without events are excluded. HTTP 403/500 responses remain responses; transport/execution errors have separate bounded outcomes. |
| temporal_auth_request_duration_seconds{target,lifecycle} | Histogram with fixed 5 ms–10 s buckets plus +Inf; covers exactly the counted events. Duration is event finish minus start using stored elapsed times. |
| temporal_auth_terminal_job_budget_requests_total | Sum of stored terminal-job request totals, including readiness checks. Interrupted partial summaries can omit requests; use event totals for observed partial work. |
| temporal_auth_terminal_job_fixture_requests_total | Sum of stored terminal-job fixture totals; some calls have no latency event. |
| temporal_auth_execution_errors_total | Jobs ending failed, including setup/budget/execution failures. Cancellations and interruptions are separate job states. |
| temporal_auth_confirmed_finding_signatures | Distinct confirmed signatures, including seeded defects; a gauge, not an independent-vulnerability count. |
| temporal_auth_sampled_probes_total{target,lifecycle,session,boundary} | Completed lab probe samples before/at-or-after the configured deadline, for old/fresh sessions. Native timing evidence remains in pilot records. |
| temporal_auth_evidence_invalid_lines | Malformed complete event lines skipped during reconstruction. Nonzero means latency/request coverage needs investigation. |
| temporal_auth_worker_uptime_seconds | Uptime of the worker that owns this exporter. Prometheus up indicates scrape reachability. |

Counters are reconstructed from retained evidence and job history. A custom collector reads new complete event lines and caches byte offsets; unfinished trailing lines wait until the next scrape. It freezes evidence from terminal jobs after ingestion. Repeated scrapes do not double-count. A worker restart rebuilds from the original records, including jobs older than the UI's 200-row history limit. This first scrape can be slower for a large history. Scraping runs in an exporter thread and never writes to experiment records or calls a target. The cache grows with retained history. This local implementation assumes append-only evidence and an intact workspace; truncating a consumed file fails the scrape, and deleting/editing history is unsupported while the worker runs. Archive a workspace and start another directory for a new campaign.

Finding deduplication uses target adapter, lifecycle, managed fixture mode, protected action, effect kind and a SHA-256 of configured-target YAML. Titles, seeds, resource/session IDs, budgets and replay attempts do not create new findings. The YAML hash is internal and never exported. Textually different configured policies can create different signatures even if semantically equivalent. This groups repeated local reproductions; it does not establish a unique real-world vulnerability.

Metric labels come from fixed allowlists. Tokens, users, origins, raw paths, document IDs, YAML, job IDs and run IDs are never labels. No generic Python process collector is enabled, so UI-process statistics cannot be mistaken for worker statistics.

The dashboard shows worker reachability, active/queued jobs, verdict history, throughput, latency quantiles, execution failures, finding signatures and request coverage. Rates require multiple scrapes and can miss short bursts; histogram quantiles are estimates from buckets. Probe samples are not exact enforcement latency. Censored, failed-control, unknown-policy and intermittent observations must be interpreted from raw run records; two samples cannot establish a propagation distribution. Use exact events, identities and declared deadlines for paper figures. Monitoring settings must be identical across compared tools in Step 9.

**Reproduce verification**

```bash
python -m pytest -q tests/test_monitoring.py
```

The tests verify histogram/count reconciliation, incremental writes, restart reconstruction, finding deduplication, sequence/deadline samples, bounded labels, symlink exclusion, complete retained history, a missing optional dependency, actual worker crash recovery, port conflicts and the optional Compose profile.

For the real-stack smoke and small overhead pilot, use fresh output directories and start these two workspace processes in separate terminals:

```bash
PYTHONPATH=src:targets python -m temporal_auth serve --port 8088 --metrics-port 9464 --data artifacts/step8-monitoring/workspace
PYTHONPATH=src:targets python -m temporal_auth serve --port 8089 --data artifacts/step8-monitoring/disabled
```

With the Compose profile running, execute:

```bash
python scripts/test_monitoring_stack.py
```

The script runs three alternating paired immediate-enforcement jobs, repeats a seeded read confirmation to check deduplication, confirms a protected-write effect, reconciles exported counts/durations with disk records, waits for a real Prometheus scrape, checks every dashboard query and verifies Grafana's data-source proxy. Its fixed expected totals require fresh workspaces; choose new --data/--output paths and matching serve paths if repeating. Stop both serve processes and the Compose stack afterward. These are functional pilots with five-second policy waits, startup and HTTP polling, not statistically powered performance claims. Verification outcomes are recorded in [the Step 8 manifest](results/step8-monitoring.json).

Configuration follows the official [Python exporter documentation](https://prometheus.github.io/client_python/exporting/http/), [Prometheus Docker instructions](https://prometheus.io/docs/prometheus/latest/installation/) and [Grafana provisioning documentation](https://grafana.com/docs/grafana/latest/administration/provisioning/). The Python client and both upstream container bases are pinned; image digests identify tested builds, not a claim that they are the latest releases. See compose.yaml and monitoring/*.Dockerfile for the exact versions.
