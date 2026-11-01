**Step 7: local experiment workspace**

The project now has a working website for submitting and reviewing experiments. It uses the same execution, oracle and clean-confirmation libraries as the CLI. The browser does not decide whether a finding is confirmed.

**Start it**

```bash
python -m pip install -e '.[dev,lab,web]'
temporal-auth serve
```

From a source checkout with dependencies already installed:

```bash
PYTHONPATH=src python -m temporal_auth serve --port 8080
```

Open [the local workspace](http://127.0.0.1:8080). The command binds to loopback and uses one separate worker. It stores its private SQLite queue and evidence under artifacts/workspace. To use a different directory or native binaries:

```bash
PYTHONPATH=src python -m temporal_auth serve --data artifacts/my-workspace --tools artifacts/tools
```

The interface has four working views:

| View | Available actions |
|---|---|
| Experiments | Inspect persistent job history; filter active runs, findings or inconclusive results |
| New experiment | Choose a managed lab, configured dedicated lab, Gitea or PocketBase; validate and submit a policy/workflow and budget |
| Experiment details | Follow recorded requests and grace-window timing, inspect response bodies, cancel execution or start a fresh replay |
| Evidence & replay | Review metadata and download observations, reports, configuration and an executable replay bundle |

**Try the controlled demonstration**

Choose Disposable document lab. The worker starts an isolated loopback instance with generated credentials, then shuts it down after the job.

| Selection | Expected result under the lab contract |
|---|---|
| Sharing revocation / Read / Stale session defect | Confirmed violation after discovery and two clean reproductions |
| Role downgrade / Write / Unauthorized write side effect | Confirmed write effect, even when the forbidden write returns 403 |
| Read / Correct immediate enforcement | No violation observed |
| Read / Correct bounded delay | No violation observed after the legitimate five-second grace period |

All six sharing/role/ownership and read/write combinations are available. Seeded fixture modes stay labeled as controlled lab observations. They are not new vulnerabilities in existing applications. The five-second bound and 50 ms tolerance come from the lab contract; the guided interface does not let users silently shorten that bound.

For Gitea and PocketBase, install the pinned binaries using scripts/fetch_pilot_tools.py first. The UI supports the temporal, P4-style single-event and generic-valid-order native read profiles introduced in Step 6. It starts disposable native applications rather than attaching to existing deployments. Their policy and research limitations remain as described in [the pilot guide](external-pilots.md). EvoMaster/RESTler compatibility runners remain CLI commands; this milestone does not add a native-competitor benchmark dashboard.

To use My running document lab, paste a valid schema-version 1 or 2 configuration and acknowledge that the dedicated fixture is reset before each attempt. Only loopback targets are accepted. Passwords and reset keys come from the named environment references inherited when the server starts; the form never accepts captured credentials. Validation identifies missing environment references without returning their values. Unknown timing remains inconclusive and causes no test requests.

**Execution and persistence**

FastAPI serves Jinja2 templates, a small browser script and vendored HTMX. Public Sans, HTMX and their licenses are bundled locally, so the interface needs no CDN connections or frontend build. The design centers on the permission transition and actual request timeline, with distinct visual states for confirmation, non-findings and incomplete evidence.

The queue uses Python's sqlite3 module with transactions and rollback journaling. An ORM is unnecessary for this small job store; this is a deliberate simplification of the original SQLAlchemy proposal. A separate persistent Python worker claims jobs. A file lock permits one worker per data directory, and durable ownership records scope interruption handling to that worker. A rejected second dashboard cannot interrupt the first worker's job. Browsing, refreshing or closing the tab does not stop execution.

| Job state | Meaning |
|---|---|
| queued | Persisted and awaiting the worker |
| running | Worker has claimed the job |
| cancelling | Cancellation is recorded; execution/cleanup is stopping |
| completed | Execution library returned a completed workflow; inspect its separate verdict |
| failed | Execution failed or exhausted its budget; partial evidence is retained |
| cancelled | A queued job was removed from execution, or a running job stopped after cancellation |
| interrupted | The worker stopped before normal delivery; the job is not silently retried |

Queued jobs survive server restarts. Interrupted running jobs remain visible and require an explicit replay. The supervisor detects worker exit, terminates its owned process group and starts a replacement worker. Normal shutdown gives the worker time to cancel and close its target before terminating the group. This implementation requires POSIX process supervision and has been tested on Linux; use the provided single-worker serve command.

Lab cancellation cancels the active asynchronous checker and closes its HTTP clients. Native cancellation is cooperative: the callback is checked before subsequent HTTP attempts and during budget checks, while a current synchronous operation can finish or time out. The UI remains cancelling during cleanup. Candidates and partial reports are retained; incomplete confirmation is never promoted. A cancellation race can retain a fully observed verdict while marking the job cancelled; the two fields describe different things.

**Counts, timeline and evidence**

Managed-lab startup readiness attempts share the job's request/time budget and are recorded in fixture.json. Core check.json preserves its original accounting: its local total covers the checker, while shared_total_requests also includes startup attempts. The UI presents the shared total and explicitly identifies startup requests separately from the workflow timeline. Native pilots retain their existing all-in accounting. Elapsed time includes startup and cleanup; it is not inferred from monitoring scrape intervals.

The timeline uses actual per-attempt request timestamps. Shading marks the declared grace interval and the dashed line marks the earliest valid probe time. Session lanes use recorded actor/generation identities where available; unidentified setup requests occupy a separate lane. Evidence from independent attempts is never presented as one common monotonic time origin. HTTP statuses describe responses, not automatic authorization verdicts.

Previews are bounded to 4 MB of scanned JSONL data, up to 30 groups and 100 displayed requests per group, with response previews truncated to 12,000 characters. A limited preview does not alter the stored observations or oracle result. Evidence bundles are limited to 64 MB and approximately 512 entries; larger artifacts remain in the private workspace directory. Raw worker logs, symlinks and files outside the job directory are excluded.

Downloads include replay.json, replay.py, README.txt, job metadata and available configuration/observation/oracle files. The generated script calls the same execution library:

```bash
python replay.py ./replayed-evidence
```

Install this project with its web dependencies before running the script. Managed labs generate new credentials and resources. Configured labs require the environment references in replay.json and are reset during replay. Native replays require the pinned binaries; set TEMPORAL_AUTH_TOOLS if needed. A reproduced confirmed fixture-policy finding exits 3, matching the CLI's finding convention. Captured tokens and passwords are not embedded in the replay.

The local server checks Host and mutation origins, requires a per-server CSRF token, disallows framing and serves a restrictive content-security policy. Templates escape titles, paths and response content. No SQL credentials or arbitrary shell command fields exist in the browser API. This is a local research interface, with no multi-user login or remote hosting feature.

**Verification**

Automated web tests cover input validation, all six guided configuration families, reset authorization, unknown timing, missing native tools, Host/origin/CSRF protection, durable exclusive claims, queue capacity, cancellation races, retained candidates, evidence escaping, bounded previews, symlink exclusion, actual worker confirmation/cancellation and worker-crash recovery.

Final regression result: **318 tests passed**, including 42 web tests. The offline wheel was exercised outside the source checkout with real HTTP, its own worker and a managed target; packaged assets, the non-finding and export all worked. See [the verification manifest](results/step7-ui.json).

The Chromium script [test_web_browser.py](../scripts/test_web_browser.py) exercised seven jobs through the UI: stale read, correct enforcement, a fresh replay, a protected-write defect, cancellation, PocketBase and Gitea. Its ten checks also verify navigation independence, evidence download, finding filters, 390-pixel mobile layout and keyboard focus. There were no browser page errors. The downloaded replay script was executed independently and reproduced the seeded read finding twice with newly generated credentials.

For browser regression testing, install the ui-test extra and fetch the pinned Linux x86_64 binaries (the script also submits Gitea/PocketBase jobs). Git is required for the Gitea fixture. Use Playwright's Chromium or pass --chromium with an installed browser path, and run this while the local server is active:

```bash
python -m pip install -e '.[web,ui-test]'
python scripts/fetch_pilot_tools.py
python -m playwright install chromium
python scripts/test_web_browser.py --url http://127.0.0.1:8080
```

Local screenshots and the browser report are under artifacts/step7-browser. Tests use temporary servers/workspaces and require local socket access. This milestone ended with the interface. Step 8 subsequently added [optional Prometheus/Grafana monitoring](monitoring.md); final research evaluation remains Step 9.
