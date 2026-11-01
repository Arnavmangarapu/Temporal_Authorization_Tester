**Step 3: HTTP runner and experiment CLI**

This guide describes the version-one sharing-revocation collector. run still does not assign a verdict or reset the target. Step 4 adds analyze/check for evaluation and confirmation; Step 5 adds version-two generated read/write workflows. See the [oracle/replay instructions](oracle-replay.md) and [generation/minimization guide](generation-minimization.md).

**Run an experiment**

Install the project with the lab/development extras as described in the README. In one terminal start the desired target variant:

```bash
LAB_MODE=stale_session PYTHONPATH=targets python -m uvicorn document_lab.app:create_app --factory --host 127.0.0.1 --port 8001 --workers 1
```

In a second terminal, from the repository root:

```bash
export LAB_ALICE_PASSWORD=alice-demo-password
export LAB_BOB_PASSWORD=bob-demo-password
PYTHONPATH=src python -m temporal_auth run examples/document-lab.yaml --output artifacts
```

Use credentials matching the target's settings if its defaults were overridden. Only actors used as owner, subject and control require credentials. The run command requires the configured password variables explicitly; it does not silently import the target's demo defaults. Configuration validation alone still needs no passwords and makes no network requests.

An installed equivalent is `temporal-auth run examples/document-lab.yaml --output artifacts`. The target must already be running at the configured origin. The run command never starts or resets it. Each run creates a new resource and marker, so returned IDs are bound dynamically; target resources remain afterward. The separate check command performs explicitly recorded lab resets for clean confirmation.

**Executed sequence**

| Order | Action | Recorded session role |
|---|---|---|
| 1 | Log in as owner | owner |
| 2 | Log in as recipient to resolve user_id | subject_discovery |
| 3 | Create a document containing a unique marker | owner |
| 4 | Grant the recipient access | owner |
| 5 | Log in as recipient after the grant | subject_old |
| 6 | Verify the old session reads the protected marker | subject_old |
| 7 | Verify legitimate control access before revocation | owner, or a separate configured control |
| 8 | Revoke recipient access and record acknowledgement | owner |
| 9 | Log in again as the same recipient | subject_fresh |
| 10–12 | After the configured bound/tolerance, read as old session, fresh session and legitimate control | respective sessions |

The default owner-as-control workflow has 12 attempted requests. A distinct control actor adds a login request and must already have legitimate access: the runner does not manufacture that permission. Before collecting post-transition evidence it checks returned principal IDs for overlap, resource ownership, consistent recipient identity and successful pre-transition protected-content reads. These are setup checks, not a post-transition vulnerability oracle.

The adapter expects username/password login JSON, user_id in the login response, a bearer token at the configured token_pointer, content in document creation, id and owner_id in its response, and subject_id for sharing. Configured operation IDs/path templates are honored; methods and placeholder names must match the documented lab contract. Other API schemas need a later adapter. Unsupported template expressions are rejected before contacting the target. Returned IDs are percent-encoded when inserted into paths.

**Sessions, timing and budgets**

Each login creates an independent HTTPX AsyncClient with its own cookie jar and a numbered actor/session generation. The old recipient client is retained across revocation; acquiring the fresh client does not overwrite it. Owner/control clients remain separate. Clients are closed when the run finishes or stops. Passwords are resolved before network activity; bearer tokens stay in memory.

Redirects are not followed and environment proxy settings are not inherited. Transport-level automatic retries are not enabled. Every login, setup request, failed attempt and probe counts against max_requests; a request prevented by an already exhausted budget is not counted. The default cap is 500, but the initial workflow normally uses 12.

UTC timestamps support human review; elapsed times use a monotonic clock relative to run start. Acknowledgement means completion of the successful revoke response body, not its first byte. probe_not_before_elapsed_seconds equals acknowledgement plus max_delay_seconds plus tolerance_seconds. Every request event records its actual start and finish elapsed times. The runner waits for that deadline before the old/fresh/control observations. It checks remaining budget before each request and refuses a wait that cannot leave time for the probe.

HTTPX has individual network-phase timeouts; the runner additionally uses asyncio deadlines for total individual-request time and overall async workflow time. This also bounds a continuously streaming response. Response capture is limited to 65,536 decoded bytes; an oversized response ends the run with response_too_large rather than being treated as a complete observation. Local synchronous artifact writing and client teardown are not forcibly preempted. Reported elapsed time includes setup and normal cleanup, up to the final report write. [HTTPX timeouts](https://www.python-httpx.org/advanced/timeouts/), [async support](https://www.python-httpx.org/async/), [asyncio deadlines](https://docs.python.org/3/library/asyncio-task.html#timeouts).

poll_interval_seconds currently bounds the sleep increments while waiting; it does not trigger repeated HTTP polling. This milestone captures one post-deadline read per session/control. Delay distributions, continuous probing and scheduling are later work.

**Evidence layout**

```text
artifacts/
  {run_id}/
    run.json
    events.jsonl
```

run.json records schema/tool version, adapter, a SHA-256 digest of the validated configuration serialization, target origin, policy, budgets, run status, counts, bindings, session roles/generations and timing anchors. The digest is not a digest of raw YAML bytes. Each line in events.jsonl records one attempted request: operation, step, actor/session generation, method/path, UTC and elapsed timings, HTTP status, bounded response evidence, and any execution error. There are no captured request/response headers.

Events are appended and flushed as attempts finish. The report is written initially after successful preflight and replaced atomically at normal termination. Handled setup failures also receive a final report. A cooperative cancellation records interrupted status and flushes partial evidence; forceful process termination may leave the initial running report or an unfinished last record. Reconstructing crash recovery is outside this step.

Login request passwords are omitted. Raw login response bodies are omitted, retaining only user_id, username and token_type metadata. Known password/token strings are redacted from captured payloads and paths; sensitive payload keys are also redacted. The run directory uses permissions 0700 and files use 0600 on POSIX. Content markers and target resource IDs are intentionally retained as evidence. Do not enable independent HTTP debug logging when handling credentials.

**Statuses and exit codes**

| Status | Meaning |
|---|---|
| completed | All planned observations collected; verdict is still not_evaluated |
| setup_failed | Missing credentials, unsupported adapter configuration, invalid bindings, failed setup or unestablished access |
| policy_unknown | No justified bound; no target request is sent |
| execution_error | Transport/timeout failure or an oversized response prevents collection |
| budget_exhausted | Request/runtime budget or time needed for the probe prevents completion |
| interrupted | Cooperative cancellation; partial evidence retained |

Completed collection exits 0 even when the old session returned protected content. Other reported run outcomes exit 1. Invalid configuration or evidence I/O failure exits 2. Keyboard interruption exits 130. Unexpected programming errors are not converted into successful reports. Non-success HTTP responses in the three post-transition reads are stored for Step 4 to interpret; a completed observation sequence can therefore include an unhealthy control and must not be called a confirmed defect.

The important boundary: `status = completed` and `verdict = not_evaluated` in run.json means collection succeeded. analyze writes a separate analysis.json without changing raw observations. check coordinates discovery and two clean replays and writes check.json. Post-transition interpretation is performed by that separate oracle.
