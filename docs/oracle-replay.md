**Step 4: temporal oracle and clean confirmation**

There are three distinct operations: run collects a trace; analyze evaluates one stored trace offline; check resets the dedicated document lab, collects discovery evidence and clean-replays a candidate twice. Raw run.json and events.jsonl remain unchanged by analysis. Derived verdicts are stored separately.

This guide gives version-one read-workflow counts and behavior. Step 5 extends the same commands to version-two lifecycle graphs and protected-write readbacks; see [generation/minimization](generation-minimization.md) for the additional schema, families and costs.

**Offline analysis**

```bash
PYTHONPATH=src python -m temporal_auth analyze examples/document-lab.yaml artifacts/RUN_ID
```

Use the original configuration matching the run. The fingerprint is based on validated serialization, including dictionary order, rather than raw YAML bytes. Offline analysis makes no network requests and writes analysis.json in the run directory. It can produce candidate, no_violation_observed or inconclusive; it can never produce confirmed_violation.

The oracle validates configuration/policy identity, adapter and evidence version, exact workflow order, request count, actor IDs/session generations, resource paths and bindings, monotonic chronology, complete responses and collection status. It requires successful creation/grant/revocation acknowledgements and healthy protected-content reads before revocation and by the legitimate control afterward. A larger advertised revocation delay than the configured bound is a policy conflict, not a vulnerability finding.

Probe start times must be at or beyond the recorded revoke-response completion plus the configured bound and tolerance. A request sent earlier cannot establish a violation because it completed later. The old and fresh sessions must identify the same recipient but have different generations. The recipient must be distinct from owner/control. Missing, redacted or malformed evidence remains inconclusive. JSON with duplicate keys or non-finite numbers is rejected.

The runner establishes a random protected marker at the configured JSON Pointer before revocation. The oracle searches for that marker in post-transition response JSON or text. The marker is not included in the probe request itself, avoiding simple request reflection as evidence. Returned protected content counts even under a 403 or 500 status. A healthy 200 public metadata response without it does not establish disclosure. A failed owner control or an uninterpretable probe makes the trace inconclusive rather than a clean result.

| Observation | Single-trace result |
|---|---|
| Old session discloses marker; fresh session does not | candidate: stale_session_access |
| Fresh session discloses marker; old session does not | candidate: fresh_session_access |
| Both disclose marker | candidate: revocation_enforcement |
| Neither observed probe discloses marker, with valid setup/controls | no_violation_observed |
| Missing policy, unhealthy controls, early probes or invalid evidence | inconclusive |

The kind describes observed session behavior; it does not prove the application's internal root cause. Local evidence is structurally checked but is not cryptographically authenticated against malicious edits. This version recognizes the plaintext marker, not arbitrary transformations/encodings of sensitive data. No-violation means none was observed in these probes, not proof of application security.

**Clean check**

Start the dedicated lab, for example in stale_session mode, using the lab instructions. In a separate terminal:

```bash
export LAB_ALICE_PASSWORD=alice-demo-password
export LAB_BOB_PASSWORD=bob-demo-password
export LAB_RESET_KEY=local-lab-reset-key
PYTHONPATH=src python -m temporal_auth check examples/document-lab.yaml --output artifacts
```

The passwords and reset key must match that instance. LAB_RESET_KEY has no implicit fallback in the checker. An alternative variable name can be supplied with --reset-key-env. Reset keys must be printable ASCII without spaces, suitable for the lab's header.

check is specifically for the dedicated lab: it clears all its documents, shares and sessions using POST /testing/reset before discovery and before every replay. The endpoint is experiment setup, not an automatically discovered public application operation. Do not point check at a shared instance whose fixture data must be preserved. The command does not start or stop the server and does not change enforcement mode.

Before any reset, the checker validates supported workflow inputs, known policy and required actor/reset credentials. Each reset requires a successful response with status reset. The known lab reset contract regenerates user IDs. The checker rejects identity overlap or resource reuse across attempts as reset_not_clean. This detects a noop reset, but is not proof that an arbitrary server implemented a clean reset; the benchmark fixture and its reset implementation are trusted and independently tested.

Discovery runs the full annotated sequence. A candidate is then replayed twice, each time after reset with fresh login sessions, fresh IDs and a new protected marker. Confirmation requires both replays to reproduce the same exposure/session pattern. It does not replay captured tokens or copy old resource IDs. Version-two optional-action minimization is now available through the separate minimize command.

| Confirmation outcome | Final result |
|---|---|
| Discovery has no observed violation | no_violation_observed; no replays needed |
| Discovery inconclusive or incomplete | inconclusive |
| Candidate plus two matching clean reproductions | confirmed_violation |
| Candidate plus one matching and one valid nonmatching replay | candidate, confirmation flaky |
| Candidate plus two valid nonmatching replays | candidate, confirmation not_reproduced |
| Candidate plus failed reset, incomplete trace or exhausted budget | candidate, confirmation incomplete |

The two-replay rule is deliberately conservative. A retained inconsistent candidate can still be a real intermittent bug. Do not treat it as a proven false alarm.

**One shared budget**

The YAML max_requests and max_runtime_seconds apply to the whole check, including fixture requests, logins, discovery, waits and replays. A fresh per-attempt budget is not granted. Individual runner timeouts are also bounded by the shared remaining time. Async deadlines are cooperative; synchronous local artifact I/O and cleanup are not forcibly preempted.

With owner also serving as control, each workflow uses 12 requests. Correct modes normally use 13 total: one reset and discovery. A fully confirmed candidate uses 39: three resets and three workflows. An exact cap of 39 can confirm; a cap of 38 cannot finish the last required control and retains the unconfirmed candidate. Total request count is authoritative in check.json; each run.json shows that attempt's local count, using the same original configuration fingerprint.

**Artifacts and exit codes**

```text
artifacts/check-UUID/
  check.json                 # Overall budget, verdict and reproduction counts
  events.jsonl               # Fixture reset attempts; no reset-key headers
  attempts/
    RUN_UUID/
      run.json               # Original observations summary, not_evaluated
      events.jsonl           # Numbered request/response observations
      analysis.json          # Single-trace oracle result
```

The check summary links discovery and replay artifacts and records fixture requests separately from the total. Reset events use the shared request ordinal, so their sequence numbers have gaps for intervening workflow requests. Actor passwords, bearer tokens and reset keys are not exported. Reports and event files use private POSIX permissions. A cooperative cancellation retains interrupted status and available partial evidence; abrupt process termination can leave a running summary.

| Exit code | analyze | check |
|---|---|---|
| 0 | No violation observed | No violation observed |
| 1 | Inconclusive | Inconclusive/setup/execution failure |
| 2 | Invalid configuration or artifact I/O failure | Invalid configuration or artifact I/O failure |
| 3 | Never emitted | Confirmed violation |
| 4 | Candidate awaiting clean confirmation | Candidate unconfirmed, inconsistent or incomplete |
| 130 | Keyboard interruption | Keyboard interruption |

The run command retains its collection-only exit codes and not_evaluated verdict. Offline analysis and clean checks do not overwrite raw observations. Confirmation of the deliberately seeded lab defect validates this implementation; it does not establish comparative research gains or discovery of a natural defect.
