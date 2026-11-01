**Step 9B: shared post-transition read inputs**

This follow-up aligns the native tools' resource, credential roles and post-transition state. It is a scoped applicability/coverage pilot. It does not establish relative defect-detection effectiveness, because no known defective existing application is present. The original Step 9A campaign remains frozen and unchanged.

This guide describes the Step 9B snapshot at commit `e91e4aad3b1c498d81e30231f483c2b92c7cd033`. Later source changes, including Step 9C's compressed-response collector correction, require the archived Step 9B source for its frozen run/audit. The [Dolibarr study](dolibarr-reproduction.md) is a separate campaign, and its known defective target does not retroactively change the scope of this pilot.

**Common workflow**

Each driver gets a new process/database with the same pinned application version and native adapter. Setup creates an ordinary recipient, a private resource and a random protected marker. The harness logs in before the change, verifies recipient and owner access, revokes collaboration in Gitea or downgrades the editor role in PocketBase, verifies the administrative state, logs in again and waits until the declared local bound plus 0.05-second tolerance has elapsed.

The search surface contains one fixed-resource GET. It cannot grant access back or reverse the transition. Each invocation supplies the owner and either the retained recipient credential or the fresh-login recipient credential. Both generations are collected and reported separately; PocketBase can issue the same token bytes twice within a second, so two login operations do not imply distinct tokens. IDs, credentials and marker values differ between disposable instances; semantic inputs are aligned, not byte-identical.

| Driver | How it uses the prepared inputs | Stopping rule |
|---|---|---|
| Scripted read | Makes an owner GET and a selected-recipient GET. This is a deterministic oracle/coverage diagnostic. | Two generated requests |
| EvoMaster 6.2.0 | Real black-box search with security checks enabled; the same owner/recipient fixed headers and GET-only schema. | Ten-second search; 500 total HTTP/180-second shared ceiling |
| RESTler pinned at 6d984dee | Real compiler and fuzz-lean run; owner as primary user, selected recipient as the NameSpaceRule secondary user, explicit fixed-path trigger. | Native fuzz-lean completion with its existing settings; 500 total HTTP/180-second shared ceiling |

All drivers share the 500-request/180-second ceiling, including readiness, setup, logins and controls. Bootstrap commands are additional non-HTTP fixture work. Budgets are cooperative; in-flight work and cleanup can finish after a deadline. Search/stopping rules differ, so observed request counts are descriptive and must not be ranked as efficiency gains. UseAfterFree is disabled for this GET-only comparison: collaboration revocation does not delete the protected resource. The older compatibility mode remains available unchanged.

After each driver, the harness independently probes both recipient credentials and the owner control. It records how many exact GETs the driver actually sent with the intended recipient credential, whether those requests occurred after the deadline, and whether complete responses disclosed the protected marker. Missing coverage is `not_exercised`, not a clean non-finding; malformed/error/early evidence is inconclusive. A content signal remains a candidate and is never promoted to clean confirmation here. Harness postchecks and native forwarded costs are separate fields.

Native logs, generated tests and native bug/fault output remain available as sanitized evidence. **The common trace-content verdict is our independent observation, not the native tool's own fault label.** This pilot does not evaluate native fault-label accuracy or lifecycle generation. The harness supplied the lifecycle and its policy. Each invocation is isolated, but native tests within an invocation do not receive individual resets.

**Run, resume and stop**

Use Linux, or the README's Windows/WSL setup. Install the development/lab extras and the external prerequisites in the [native pilot guide](external-pilots.md): Java, Git, the pinned downloaded tools and Docker. No website or monitoring service needs to be running.

```bash
source .venv/bin/activate
python scripts/fetch_pilot_tools.py
python scripts/build_restler.py
python -m temporal_auth.evaluation.native_comparison freeze benchmarks/native-read-local.json
python -m temporal_auth.evaluation.native_comparison run benchmarks/native-read-local.json --output artifacts/native-read-local --tools artifacts/tools
python -m temporal_auth.evaluation.native_comparison analyze benchmarks/native-read-local.json --output artifacts/native-read-local
```

The freeze fixes two applications × two credential generations × three drivers × three seeds = 36 invocations, with deterministic shuffled execution order, source hashes, tool pins and measurement environment. An existing freeze is never overwritten. To execute the published protocol, use `benchmarks/native-read-v1.json` from its exact source snapshot and environment. On a different environment or after changing source/tests, create a separately named freeze. Do not rewrite an earlier protocol to make it match new code.

Press **Ctrl+C in the running terminal** to stop; tool processes and the owned target are cleaned up. Repeat the identical run command to resume. Completed rows, failures and exported evidence are retained and hash-checked. A missing/tampered artifact, duplicate/torn row or changed protocol is rejected. Incomplete directories from interruption remain as uncounted evidence. Failures are recorded rather than silently rerun for a better result; executable fixes require a new protocol. An output lock prevents concurrent collection into the same campaign.

Results live in `artifacts/native-read-local`: frozen protocol, append-only rows, individual `native.json`/`events.jsonl`/sanitized native exports and aggregate `analysis.json`. Keep this directory if you want an auditable result; the source repository contains only the small published protocol and summaries.

For offline audit with an available raw bundle and its frozen source, install the source's documented dependencies and run:

```bash
python scripts/audit_native_comparison.py --source /path/to/frozen/source --campaign /path/to/native-read-v1
```

This checks source/protocol/evidence hashes and exact regenerated analysis without launching any target or tool. It allows a different analysis environment, which is distinct from replicating measurements. The Step 9A source fingerprint predates this implementation: use commit `cb719ac0ae105f6a9add5ef89c5353a54db04a38` or its archived source when auditing or rerunning Step 9A. Never update its saved source hashes or rows to reflect this follow-up.

External bug screening is documented [separately](external-benchmark-screening.md). Independently defective application pairs and native fault-label comparisons remain future gates.

**Measured checkpoint results**

The [frozen protocol](../benchmarks/native-read-v1.json) has SHA-256 `9edb32be11ca88d67ee43e86cfa3cf2dda41136a8bf14def8a9713c0cc390b5e`. All 36 invocations completed, with valid controls and intended-recipient GET coverage in every invocation. There were no independent protected-content candidates or inconclusive trace verdicts. The [aggregate JSON](results/step9b-native-read.json) retains each application/generation/driver cell and descriptive costs.

| Application | Credential generation | Scripted completed / exercised | EvoMaster completed / exercised | RESTler completed / exercised |
|---|---|---|---|---|
| Gitea 28.3.0 | Retained | 3 / 3 | 3 / 3 | 3 / 3 |
| Gitea 28.3.0 | Fresh login | 3 / 3 | 3 / 3 | 3 / 3 |
| PocketBase 0.40.6 | Retained | 3 / 3 | 3 / 3 | 3 / 3 |
| PocketBase 0.40.6 | Fresh login | 3 / 3 | 3 / 3 | 3 / 3 |

The drivers collectively issued 572 exact recipient GETs: 548 from EvoMaster, twelve from RESTler and twelve from the scripted diagnostic. All returned 404 without the protected marker; the independent owner checks succeeded. The entire campaign used 2,165 HTTP requests including fixtures, of which 1,300 were native/scripted forwarded requests; each invocation had three additional harness postchecks. These are execution counts, not independent defects or an efficiency ranking.

PocketBase returned identical old/fresh token bytes in sixteen of its eighteen invocations. Both login operations occurred in the required order, but this subset cannot support conclusions about distinct-token behavior. All RESTler invocations used the same recorded image ID, `sha256:bf9baa01fa78ffb318928a0786a80d16df34c3c452268a3cdee1537189a4a07c`. Target binary hashes were identical across their respective invocations.

Regression validation passed **362 tests in 116.00 seconds**, including fourteen new comparison/provenance checks. An offline audit regenerated the 36-row analysis exactly, and the earlier 1,039-row Step 9A audit still passed against its original source snapshot. Owned target processes and RESTler containers were absent after collection. See [verification provenance](results/step9b-verification.json).

This closes the input-alignment and screening checkpoint. It leaves native fault-label evaluation, independently reproduced defective/fixed pairs, held-out-family assessment and novelty review open. None of these non-findings establishes that one tool is better at detecting authorization defects.
