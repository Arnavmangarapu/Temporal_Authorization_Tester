**Step 5: annotated generation, protected writes and minimization**

Version-two configurations support sharing_revocation, role_downgrade and ownership_transfer, each with a read or write action. Six example files are in examples/lifecycle-*.yaml. Version-one configuration, collection, analysis and confirmation remain supported without changing their configuration fingerprints.

This is a bounded generator over explicit action/state contracts, not an automatic OpenAPI/business-policy inference engine. Role/ownership policies and request payloads are defined for the controlled document lab. No external application or competing fuzzer is integrated in this milestone.

**The six experiment families**

| Lifecycle | Establish valid access | Transition | Post-deadline test |
|---|---|---|---|
| Sharing revocation | Alice shares with Bob; write tests grant write permission explicitly | Alice revokes the share | Bob's old/fresh credentials must lose the configured access |
| Role downgrade | Alice, the lab administrator, makes Bob an editor of role-managed documents | Alice changes Bob to viewer | Viewer cannot access this editor-required resource |
| Ownership transfer | Alice creates a document and transfers it to Bob | Bob transfers it back to Alice | Former owner Bob must lose access |

Each row has separate read and write configurations. The lab's role-managed documents require editor privileges for the subject's protected reads and writes; this is not a claim that all applications deny viewers read access. Alice's administrative audit access is explicit fixture policy and supplies a legitimate independent control even while Bob owns a document. In the ownership workflow Alice is the creator and final owner; Bob is the temporary owner whose old session is tested.

The lab now exposes PATCH /documents/{document_id}, POST /users/{subject_id}/role and POST /documents/{document_id}/owner. Only an administrator changes roles. Only the current owner or administrator transfers ownership. The four modes are immediate, delayed, stale_session and write_side_effect. The last deliberately commits an unauthorized mutation before returning 403. Correct delayed enforcement applies the same five-second maximum bound to sharing, role and ownership changes. Stable sessions capture sharing/ownership permissions and roles for the stale-session fixture; correct modes consult current state and the allowed grace period.

**Generate and execute a plan**

```bash
PYTHONPATH=src python -m temporal_auth plan examples/lifecycle-role-write.yaml --seed 7 > scenario.json
PYTHONPATH=src python -m temporal_auth run examples/lifecycle-role-write.yaml --scenario scenario.json --output artifacts
```

The target must already be running, with matching actor password variables set as described in the lab/runner guides. plan makes no network requests and needs no credentials. schema --version 2 exports the new configuration schema; the default remains version 1. run and check accept --seed to generate a scenario directly, or --scenario to load an existing manifest. --no-warmups omits optional warmups at generation time. Explicit manifests are validated against the supplied configuration rather than silently modified by the seed/warmup flags.

The generator builds a directed acyclic graph and performs seeded selection among currently eligible actions. Logins and creation can move relative to independent actions, while sharing/role/ownership setup must precede capture of the old session. Transition dependencies require successful protected-access setup and controls. Fresh login follows the transition. The deadline wait precedes post-transition probes. For writes, the seed chooses old-first or fresh-first order; each mutation remains paired with its own before/after control observations.

Every action has an ID and explicit dependencies. The stored scenario is authoritative for replay, including its topological order; seed records generation provenance. Unknown actions, duplicate actions, missing prerequisites, changed dependencies, wrong policies and invalid ordering are rejected. Required transitions, waits, observer readbacks and probes cannot be removed. Read plans have 15 actions by default, including one non-HTTP wait and two optional warmups; write plans have 21. Actual default request counts are therefore 14 and 20 respectively, when owner also serves as control.

Optional warmup_old and warmup_control are additional pre-transition protected reads. They can exercise permission caches or history-dependent behavior. Their presence is recorded rather than hidden as setup. They are included in the request budget.

**Independent verification of writes**

Before the transition, the old subject performs an authorized write using a unique setup marker. A control readback must establish that the write actually succeeded. This avoids claiming that a user lost a capability it never had.

For each old/fresh post-transition write probe:

1. The control reads the current resource and establishes its baseline content and owner.
2. The subject attempts PATCH with a new, session-specific marker.
3. The control independently reads the resource again.
4. The oracle compares the stored value with the baseline and attempted marker.

If the new marker is stored, an unauthorized effect is observed regardless of whether PATCH returned 200, 403 or another status. A claimed 200 without the matching state change is insufficient to report a write defect. A denied write that really committed is a candidate. Unhealthy readbacks, wrong resources/owners, unrelated state changes, missing markers or early probes remain inconclusive.

Write markers are distinct from the initial protected-content marker and from one another. The second probe's baseline must reflect the first probe's actual readback, so old-first and fresh-first traces are interpreted correctly. Candidate kinds are stale_session_write, fresh_session_write or unauthorized_write according to the observed session pattern. These describe evidence, not a proven internal root cause.

**Clean confirmation**

With the dedicated lab running in the desired mode and matching actor credentials set:

```bash
export LAB_RESET_KEY=local-lab-reset-key
PYTHONPATH=src python -m temporal_auth check examples/lifecycle-role-write.yaml --seed 7 --output artifacts
```

check resets the entire dedicated lab before discovery and each candidate replay. The same validated manifest is used, but credentials, user IDs, resource IDs and markers are reacquired. Both replays must reproduce the same protected effect/session pattern. The original request/runtime limits remain one shared budget including resets. Default full confirmation costs 45 requests for read plans with both warmups, or 63 for write plans; without warmups these become 39 and 57. A separate control login increases these counts.

The real HTTP generated-write test uses role downgrade in write_side_effect mode: both PATCH probes return 403, owner readbacks observe the attempted markers, and two clean reproductions confirm the seeded defect. This validates the tool against an intentionally defective benchmark, not an unknown natural vulnerability.

**Minimize a confirmed sequence**

```bash
PYTHONPATH=src python -m temporal_auth minimize examples/lifecycle-role-write.yaml artifacts/check-SOURCE_ID --output artifacts
```

minimize requires an existing confirmed version-two check and its original configuration. It reevaluates all three source traces and validates that their manifests agree before sending any request. Version-one or unconfirmed sources are rejected. The target must still implement the same configured policy; each search trial resets the dedicated lab and uses fresh state.

The reducer greedily tries deleting one optional warmup, updates the remaining dependency edges, and preserves the relative order of retained actions. It accepts a deletion only after discovery plus two matching clean confirmations of the reduced sequence. After an accepted deletion it restarts the search, because another deletion may have become possible. A failed or inconsistent reduction is retained as rejected evidence. A history-dependent test demonstrates that a warmup necessary for reproduction is kept.

The search has its own single request/runtime budget from the original configuration, shared by every trial and its confirmations. The already recorded source-check cost is reported separately by the source artifact; it is not free experimental work. Trial check summaries contain local totals plus shared cumulative totals. If the search exhausts its budget, it keeps the smallest sequence actually verified so far, including the original as fallback. Invalid reset credentials stop the search with an error rather than reporting a successful reduction.

Default read fixtures can drop both warmups, from 15 to 13 actions (14 to 12 HTTP requests). Write fixtures can drop both, from 21 to 19 actions (20 to 18 requests). The two accepted trial confirmations normally cost 81 search requests for reads or 117 for writes. These are fixture/request counts, not measured research improvements. This reducer searches deletion of the two declared optional actions only; it does not claim global minimum traces, minimize payloads or remove the required causal/evidence chain.

Search artifacts are stored under artifacts/minimize-UUID/:

```text
minimization.json         # Source ID, verified sizes, trial acceptance and costs
scenario.json             # Smallest verified manifest found
trials/check-UUID/         # Reset, discovery and two-replay evidence per trial
```

scenario.json can be supplied to run or check with --scenario. Minimization exits 0 for a completed bounded search, 1 for budget/error incompletion, 2 for invalid input/I/O failure and 130 for interruption. Check/analyze exit codes retain the meanings in the oracle/replay guide. Exported plans contain no tokens, passwords or captured resource IDs. Normal request artifacts retain the existing credential redaction and private file permissions.

**Limits and subsequent work**

Generation currently covers these six annotated lab families and seeded legal orders. It does not infer arbitrary workflows, add new lifecycle operations automatically, implement a coverage-adaptive search, or establish effectiveness against other fuzzers. The minimizer's search space is deliberately explicit. Step 6 subsequently added native Gitea/PocketBase read adapters and tool compatibility pilots; see [external pilots](external-pilots.md). Fair final effectiveness comparisons remain Step 9. No generation advantage or general research gain has been established.
