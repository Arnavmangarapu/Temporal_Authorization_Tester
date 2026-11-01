**Step 9: frozen artifact evaluation**

This stage adds a reproducible experimental workload, immutable protocol/source fingerprints, raw evidence indexes, resumable execution and analysis. It evaluates the implemented artifact on known controlled fixtures and two supported existing applications. It does not turn development fixtures into held-out data or establish a publishable novelty claim.

This guide describes the frozen Step 9A snapshot. Later executable changes intentionally cause its source check to fail in a newer checkout; use commit `cb719ac0ae105f6a9add5ef89c5353a54db04a38` or that campaign's archived source. The separate [Step 9B native-read protocol](native-read-comparison.md) does not replace or rewrite Step 9A evidence.

The frozen corpus has 29 configurations: sharing/role/ownership × read/write × four lab modes, plus five explicitly labeled response/policy/availability controls. Ten configurations expose planted defects, sixteen are correct and three must be inconclusive. The ten defective configurations represent only **two root-cause families**: retained authorization snapshots and committing writes before returning denial. The error-status disclosure overlay is another representation of the snapshot defect, not a third root cause. Expected labels come from target source review, independent target tests and manual-API overlay ground-truth tests. These fixtures were used in development; no independent human mutation review or unseen defect-family generalization is claimed.

Correctness labels apply to the selected workflow and protected action. In particular, a read-only check in write_side_effect mode has a correct read path even though that fixture contains a write defect. A non-finding does not certify the entire application.

**Freeze before execution**

Install the README's dev/lab/web/monitoring extras. From the source checkout, create a new protocol file:

```bash
python -m temporal_auth.evaluation freeze benchmarks/my-protocol.json
```

An existing protocol is never overwritten. The freeze records case IDs, seeds 1000–1009, scheduling methods, 500-request/600-second shared budgets, monitoring disabled, a fixed execution-order seed, dependency versions and hashes of implementation, target, example and test sources. Freeze happens after harness development and tests, before canonical campaign execution; it is not an external preregistration. Neither a self-computed hash nor a timestamp proves authenticity against malicious edits.

For replication on a different machine/environment, freeze a separate protocol and label it as a replication. Runtime/source mismatches are rejected rather than silently presented as identical experiments. Document any differences. Documentation can evolve after the freeze; executable source/example/test changes require a new protocol and campaign. The frozen canonical file and aggregated result summary are linked from implementation status after collection.

**Tracks and comparison meaning**

| Track | Frozen workload | Meaning |
|---|---|---|
| logical | 29 cases × 3 scheduling methods × 10 seeds = 870 checks | Full production checker and oracle over actual in-process ASGI requests with an injected logical monotonic clock. Correctness and request counts; no real runtime claims. |
| early | 6 correct delayed cases × 10 seeds = 60 single traces | Evaluation-only collector deliberately omits the legitimate wait. Compare an unsafe effect signal with the unchanged production oracle's early-evidence rejection. No clean confirmation or defect claim. |
| tcp | 4 representative cases × 3 methods × 3 seeds = 36 checks | Real loopback HTTP, monotonic time and disposable target processes, including actual five-second waits and replay. Operational validation, not a powered speed benchmark. |
| minimize | 3 planted-defect cases × 3 seeds = 9 searches | Existing production reducer, two optional warmups, clean confirmation of accepted deletions and separately counted search cost. |
| external | 2 codebases × 3 local profiles × 10 seeds = 60 campaigns | Fresh native Gitea/PocketBase instances; equivalent local policy/accounts/reset setup and budgets across profiles. Existing applications have an unknown defect denominator. |
| native | 2 codebases × EvoMaster/RESTler = 4 invocations | Actual pinned tools, separately reported compatibility/applicability audit. Their inputs and native oracles remain unequal to the lifecycle harness. |

All 1,039 required rows are tracked explicitly, including failures and inconclusive results. A row being recorded is separate from its execution succeeding.

The three logical/TCP methods share the same policy, actor information, target, checker and confirmation rule:

- seeded-dag: the implemented seeded topological scheduler with both optional warmups.
- canonical-dag: lexicographically first eligible action with a fixed old-first write order; same required graph and warmups.
- seeded-minimal: seeded topological scheduling without the two optional warmups.

These are scheduling ablations of our annotated workflow, not independent generic fuzzers. They always retain mandatory transitions, sessions, probes and controls. Equal results are a valid negative finding about scheduling value on this corpus. Lower counts from removing known optional reads are an engineering tradeoff, not a proven new search technique.

Retrospective old-only, fresh-only and status-only projections use the full method's valid traces. A status-only signal means a 2xx probe, regardless of content/readback. The public-200 control can therefore generate an unsafe signal, while denied-but-committed writes and disclosed data under 403 can be missed. These projections execute no independent searches, save no measured requests and suffer confirmation-selection bias: only full-method candidates have two replay traces. They are sensitivity diagnostics, not measured P4/RESTler/EvoMaster effectiveness. Native single-event profiles likewise instantiate one selected event; the base paper's original code/settings are unavailable, so this is not an exact reproduction.

**Run and resume**

For logical-clock correctness and analysis diagnostics:

```bash
python -m temporal_auth.evaluation run benchmarks/my-protocol.json --output artifacts/my-evaluation --track logical
python -m temporal_auth.evaluation run benchmarks/my-protocol.json --output artifacts/my-evaluation --track early
python -m temporal_auth.evaluation run benchmarks/my-protocol.json --output artifacts/my-evaluation --track minimize
```

For all tracks, first fetch the pinned binaries and build RESTler; Git, Java and a working Linux Docker daemon are required for the relevant native tools:

```bash
python scripts/fetch_pilot_tools.py
python scripts/build_restler.py
python -m temporal_auth.evaluation run benchmarks/my-protocol.json --output artifacts/my-evaluation --track all
```

Use --tools to specify another verified binary directory. No website or monitoring stack needs to be running. All experiments are serial and each native fixture is fresh. Stop with Ctrl+C; completed rows remain, and a repeated command resumes unrecorded keys after checking prior evidence. Unfinished directories are retained but do not become completed rows. A torn JSONL line, modified evidence or changed row fails verification; do not silently delete inconvenient rows. Harness errors are recorded and stop further collection. Fixing executable code requires a new protocol, preserving the failed campaign separately.

Each row contains track/case/method/seed, actual status/verdict/cost, relative evidence location, file hashes and a row hash. configs and plans are saved alongside original checker/run reports and incremental request events. Reset, authentication, controls and confirmation remain in shared budgets. Real managed-target startup requests are included and distinguished from the event timeline; native bootstrap/readiness accounting retains its original explicit scope. Logical-clock model elapsed time is never relabeled as wall time. Native tools have their own frozen smoke settings (including a ten-second EvoMaster search) and are not ranked against 600-second lifecycle budgets.

**Analyze**

```bash
python -m temporal_auth.evaluation analyze benchmarks/my-protocol.json --output artifacts/my-evaluation
```

This verifies every recorded row/evidence hash and produces analysis.json, runs.csv and report.md. Partial coverage is visible and the command exits 1 if any frozen row is missing. A recorded infrastructure failure remains a failure. Read the per-track statuses as well as coverage.

For offline review on a different machine, use the frozen source snapshot and the raw campaign from the audit bundle. Install the source's documented dependencies, then run:

```bash
python scripts/audit_evaluation.py --source . --campaign /path/to/extracted/evaluation-v1
```

Replace the campaign path with its actual extraction location. This helper verifies the frozen source and protocol, copies raw data into a temporary directory, checks every row/evidence index, and compares regenerated analysis/CSV with the saved outputs. It executes no target and leaves the original campaign unchanged. Its post-processing is distinct from replicating measurements; the execution CLI still requires the frozen runtime or a separately labeled new protocol. The raw bundle must be available locally; the repository's small aggregate JSON/CSV alone cannot support this audit.

Report exact counts over this finite corpus. Repeated seeds do not create new defects, and fixtures sharing the same implementation are correlated. The report separates configuration coverage, two root-cause families, candidate/confirmed false alarms, expected inconclusive cases, sequence completion, replay reliability and paired request costs. It does not manufacture population confidence intervals from requests or repeated fixtures. No natural-defect recall is computed for the two existing codebases. Three real-HTTP repeats are too few for a general performance claim; sampled request timestamps do not establish an enforcement-time distribution.

Publication readiness requires additional held-out targets/defect families, independent mutation review, input-matched modern-tool experiments where supported and a defensible contribution beyond the related work. A complete artifact campaign may show that the current scheduler adds no detection benefit. Keep that result and narrow the claim rather than selecting a more favorable denominator.
