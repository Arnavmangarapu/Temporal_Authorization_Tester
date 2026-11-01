**Implementation status**

Step 1 corresponds to the policy/comparison foundation (Stage 0 in the detailed plan). Steps 2–4 added the target, collector and confirmation; Step 5 added annotated lifecycle generation, write verification and bounded reduction. Step 6 added native existing-application read adapters and baseline compatibility pilots. Step 7 added the local browser workspace and separate persistent worker. Step 8 adds optional evidence-backed monitoring.

| Step | Status | Evidence |
|---|---|---|
| 1. Policy/comparison and configuration foundation | Complete for the initial sharing-revocation contract | Validated models, YAML loader, JSON Schema command, example, comparison notes and automated tests |
| 2. Controlled document-sharing application | Complete | Immediate, delayed and stale-session modes; SQLite isolation, authentication, sharing API, reset and independent HTTP tests |
| 3. HTTP runner and experiment CLI | Complete for document_lab_v1 | Bounded share/read/revoke workflow, isolated sessions, dynamic bindings, CLI and versioned JSON evidence |
| 4. Temporal oracle and replay | Complete for read-only sharing revocation | Offline analysis, protected-marker/temporal/control checks, two clean replays and one shared campaign budget |
| 5. Generalized generation and write verification | Complete within the annotated lab scope | Version-two lifecycle graphs, read/write checks, effect readbacks and clean-confirmed optional-action minimization |
| 6. Existing-application adapters and baseline execution | Complete for native protected-read pilots | Two pinned codebases, 12 local-profile runs, real EvoMaster and RESTler compatibility checks; final matched effectiveness evaluation remains Step 9 |
| 7. Web interface | Complete for the local single-worker workspace | Guided/configured labs, native pilots, durable SQLite jobs, progress, cancellation, findings/evidence and executable replay downloads |
| 8. Prometheus and Grafana | Complete for the optional local worker stack | Bounded metrics, evidence reconciliation, restart recovery, deduplicated finding signatures and provisioned dashboard; see the monitoring guide |
| 9. Frozen evaluation and release | Not started | No detection or improvement results claimed |

**Step 1 verification**

Tested on Python 3.14.8 with the dependency versions pinned in pyproject.toml. The automated suite covers valid/unknown/immediate timing; missing, negative and non-finite bounds; invalid budgets; mismatched actors and operations; protected-field syntax; ambiguous YAML; credential handling; and CLI/schema behavior. The example validates without requiring a running target or resolving password environment variables.

Verification result: `python -m pytest -q` — 63 passed. The source-tree validation command also completed successfully against examples/document-lab.yaml.

Source-level comparison notes identify overlap with RESTler, EvoMaster and AuthREST. Publication novelty and target compatibility remain provisional until deeper implementation review and pilot comparisons. This step does not certify a novel research contribution.

**Step 2 verification**

At Step 2 the full suite passed 94 tests. The 31 added target checks cover old/fresh sessions across all three modes, exact delayed-enforcement boundary, repeated revoke, regrant, unrelated-user denial, owner-only sharing, session/state isolation, protected reset, invalid authentication, configuration/OpenAPI agreement and settings validation. A real TCP test starts all three targets, waits beyond the actual five-second bound and verifies the protected marker and owner control. All temporary servers are shut down afterward.

The sandbox blocks socket-pair communication required by FastAPI's test client. The tests were successfully run outside that restriction. Wheel packaging was checked to include both the tester package and the independent document_lab package. The lab's startup/settings integration uses FastAPI's lifespan mechanism; no tester engine code is used for target ground-truth verification.

**Step 3 verification**

Final verification: `python -m pytest -q` — 133 passed. Coverage includes all lab modes, old/fresh generation and cookie isolation, actual account/resource bindings, protected-access setup, request/runtime limits, streaming-size limits, cancellation evidence, credential redaction, unsupported templates, unknown policy, redirect refusal and invalid login/JSON responses. The real-HTTP CLI test confirms 12 recorded requests and actual probe starts beyond the five-second deadline. Wheel contents and HTTPX runtime dependency metadata were also checked. No automatic security verdict or research improvement is claimed.

Evidence is one new directory per run with run.json and incrementally flushed events.jsonl. Credentials stay in memory and are omitted/redacted in exported observations. The run command uses the explicit document-lab payload contract; automatic OpenAPI inference remains unimplemented. Step 4 adds a separate reset/replay coordinator.

**Step 4 verification**

Final full regression: `python -m pytest -q` — 179 passed. The 46 added checks cover the three independent lab modes, content disclosure under error statuses, benign public 200 responses, policy conflicts, incorrect timing, failed controls, malformed/missing evidence, session/resource identity, unknown policy, ineffective resets, wrong reset credentials, shared request/runtime budgets, cancellation and flaky/nonreproducing candidates. The real-HTTP check CLI performs discovery plus two independent clean replays and confirms the seeded stale-session defect using exactly 39 requests, including three resets. The correct immediate/delayed fixtures produce no_violation_observed in the oracle/check integration tests.

Offline analyze creates analysis.json without editing observations and cannot confirm a finding. check requires an explicit fixture reset credential and stores confirmation/budget details in check.json. Missing evidence or incomplete confirmation never promotes a candidate. This milestone verifies a controlled seeded defect; no new real-world vulnerability or research improvement is claimed. Protected-write verification and minimization are deferred to Step 5.

**Current research boundary**

Steps 1–8 are implemented and verified within the documented local scope. Step 9, the frozen comparative evaluation and release, remains pending. Historical verification summaries below describe each milestone; generated local artifacts are not distributed in this repository. See [results provenance](results/README.md).

**Step 5 verification**

Final full regression: `python -m pytest -q` — 237 passed. The 58 added checks exercise seeded graph reproducibility/dependencies, all six lifecycle/action families across four lab modes, both write orders, independent state readbacks, misleading 200 responses, bad/early evidence, role/owner administration, minimization, required-history retention and budget/error fallback. A real HTTP plan/check CLI test confirms writes committed despite 403 responses after role downgrade, with two clean reproductions and 63 total requests including resets.

Version-one models/configuration fingerprints are preserved. Version two supports explicit sharing, editor-role and ownership policies; these are annotated controlled targets, not arbitrary API inference. Each accepted reduction is independently clean-confirmed. The reducer currently searches deletion of the two optional warmup actions and never removes required causal/evidence actions; global/payload minimization and adaptive coverage scheduling are not claimed. All resource-cost examples are fixture counts, not comparative research gains. See the generation/minimization guide for commands, scope and limits.

**Step 6 verification**

Full regression: `python -m pytest -q` — **276 passed**. The 39 added tests cover native PocketBase request contracts, protected-content oracles under error statuses, missing/early/failed controls, clean replay orchestration, ineffective transitions, shared budgets, profile costs, credential redaction and real TCP proxy fidelity. Test doubles with seeded failures are explicitly separate from existing-application evidence.

The offline wheel includes all integration modules. Download verification and the cached RESTler build script were exercised; edited Markdown links and all canonical evidence hashes were checked. No owned application process or RESTler container remained running after verification.

Gitea 28.3.0 and PocketBase 0.40.6 were downloaded from official releases, checksum-verified and run in disposable local instances. All 12 temporal/P4-style/generic profile pilots completed without observing protected disclosure after the declared local transitions. Actual EvoMaster 6.2.0 security-enabled runs and a RESTler build pinned to commit 6d984deedbc54aad957fa3da0c7e9e5df23a2aee executed against both applications. Native labels, actual checker request counts and instrumentation failures are reported separately; none establishes a new temporal vulnerability or comparative gain. See [the pilot guide](external-pilots.md) and [results manifest](results/step6-pilot.json).

External adapters use explicit native read templates and a separate evidence format, rather than the version-two lab generator/reducer. PocketBase's schema is researcher-supplied; its post-change login can return an identical token value within one second, which is recorded. Timing is an annotated single-process fixture contract, not a vendor propagation SLA. External writes, broader scheduling evaluation, matched final competitor inputs and frozen effectiveness measurements remain outside this completed pilot milestone.

**Step 7 verification**

Final full regression: `python -m pytest -q` — **318 passed in 111.53 seconds**. The 42 added web tests cover guided/configured targets, all six lab configurations, Host/origin/CSRF boundaries, unknown timing, durable queue claims, queue limits, cancellation races, retained candidates, evidence escaping/export limits, real worker confirmation/cancellation, worker-crash recovery and rejecting a second dashboard without interrupting the first worker. Existing CLI/oracle/native-adapter tests remain passing. The final web suite also verifies that a future policy deadline stays correctly positioned when a trace ends early.

Chromium completed ten browser checks across seven jobs, including a confirmed seeded read, correct enforcement, fresh replay, a confirmed protected-write effect, cancellation, PocketBase and Gitea. Browser navigation did not interrupt execution. Evidence downloads, finding filters, visible keyboard focus and 390-pixel mobile layouts were verified with no page errors. The downloaded Python replay independently reproduced the seeded read finding twice using new credentials. A second browser pass also verified existing history after server restart.

The offline wheel includes every web module, template, stylesheet, script, font and vendor license. Its files match the final source. A separate process using the extracted wheel, outside the checkout, served all assets, ran its worker and managed lab, returned a correct non-finding and exported evidence. Documentation links and vendored asset hashes were checked. Results and local evidence references are recorded in [step7-ui.json](results/step7-ui.json); usage is in [the interface guide](web-interface.md).

The interface uses explicit local policies and the same core verdict logic as the CLI. Native competitor runners remain CLI-only; external writes, external minimization, multi-user/remote hosting, Prometheus/Grafana and final effectiveness evaluation are not included in this milestone.

**Step 8 verification**

Final full regression: `python -m pytest -q` — **328 passed in 113.12 seconds**, including ten monitoring tests. These cover incremental JSONL reads and partial lines, request counts and histogram sums, native event formats, error outcomes, malformed evidence, confirmation deduplication, sequence/deadline samples, bounded labels, symlink exclusion, history beyond 200 jobs, operation without the optional dependency, actual worker crash/restart and occupied-port failure reporting. Monitoring remains disabled by default; the worker owns the optional loopback exporter.

The real Prometheus/Grafana stack was built from digest-pinned upstream images. Public provisioning is copied into small local images because this mounted drive rejected container bind-mount reads under SELinux. The Docker context excludes private evidence. Prometheus configuration passed promtool; its target was healthy. All 13 dashboard queries and Grafana's data-source proxy worked. Chromium displayed the provisioned dashboard without page errors or failed API responses.

Six monitored jobs produced exactly **198 stored HTTP events**, 12 completed sequences and two distinct confirmed seeded finding signatures. Two independent read-confirmation jobs deduplicated into one signature; the other signature was a confirmed write effect. Exported event counts, histogram count/sum, terminal-job totals and fixture totals matched stored records. The worker also reconstructed the same final totals after restart. Three unmonitored jobs completed correctly. A three-pair alternating wall-time pilot measured medians of 5.760 seconds disabled and 5.866 seconds monitored (approximately +1.84%); the small sample, policy waits, startup and polling prevent a general overhead or significance claim.

The final wheel contains the matching monitoring/worker/CLI modules and optional dependency metadata. From outside the checkout, the extracted wheel started its worker, completed a managed-lab non-finding and served metrics over HTTP. See [the monitoring guide](monitoring.md) and [verification manifest](results/step8-monitoring.json). This milestone adds operational visibility; final matched effectiveness evaluation and release remain Step 9.
