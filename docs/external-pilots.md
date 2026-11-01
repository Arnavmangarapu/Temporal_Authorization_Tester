**Step 6: native application adapters and baseline pilots**

Two independent existing codebases now work end to end: Gitea 28.3.0 and PocketBase 0.40.6. The tester calls their native APIs in fresh local instances. It does not replace their authorization logic with the document lab. These are development pilots; no revocation bypass or comparative improvement has been established.

The commands below retain their original compatibility scope. A separate [Step 9B shared-input pilot](native-read-comparison.md) prepares identical post-transition role/resource semantics for the native runners and records independent trace coverage. It does not reinterpret these older runs as matched effectiveness results.

**Application screening and adaptation**

| Candidate | Decision | Policy and adaptation |
|---|---|---|
| Gitea | Implemented and executed | Create an ordinary user and private repository; add a read collaborator; store a random marker in a file; remove collaboration; probe raw file access. The repository owner is also the fixture administrator and provides the independent control. |
| PocketBase | Implemented and executed | Create an auth collection with editor/viewer roles and a protected record collection. Its viewRule requires the current authenticated role to be editor. Downgrade the subject to viewer and probe record access. The superuser supplies setup and independent readback. This tests the existing framework's authorization engine under a researcher-supplied schema and policy; it is not an independently deployed business application. |
| OWASP Juice Shop | Deferred after initial source screening | An intentionally vulnerable training application, but this pilot did not establish a suitable bounded permission-change workflow and reset contract. No claim that integration is impossible. |
| OWASP WebGoat | Deferred after initial source screening | Its documented scope is teaching security lessons. A lesson-specific lifecycle policy and adapter would need separate validation; intentional flaws must also be distinguished from natural findings. |

Sources: [Gitea's pinned collaborator handlers](https://github.com/go-gitea/gitea/blob/v28.3.0/routers/api/v1/repo/collaborators.go), [Gitea token API documentation](https://docs.gitea.com/development/api-usage/), [PocketBase access rules](https://pocketbase.io/docs/api-rules-and-filters/), [PocketBase's pinned login handler](https://github.com/pocketbase/pocketbase/blob/v0.40.6/apis/record_auth_with_password.go), [Juice Shop](https://github.com/juice-shop/juice-shop), [WebGoat](https://github.com/WebGoat/WebGoat).

The local fixture contract expects denial after the acknowledged synchronous update, with a 0.05-second probe tolerance. An administrator verifies the changed role or removed collaboration before probes. This is an explicitly annotated, single-process local policy, not a vendor's distributed propagation SLA. These adapters cannot attach to arbitrary remote services.

Both adapters currently check protected **reads**. External writes, automatic workflow inference and external trace minimization are not implemented. The version-two lab generator, write oracle and reducer remain available through the existing commands; external-check uses explicit native workflow templates and a separate evidence schema.

**Local comparison profiles**

Every profile gets the same native API, application version, owner/subject accounts, marker, policy, transition-state control and content-based oracle. Each gets a fresh process and empty database. Authentication, setup, controls and probes count as workflow requests; readiness polls count separately and are included in total requests. Bootstrap CLI operations and elapsed time are recorded.

| Profile | Implemented behavior | Interpretation |
|---|---|---|
| temporal | Functional setup, pre-access and control, permission change, old and post-change-login probes, final control | Explicit native read template; tests both login generations |
| p4-single-event | Same functional setup and policy; one selected post-transition protected-read event; seed 0 selects fresh, seed 1 selects old | A documented P4-style instantiation, not an exact reproduction of unavailable original code. Setup/control requests supply functional evidence. |
| generic-valid-order | Same valid causal chain and oracle, two optional functional warmups in seeded order, both probes in seeded order | A limited scheduling ablation. It does not represent all generic fuzzers or demonstrate a generation advantage. |

The [P4 paper](https://thescipub.com/pdf/jcssp.2024.1176.1184.pdf) already supports functional workflows. These profiles preserve that capability. Reduced request counts from omitting a probe or two warmups are implementation choices, not a research efficiency result.

**Measured local results, 1 November 2026**

Each row covers seeds 0 and 1, with one discovery workflow per seed. No candidate occurred, so no replay was necessary. The tests separately exercise discovery plus two clean reproductions, ineffective transitions, nonreproducing candidates and exhausted confirmation budgets using explicitly labeled test doubles.

| Application | Profile | Workflow HTTP requests per seed | Readiness attempts per seed | Total HTTP attempts per seed | Outcome |
|---|---|---:|---:|---:|---|
| Gitea 28.3.0 | temporal | 16, 16 | 14, 10 | 30, 26 | No protected disclosure observed |
| Gitea 28.3.0 | p4-single-event | 15, 13 | 12, 15 | 27, 28 | No protected disclosure observed |
| Gitea 28.3.0 | generic-valid-order | 18, 18 | 34, 17 | 52, 35 | No protected disclosure observed |
| PocketBase 0.40.6 | temporal | 14, 14 | 2, 2 | 16, 16 | No protected disclosure observed |
| PocketBase 0.40.6 | p4-single-event | 13, 12 | 2, 2 | 15, 14 | No protected disclosure observed |
| PocketBase 0.40.6 | generic-valid-order | 16, 16 | 2, 2 | 18, 18 | No protected disclosure observed |

Across these 12 runs: 181 workflow requests plus 114 readiness attempts = 295 total HTTP attempts. Readiness includes failed connections during startup. Counts vary with machine load; regression tests were running during part of this pilot, so elapsed times cannot support a performance ranking.

An old login is retained before the transition, and a separate successful login is made afterward when a fresh probe is selected. PocketBase can return identical token values for those exchanges within one second. The temporal seed-1 run did so; its report sets fresh_credential_matches_old=true. Treat that run as two login exchanges using an identical bearer value, not two distinct token snapshots. No token-expiry or refresh-token policy was tested.

Machine-readable rows and evidence hashes are in [the results manifest](results/step6-pilot.json). Raw observations remain in [the local matrix evidence](../artifacts/step6-matrix/matrix.json). No mutation recall or natural-vulnerability recall is computed: these applications have no known complete defect denominator. A non-finding does not establish security or a zero false-alarm rate.

**Real modern-tool execution**

The actual EvoMaster jar and compiled RESTler runtime were executed. Both consumed curated slices containing native paths and fixed fixture resource IDs. Their native reports remain separate from the temporal verdict.

| Native run | Configuration and measured scope | Measured result |
|---|---|---|
| EvoMaster 6.2.0 / Gitea | Seed 0, black box, security=true, 10-second search, 600 requests/minute; owner and old-subject tokens; 128 forwarded native requests, 158 total including setup/readiness | All 3 supplied operations achieved 2xx coverage. Three native fault labels, discussed below. |
| EvoMaster 6.2.0 / PocketBase | Same search settings; 115 forwarded native requests, 123 total | Both supplied operations achieved 2xx coverage. Two native OPTIONS/Allow-header labels. |
| RESTler commit 6d984dee / Gitea | Compile plus fuzz-lean; namespacerule and useafterfree enabled; owner plus unrelated unauthorized attacker; 4 native requests, 30 total | 3/3 supplied operations covered, one NameSpaceRuleChecker request, zero native bug buckets. |
| RESTler commit 6d984dee / PocketBase | Same mode/checkers; 3 native requests, 14 total | 2/2 supplied operations covered, one NameSpaceRuleChecker request, zero native bug buckets. |

UseAfterFreeChecker sent **zero** requests in both slices. Collaborator removal does not delete the repository, and the PocketBase slice has no DELETE. Enabling a checker is not evidence that its triggering conditions occurred. RESTler's [checker documentation](https://github.com/microsoft/restler-fuzzer/blob/6d984deedbc54aad957fa3da0c7e9e5df23a2aee/docs/user-guide/Checkers.md) describes that distinction. Its namespace attacker is a third account denied access even while the recipient is authorized; an authorized collaborator would be an invalid namespace negative control.

EvoMaster's [native security options](https://github.com/WebFuzzing/EvoMaster/blob/v6.2.0/docs/options.md) were active. The Gitea run produced F100 and F200 for the **same** invalid permission value causing HTTP 500, plus F310 for a GET operation absent from the curated schema. The server error was replayed directly in two fresh Gitea instances with healthy resource controls; it is an input-validation observation, not a demonstrated authorization bypass. The GET collaborator handler exists in Gitea's source; absence from our partial schema is not a new hidden security flaw. PocketBase's two F201 labels concern OPTIONS/Allow behavior and remain unadjudicated protocol diagnostics. None is counted as a confirmed temporal defect or a new vulnerability discovery.

These are native compatibility checks, **not an input-matched effectiveness benchmark**. The native tools do not consume the old/fresh lifecycle annotation or timing bound in this harness, and native sessions are not reset per generated test. Search budgets, auth contexts and oracle scope differ. Their request counts and labels cannot be ranked against our fixed workflows. Step 9 must resolve these differences, use matched final inputs where supported and preserve unsupported cases explicitly.

Exploratory evidence is retained separately: an early unpaced EvoMaster run hit the request cap; early schema/proxy versions produced instrumentation artifacts; the first RESTler attempt failed because of a Docker mount permission. Those runs are excluded from the canonical rows. The final proxy forwards raw bodies, actor credentials, end-to-end test headers and HTTP-security methods; tests verify this behavior.

**Reproduce**

Prerequisites: project Python dependencies, Linux x86_64, Git for Gitea, Java for EvoMaster, and Docker for RESTler. Scripts were exercised on Python 3.14.8; source extraction uses Python's data safety filter. Downloads are pinned in [tools.lock.json](../integrations/tools.lock.json), with checksums verified before extraction. Runtime checks also verify application executable and EvoMaster jar digests.

```bash
python scripts/fetch_pilot_tools.py
python scripts/build_restler.py
PYTHONPATH=src python scripts/run_external_matrix.py

PYTHONPATH=src python -m temporal_auth external-check gitea --profile temporal
PYTHONPATH=src python -m temporal_auth external-check pocketbase --profile p4-single-event --seed 1
PYTHONPATH=src python -m temporal_auth native-evomaster gitea --seconds 10
PYTHONPATH=src python -m temporal_auth native-restler pocketbase
```

RESTler uses the unmodified official Dockerfile at full commit 6d984deedbc54aad957fa3da0c7e9e5df23a2aee; the image ID is recorded. Upstream base/dependency tags resolve during build, so the source commit alone does not promise a bit-identical rebuild. Telemetry is disabled. Its Docker mount uses :Z on a project-owned temporary directory for SELinux compatibility, and the process runs with the invoking user's UID/GID.

external-check defaults to a 500-request/180-second campaign budget. Candidates require two additional matching reproductions in independently created instances; failures retain candidates without promoting them. The request cap includes readiness, authentication, controls and replays. Bootstrap CLI commands are additional non-HTTP costs. The elapsed clock includes startup, waits and cleanup. Budgets are cooperative: an in-flight synchronous read or process cleanup can finish after the nominal wall-clock deadline; this is not a hard real-time scheduler.

external-check exits 0 for a completed non-finding, 3 for a clean-confirmed fixture-policy violation, 4 for an unconfirmed candidate, 1 for an inconclusive/error result and 2 for invalid input/file errors. Native commands exit 0 only for completed tool runs, retaining authorization verdict not_evaluated.

Pilot directories store pilot.json and attempt directories containing attempt.json/events.jsonl. Native directories contain native.json, schema.json, observations and sanitized native output. Authentication bodies/headers, bootstrap databases and raw credential configuration are not exported. Evidence has private file permissions. Temporary processes and data are cleaned on success, failures and interruption. Confirmed external results would still need policy, root-cause and natural/seeded review before publication claims.

Verification: **276 tests passed**, including 39 new adapter/oracle/orchestration/proxy tests. Two application binaries, 12 common-profile pilots, four canonical modern-tool runs and independent server-error triage were exercised locally. This was the Step 6 stop point. Steps 7 and 8 subsequently added the [web interface](web-interface.md) and [optional monitoring](monitoring.md).
