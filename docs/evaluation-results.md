**Step 9A: frozen artifact-evaluation results**

The canonical campaign completed all **1,039 required rows** with no harness errors. Its protocol was frozen before collection at SHA-256 `a97cfbaf9e2d3ea1942e392a9cff9fdc9f735a79bd9a5248519d272164fcf0fa`. All recorded row/evidence hashes passed analysis verification, and the frozen executable source fingerprints and environment remained unchanged.

See the [protocol](../benchmarks/artifact-v1.json), [machine-readable analysis](results/step9-artifact.json), [run table](results/step9-runs.csv) and [methodology/reproduction guide](evaluation.md). The corpus was used during development. It is not a held-out effectiveness study.

| Track | Recorded / required | Outcome |
|---|---:|---|
| Controlled logical clock | 870 / 870 | Three methods × 29 configurations × ten seeds; all methods agree in every matched case/seed triple |
| Early timing diagnostic | 60 / 60 | Unsafe early signals in all correct delayed traces; production oracle rejects all as pre-deadline evidence |
| Real loopback HTTP | 36 / 36 | All checks completed; identical verdicts in all 12 matched triples |
| Minimization | 9 / 9 | Every search completed; two optional actions removed, with clean confirmation of accepted reductions |
| Existing-application local profiles | 60 / 60 | Gitea/PocketBase × three profiles × ten seeds; no violation observed in these workflows |
| Native-tool applicability | 4 / 4 | Actual EvoMaster and RESTler invocations completed for both codebases; native verdicts remain not_evaluated |

**Controlled comparisons**

| Scheduling method | Checks | Defective configurations found | Correct configurations with any alarm | Expected inconclusive configurations classified correctly |
|---|---:|---:|---:|---:|
| Seeded DAG with optional warmups | 290 | 10 / 10 | 0 / 16 | 3 / 3 |
| Fixed eligible-action order | 290 | 10 / 10 | 0 / 16 | 3 / 3 |
| Seeded DAG without optional warmups | 290 | 10 / 10 | 0 / 16 | 3 / 3 |

Every method confirmed the defective configurations at every seed. Each produced 100 confirmed runs, 160 non-findings and 30 expected inconclusive outcomes. These are **ten configurations but only two planted root-cause families**, not 100 independent vulnerabilities. Correctness applies to the selected workflow/action. An expected target outage remains an execution error with an inconclusive verdict; missing policy and failed controls are not counted as successful denials.

All **290 matched logical-clock triples** and all **12 real-HTTP triples** agreed on verdict. This study therefore shows no detection advantage from seeded ordering over the simpler fixed scheduler. The minimal scheduler also preserved detection here. These methods share our annotation, actors, runner and oracle; they are scheduling ablations, not independent generic fuzzers.

For planted-defect confirmation in the logical track, default warmups cost 45 requests for reads and 63 for writes. Omitting the two optional reads reduced these to 39 and 57, respectively, including resets and both clean replays. Those six saved requests follow directly from deleting two reads in three attempts. They are not a newly discovered search-efficiency gain. Caps were not binding in these ordinary fixtures, and none of this measures scalability of a general API search.

**Oracle and timing diagnostics**

Retrospective projections reuse the full method's paired traces. Across the 100 planted-defect runs, old-session-only projections retained a signal in 100, fresh-session-only in 30, and status-only in 60. On the 160 correct runs, status-only produced ten unsafe signals on the public-metadata-200 control. These are signal counts, not independently executed or independently confirmed baseline findings. Replays are selectively available only for full-method candidates, and no query saving is measured by these projections.

The old-session projection already covers every planted defect in this corpus. Consequently, these data do not demonstrate an incremental detection benefit from adding fresh sessions. They do illustrate why fresh-session-only checking misses retained-session behavior and why status alone misses denied-but-committed writes or content disclosed under error responses.

The early diagnostic deliberately omitted the legitimate wait in six correct delayed configurations over ten seeds. All 60 traces exposed a policy-permitted effect that an unsafe detector could flag. The unchanged production oracle returned inconclusive with reason probe_before_deadline for every trace. No clean confirmation was attempted for these early signals, and they are not defects.

**Existing applications and native tools**

All 60 existing-application local profiles completed without an observed authorization violation. Gitea and PocketBase are two existing codebases, with unknown natural-defect denominators. Their finite non-findings establish neither recall nor global security. The P4-style profile selects one annotated event and preserves its functional setup; it is not an exact reproduction of the base paper's unavailable code. Request-count differences between profiles partly reflect their explicitly different number of probes/warmups.

The native runs consumed the curated endpoint/credential inputs described in their original harnesses. Forwarded native requests were 112 and 126 for EvoMaster on PocketBase/Gitea, and three and four for RESTler on PocketBase/Gitea. These counts include each tool's actual triggered behavior; they are not comparable effectiveness denominators. Lifecycle timing/old-fresh annotations and per-test reset are not consumed equivalently by these integrations. A native diagnostic or successful tool exit is not a clean-confirmed temporal finding. Raw native outputs remain available for triage in the local evidence bundle.

**Minimization, verification and limits**

Nine reduction searches completed. Each removed both declared optional warmups; accepted deletions required the existing discovery-plus-two-clean-replay rule. Search costs were 81 requests for the read configuration and 117 for the write configurations, separate from the source confirmation. This is greedy reduction within two optional actions, not global trace or payload minimization.

Before freezing, the full suite passed **348 tests in 129.84 seconds**, including twenty evaluation checks. The wheel built successfully, every packaged source/static file matched the source tree, and the evaluation CLI loaded from the extracted wheel outside the checkout. All 36 managed TCP fixture records report their processes stopped; no project RESTler container remained after collection.

The packaged real-HTTP sample also confirmed the seeded stale-session effect with two clean reproductions and stopped its target. That release check is separate from the canonical 1,039 rows. The offline audit reproduced the saved analysis and CSV without running a target. See [verification details](results/step9-verification.json).

These are exact finite-corpus counts. Repeated seeds and shared fixture implementations are correlated, so no population confidence intervals or general accuracy percentages are inferred. Logical-clock elapsed time is not wall time. The real-HTTP track has three repeats per configuration/method, suitable for operational validation rather than a powered performance claim.

Step 9A completes a reproducible artifact checkpoint. **Step 9's broader publication-readiness gates remain open:** independently reviewed held-out defects/applications, matched modern-tool effectiveness experiments, and a contribution defensible against the related work. The current evidence supports correct implementation on this corpus, with a negative scheduling result; it does not establish improvement over the base paper, RESTler or EvoMaster.
