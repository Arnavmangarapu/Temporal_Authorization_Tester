**Step 1 research comparison specification**

Documentation and papers checked on 1 November 2026. The table below describes source-based capabilities. Step 6 subsequently executed local profiles and native modern-tool compatibility pilots; measured results and their limits are recorded in [external-pilots.md](external-pilots.md). These pilots are not a completed matched effectiveness benchmark.

**Candidate research contribution**

Test authorization across a known permission-lifecycle transition while retaining old credentials, honoring a justified propagation bound, verifying the protected effect and replaying the result. Evaluate generation and verification separately. This is a candidate contribution; this review does not establish that no existing implementation supports it.

| Comparator | Source-supported overlap | Evaluation requirement |
|---|---|---|
| P4 paper-style reimplementation | Functional workflows and vulnerability-event insertion; illustrated scenarios restricted to one penetration-test event | Reconstruct documented behavior, retain its workflow capability and list unavailable implementation details |
| RESTler | Stateful request sequences; NameSpaceRuleChecker checks access using an unauthorized user; UseAfterFreeChecker checks resource access after deletion | Enable applicable checkers, configure multiple credentials and disclose supplied lifecycle information; do not compare only against crash checks |
| EvoMaster security checks | Published access-policy and injection oracles, integrated into an API fuzzer | Verify the selected release implements the relevant checks and can integrate with each target; record native and externally verified results separately |
| Generic sequence scheduler plus our runner/oracle | Same policy knowledge, accounts, execution and verification as the proposed method | Change scheduling only, to isolate lifecycle-generation value |
| AuthREST, related work | Published testing of credential stuffing, brute-force login and token authenticity | Record authentication-testing overlap; do not assume its published scope establishes revocation support or absence |

Sources: [P4 paper, pp. 1181–1183](https://thescipub.com/pdf/jcssp.2024.1176.1184.pdf), [RESTler](https://github.com/microsoft/restler-fuzzer), [RESTler checker documentation](https://github.com/microsoft/restler-fuzzer/blob/main/docs/user-guide/Checkers.md), [EvoMaster security-oracle preprint](https://arxiv.org/html/2604.00702v1), [AuthREST paper](https://arxiv.org/html/2509.10320v1).

RESTler's documented access and deletion checks make “stateful security testing” an insufficient novelty claim. The narrower question is whether our explicit permission-transition/timing model improves verified findings and false-alarm behavior. Source reading supports implementing a limited pilot; it does not clear a publication novelty gate. Review complete relevant implementations and recent literature again before final research claims.

**Benchmark design and fair inputs**

Use a controlled track with reviewed single-defect mutations and correct controls, followed by an independently reported existing-application track. Keep seeded and natural defects separate. Freeze held-out instances before final evaluation; never tune policy bounds to make an application fail.

For input-matched comparisons supply equivalent role accounts, relevant policy/workflow information, fixture/reset privileges and target versions wherever supported. Record unsupported inputs. Native tool comparison and common-oracle comparison answer different questions; report them separately. Public target behavior is the default observation channel. Any privileged readback or reset is disclosed and supplied consistently in the applicable track.

The example configuration starts with a 500-request/600-second cap. These are development defaults, not a frozen final experiment. Calibration occurs on development fixtures; freeze final budgets and repeat counts before held-out runs. Include authentication, controls, probes, confirmation and minimization costs in the appropriate reported totals. Permission-propagation waits count toward elapsed time; report fixture/reset costs separately.

**Metrics required for final evaluation**

| Metric | Definition |
|---|---|
| Confirmed unique defects | Independently reviewed root causes reproduced under the declared confirmation rule; repeated requests/traces are deduplicated |
| Mutation recall | Known seeded defects detected / applicable known seeded defects; does not apply to unknown natural defects |
| False-alarm rate | Correct benchmark cases incorrectly reported as violations / evaluated correct cases; state the counting unit |
| Discovery cost | Requests and elapsed time to first confirmed defect; report runs with no finding as censored |
| Workflow effectiveness | Valid completed sequences / attempted sequences, with explicit setup-failure counts |
| Replay reliability | Reproducing clean attempts / total clean attempts for each candidate |
| Adaptation cost | Annotation and adapter effort plus any privileged target access |

Store inconclusive outcomes and execution failures rather than folding them into correct denials. Preserve raw per-run evidence and random seeds. Treat independent targets/defects and runs as analysis units; thousands of requests against one defect do not supply thousands of independent observations.

**Decision after the pilot**

Proceed to broader experiments if the tool distinguishes a stale permission defect from legitimate delayed revocation and there is a measurable capability or efficiency question beyond existing approaches. If current competitors already handle the same semantics equally well, narrow the contribution to demonstrated oracle accuracy, scheduling cost or a reproducible benchmark. Do not invent an improvement percentage or describe a synthetic lab defect as a newly discovered vulnerability.
