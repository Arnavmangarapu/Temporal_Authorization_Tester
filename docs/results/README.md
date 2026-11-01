**Verification summaries and provenance**

These JSON manifests record local implementation milestones:

| File | Verification scope |
|---|---|
| [step6-pilot.json](step6-pilot.json) | Native Gitea/PocketBase pilots and actual EvoMaster/RESTler compatibility runs |
| [step7-ui.json](step7-ui.json) | Local website, worker, browser flows, replay and package verification |
| [step8-monitoring.json](step8-monitoring.json) | Optional worker exporter, real monitoring stack, evidence reconciliation and a small overhead pilot |

They are historical summaries, not raw datasets or final effectiveness results. Seeded lab defects, existing-application non-findings and native-tool diagnostics have different meanings and remain separate in the guides. No confirmed natural revocation bypass or comparative improvement is established by these milestones.

Paths under artifacts/, /tmp/ or a particular machine's home directory identify where verification outputs originally existed. Raw requests, screenshots, downloaded binaries, transient databases, wheel files and the local evidence-hash indexes are deliberately excluded from this source repository. A fresh clone does not contain those referenced artifacts. The manifests record the original local outputs; they do not guarantee their ongoing availability or independently authenticate the reported results.

Source and artifact hashes describe the corresponding milestone snapshot. Later documentation or implementation changes can legitimately differ from those hashes. Preserve a new run's own reports and source revision when collecting new evidence; do not update old manifests to make historical measurements appear to describe a different snapshot.

To generate new records, follow the [native pilot guide](../external-pilots.md), [web interface guide](../web-interface.md) and [monitoring guide](../monitoring.md). For quick regression validation, install the README's development/lab/web/monitoring extras and run `python -m pytest -q`. Browser and external-tool pilots have additional documented dependencies. Use new workspace/output directories when a script requires empty history.

Current implementation scope and milestone test counts are tracked in [implementation status](../implementation-status.md). Final matched budgets, held-out experiments and research claims remain the Step 9 evaluation described in [research comparisons](../research-comparisons.md).
