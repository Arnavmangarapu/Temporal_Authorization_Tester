**Step 9C: reproduce Dolibarr's known currency-permission defect**

This checkpoint tests the previously reported [Dolibarr #26066](https://github.com/Dolibarr/dolibarr/issues/26066) and its [upstream fix](https://github.com/Dolibarr/dolibarr/commit/62ad3d12d2ee86f2f665f341565860f3e88b076a). It is a scripted, known-endpoint static authorization reproduction. It does not demonstrate automatic vulnerability discovery, permission-change timing, a new vulnerability, held-out generalization or superiority over another tool.

**Application pair and fixture**

The buggy revision is `c16313007a90010524cafba67acadcce036b6a9f`; the fixed revision is `62ad3d12d2ee86f2f665f341565860f3e88b076a`. The former is the latter's direct first parent. Complete checksum-verified archives differ in exactly one file, `htdocs/multicurrency/class/api_multicurrencies.class.php`. The fixed container uses that exact upstream file on the otherwise identical application tree. No local authorization patch is applied. The fix also adds the missing pagination argument, so this is a comparison of upstream revisions rather than a claim that only one line changed.

Both snapshots declare **19.0.0-dev**. The original issue reports release 18.0.1; this reproduction uses the benchmark's exact development-branch commit pair, not an asserted binary-identical reproduction of the reporter's installation. Both run on the same pinned PHP 8.2/Apache base and MariaDB 10.11 image digests. These are controlled reproduction environments rather than the reporter's complete original deployment. Source and runtime pins are in [source.lock.json](../integrations/dolibarr/source.lock.json).

Each invocation starts an owned database and application on a new dedicated Docker bridge network. Only an ephemeral application port is published, bound to 127.0.0.1. The database has no published port and stores its data in a disposable tmpfs. A native installer creates the schema/data. A CLI-only fixture script activates modules, creates users through native classes, sets installation metadata and creates an XTS currency with a synthetic protected marker. Application authorization handlers remain upstream.

| Actor | Administrator | Product/category read | Currency read | Purpose |
|---|---|---|---|---|
| owner | Yes | Enabled | Enabled | Setup and independent positive control |
| allowed | No | Enabled | Enabled | Ordinary-user positive control |
| restricted | No | Enabled | Removed | Negative authorization probe |

The currency module grants read by default. The fixture explicitly clears each user's default grants before adding the listed rights. The HTTP user endpoint is queried with `includepermissions=1` to verify identities, administrator status and effective currency permissions; the oracle also checks the bootstrap's permission snapshot. Each pair uses identical role names, code and marker data, with separate fresh databases and generated credentials. This is not a retained/fresh-login temporal experiment.

**Workflow and oracle**

Each run makes eleven bounded HTTP requests: three identity/permission checks; anonymous and invalid-key controls; owner and ordinary allowed-user list reads; the restricted user's by-code read; the restricted user's list read; then owner and allowed-user list reads again. The by-code endpoint already checks permissions in both revisions. The known defect concerns the list endpoint.

A disclosure requires the exact currency ID, XTS code and marker name in the restricted list response, with valid identities, denied currency permission and successful surrounding positive controls. A 200 response alone is insufficient. Denial requires 401/403 with no protected marker and valid positive controls. Wrong records, missing/duplicate/reordered observations, writes in the read-only trace, truncated responses, network failures or broken controls yield inconclusive evidence. Offline analysis recalculates this oracle from raw requests rather than trusting saved summary labels.

The collector now removes content-encoding and compressed-length headers after decoding HTTP response bytes, preventing a second decompression when constructing its recorded response. A gzip regression covers this correction. It does not modify the target's returned status or application payload. Earlier frozen campaigns retain their original collector snapshots and results.

**Build, run and stop — Linux / Windows WSL**

Use the README's Linux environment, or its Windows/WSL instructions, with Docker Engine available to that environment. Native Windows PowerShell execution of these Docker/research helpers has not been tested. Install the project's development/lab extras; Java and the native fuzzers are unnecessary for this checkpoint. No website, monitoring service or pre-existing database needs to run.

```bash
source .venv/bin/activate
python scripts/build_dolibarr_reproduction.py
python -m temporal_auth.evaluation.dolibarr_reproduction freeze benchmarks/dolibarr-local.json
python -m temporal_auth.evaluation.dolibarr_reproduction run benchmarks/dolibarr-local.json --output artifacts/dolibarr-local
python -m temporal_auth.evaluation.dolibarr_reproduction analyze benchmarks/dolibarr-local.json --output artifacts/dolibarr-local
```

The builder downloads two approximately 70 MB source archives plus the pinned container bases, verifies archive and handler hashes, checks that only the declared file differs, and records local image IDs. Source caches/images are retained for future runs. Generated credentials and bootstrap databases are excluded from exported evidence. Fixture templates are repository files and require a source checkout; this experiment is not exposed as a dashboard target or installed-wheel-only workflow.

The freeze records source/tests, fixture templates, builder/auditor, archive/runtime pins, actual built image IDs, environment, three pair IDs, shuffled order and a 100-HTTP-request/300-second ceiling per invocation. Database readiness and installer/bootstrap CLI work are additional non-HTTP costs, recorded separately. Deadlines are cooperative; bounded cleanup can finish after the execution ceiling. An existing protocol is never overwritten. A different build environment, image ID or source revision requires a new local protocol; do not edit a published freeze to match your machine.

Press **Ctrl+C in the running terminal** to stop. Owned containers and their network are removed and the database disappears with the container. Completed rows and failed/inconclusive results are retained. Repeat the same run command to resume unrecorded keys after integrity checks; completed failures are not silently replaced by successful retries. Interrupted directories remain as uncounted evidence. Do not run two collectors into the same output directory.

The source archive caches and built images remain after stopping; they are not active services. The optional web interface has its separate README start/stop commands.

**Offline review**

With the raw campaign and its frozen source available locally:

```bash
python scripts/audit_dolibarr_reproduction.py --source /path/to/frozen/source --campaign /path/to/dolibarr-26066-v1
```

This checks frozen source/template hashes, protocol/row/file integrity, recalculated static oracles and exact regenerated analysis. It starts no container or target. Install the source's documented Python dependencies; Docker/PHP and the downloaded application archives are unnecessary for offline audit. Integrity hashes are not digital signatures.

Earlier data remains separate: Step 9A uses commit `cb719ac0ae105f6a9add5ef89c5353a54db04a38`, and Step 9B uses `e91e4aad3b1c498d81e30231f483c2b92c7cd033` or their respective archived sources. The current collector/source fingerprint must not replace their saved fingerprints or observations.

**Measured results**

The [frozen protocol](../benchmarks/dolibarr-26066-v1.json) has SHA-256 `0c0ad09404ccbc55f3e66c6531077035813da977f6ce645aa890156488fa654b` and fingerprints 78 source/test/template/helper files. All six invocations completed, and the exact record/identity/permission/control oracle produced the expected result in all three pairs.

| Pair | Buggy restricted-user result | Fixed restricted-user result | Owner and ordinary authorized-user controls |
|---|---|---|---|
| 1 | 200; exact protected record disclosed | 401; protected marker absent | Passed before and after |
| 2 | 200; exact protected record disclosed | 401; protected marker absent | Passed before and after |
| 3 | 200; exact protected record disclosed | 401; protected marker absent | Passed before and after |

Anonymous and invalid-key requests were denied in every invocation. The restricted by-code request was denied in both revisions. The fixed list response confirms the screening discrepancy: this upstream fix returns **401**, rather than the replication document's expected 403. A status-only oracle would be inappropriate.

The six invocations used **66 HTTP requests**, eleven each, plus separately recorded installer/readiness commands. The pinned PHP runtime reported **8.2.35**. Median end-to-end durations were approximately 6.65 seconds buggy and 6.70 seconds fixed, including startup and cleanup; these six runs do not support a performance comparison. All twelve campaign containers and six networks were independently checked absent afterward.

The full suite passed **385 tests in 128.58 seconds**. Offline audit verified source/template and raw-file hashes, recomputed all six static oracles and exactly regenerated the aggregate [results JSON](results/step9c-dolibarr.json). See [verification provenance](results/step9c-verification.json). Nine development report directories—including failed setup/collection and inconclusive installer redirects—remain separate from this frozen campaign. They were not replaced or included in its denominator; additional low-level diagnostics were also used before freezing.

This adds one independently reported static bug/fix pair to the artifact's evidence. There is still no demonstrated natural temporal bypass, native competitor effectiveness comparison, blind held-out result or cleared publication novelty claim.
