**Step 1 policy contract — schema version 1**

This document retains the version-one sharing-read contract. Steps 1–4 implement its collection/evaluation/confirmation. Step 5 adds a separate version-two schema for annotated role/ownership/sharing lifecycles, protected writes and reduction; see the [generation/minimization guide](generation-minimization.md). Version-one configuration fingerprints remain unchanged.

**Supported experiment**

The initial lifecycle is sharing_revocation, using a bearer token obtained through a POST login operation. The owner creates and shares a resource with the subject. The subject authenticates after receiving access and retains that session. The owner revokes sharing. The tool later probes the same resource with that saved session and, where supported, a newly acquired subject session. An independently authorized control checks that the resource is still available.

Actor references must exist and identify different usernames. The subject must differ from the owner and control; the owner may also be the control. Configuration does not prove the control is authorized: the runner establishes that through a successful protected read, and the oracle checks both pre- and post-transition controls. A failed setup or control cannot be treated as successful denial of unauthorized access.

All operation references must exist. The configuration schema allows POST login, GET reads, and non-GET create/grant/revoke operations. Step 3's document_lab_v1 adapter further requires POST create/grant and DELETE revoke, with the documented resource/subject path placeholders. It supplies explicit lab payloads and binds returned user_id, owner_id and document id fields. This is an annotated lab workflow, not general payload inference from OpenAPI. base_url is an HTTP(S) origin. Operation paths carry any API prefix and must not contain another origin, query or fragment.

**Timing semantics**

| Timing mode | Required inputs | Meaning |
|---|---|---|
| bounded | max_delay_seconds, source; acknowledgement anchor | Permission enforcement must complete within the stated delay after successful transition acknowledgement |
| unknown | reason | The necessary temporal policy is unavailable; temporal violation checks are inconclusive |

Bounded timing explicitly requires a finite, non-negative delay and a non-empty source identifying the lab contract or actual application policy. Zero means immediate enforcement. Missing policy never defaults to zero. Version 1 accepts only transition_acknowledged as the timing anchor. Commit-relative and other unobservable anchors must not be silently reinterpreted.

The example's five-second bound is a specification for our controlled lab, not an assertion about another application. An adapter for an existing application must supply that application's justified semantics or declare timing unknown. The oracle rejects a trace whose revocation acknowledgement advertises a larger delay than the configured policy permits.

The runner records monotonic elapsed time when the successful transition response finishes. It starts a fresh probe no earlier than that timestamp plus max_delay_seconds plus tolerance_seconds, recording the actual probe timing and enforcing the remaining budget. The default 0.05-second tolerance is an experimental boundary margin, not an extra application-policy allowance or a measured platform guarantee. A request begun before the deadline cannot establish a post-deadline failure merely because its response arrives afterward.

Requests may begin only while budget remains. Timeout, polling interval and runtime must be finite and positive; request count must be a positive integer. Configuration rejects a runtime that cannot reach the stated policy deadline plus tolerance. This is a necessary feasibility check, not a guarantee that setup and verification will fit. The runner counts all attempted testing requests and marks exhausted runs budget_exhausted with verdict not_evaluated. It uses async deadlines for the workflow and individual requests; local file writing and client teardown are not forcibly preempted. See the [runner instructions](runner.md).

**Evidence and verdicts**

| Observation | Intended classification |
|---|---|
| Protected marker returned after a valid deadline, with healthy controls | Violation candidate |
| Candidate reproduced in two independent clean replays | Confirmed finding |
| Valid post-deadline checks return no protected content | No violation observed for those checks |
| Unknown timing, unverified transition, or failed control | Inconclusive or invalid setup |
| Network failure, malformed response or target outage | Execution error or inconclusive |

An HTTP status alone does not determine disclosure. The protected_field uses JSON Pointer syntax and identifies content whose release actually violates policy. The lab runner puts a per-run random marker in /content. After establishing its protected status, the oracle checks for that unique marker in post-transition JSON values/keys or response text, including error responses. A public metadata response without that marker does not establish protected-data access. Version-two write checks establish unauthorized state changes through independent readback, including when an attempted write returns an error.

Two matching clean replays are the implemented confirmation rule. The explicit check command resets the dedicated lab before discovery and each replay, requires a reset key, reacquires credentials and binds new resources. Resets and all attempts share one request/runtime budget. Inconsistent candidates and reproduction counts remain recorded; the conservative rule may miss intermittent defects. A no-violation result applies only to the executed observations. It is not proof of global correctness. See [oracle/replay details](oracle-replay.md).

**Laboratory API, implemented in Step 2**

| Operation | Planned contract |
|---|---|
| POST /auth/login | Accept username/password JSON; return access_token and user identity |
| POST /documents | Owner creates a document with protected content; return a fresh document ID |
| POST /documents/{document_id}/shares | Owner grants read access to a subject ID |
| DELETE /documents/{document_id}/shares/{subject_id} | Owner revokes access and receives acknowledgement |
| GET /documents/{document_id} | Return protected content only to permitted actors |

Target data resides in a dedicated, per-application in-memory SQLite database. POST /testing/reset requires X-Lab-Reset-Key and clears documents, shares and sessions, then reseeds fixture accounts with new user IDs. This is a controlled fixture operation, excluded from the published OpenAPI schema and recorded separately from public application operations. See the [lab instructions](document-lab.md).

Implemented lab variants: immediate correct enforcement; correct enforcement delayed within the five-second bound; and a stale-session defect that retains the subject's access beyond that bound. In the defect variant, an old session retains a permission snapshot while a fresh login reflects revocation. Independent target tests establish this behavior, including a real HTTP check after the five-second bound. This verifies the fixture; comparative tester effectiveness requires the separate final evaluation.

**Configuration loading**

The loader uses a safe YAML loader and rejects duplicate mapping keys, including nested keys. Unknown fields are rejected so misspelled policy settings cannot silently take defaults. Passwords are represented by environment-variable names; literal password fields are unsupported. User-supplied field values and YAML source lines are omitted from handled error messages. Validation does not read those environment variables or contact the configured origin.
