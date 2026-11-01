**Step 2: document-sharing laboratory**

This is the application we test. It has no dependency on the tester's configuration, runner or oracle. Modes share endpoints, fixture accounts and a five-second lifecycle enforcement bound. Steps 2–4 established the three read fixtures below; Step 5 adds role/ownership scopes, writes and the write_side_effect mode. See the [runner instructions](runner.md) and [generation/minimization guide](generation-minimization.md).

| LAB_MODE | Implementation | Expected behavior after the five-second bound |
|---|---|---|
| immediate | Every read checks current sharing state; revocation is effective immediately | Old and fresh Bob sessions denied |
| delayed | Reads honor a revoked share until its recorded revocation time plus the configured delay | Old and fresh Bob sessions denied |
| stale_session | A session retains the active-share snapshot captured when it logged in | Old Bob session incorrectly allowed; fresh Bob session denied |
| write_side_effect | Unauthorized writes commit before returning 403; read enforcement stays correct | Readback exposes the forbidden mutation, despite denial status |

Alice retains legitimate owner access in the version-one workflow. For version-two role/ownership controls she also has explicit administrative audit access; Bob and Charlie initially have viewer roles. Charlie remains unrelated to an unshared resource. In stale_session mode Bob logs in after access is established to capture the relevant share/role/ownership snapshot. The role-managed resource class requires editor access; viewers cannot read/write its protected content. Sharing defaults to read-only unless write permission is explicitly granted.

**Start locally**

From the repository root, install the optional lab dependencies and start one instance:

```bash
python -m pip install -e '.[dev,lab,web,monitoring]'
LAB_MODE=immediate PYTHONPATH=targets python -m uvicorn document_lab.app:create_app --factory --host 127.0.0.1 --port 8001 --workers 1
```

Change LAB_MODE to delayed, stale_session or write_side_effect before starting to select another mode. Press Ctrl+C in the target terminal and wait for shutdown before restarting on the same port. The settings are fixed for the lifetime of the process. There is no mode-switch endpoint.

The disposable target is deliberately defective in stale_session mode. The provided command binds it to loopback. Its database is in memory, separate from tester storage, and is recreated on restart. Use one worker: different workers would have independent databases and sessions. No server is left running by the test suite.

Open http://127.0.0.1:8001/docs for manual API exploration or /openapi.json for the schema. This is the target's API explorer, separate from the testing-tool website started with `temporal-auth serve`. /health returns a simple status without credentials.

**Fixture credentials and configuration**

| Variable | Demo default | Purpose |
|---|---|---|
| LAB_MODE | immediate | Enforcement implementation |
| LAB_REVOCATION_DELAY_SECONDS | 5.0 | Actual delayed-mode interval; must be finite and between zero and five |
| LAB_ALICE_PASSWORD | alice-demo-password | Owner fixture password |
| LAB_BOB_PASSWORD | bob-demo-password | Recipient fixture password |
| LAB_CHARLIE_PASSWORD | charlie-demo-password | Unrelated-user fixture password |
| LAB_RESET_KEY | local-lab-reset-key | Key for the fixture reset operation |

Usernames are alice, bob and charlie. Their IDs are generated at startup/reset; obtain an ID from that user's login response. Passwords use salted scrypt hashes in the target database. Bearer tokens are opaque random session identifiers; only token hashes are stored. Sessions have no expiry in this fixture and are invalidated by reset/restart. This simplifies the authorization experiment; it is not a production authentication design.

LAB_REVOCATION_DELAY_SECONDS does not alter the declared five-second policy. It can shorten the correct delayed implementation for development. Values above five are rejected so a supposedly correct fixture cannot accidentally violate its bound. Immediate and stale-session behavior do not use that delay setting.

**Manual workflow and payloads**

1. POST /auth/login with `{"username":"alice","password":"alice-demo-password"}`. Save access_token as Alice's bearer token.
2. Log in as Bob to obtain his user_id. POST /documents as Alice with `{"content":"unique-protected-marker"}`; save the returned id.
3. POST /documents/{document_id}/shares as Alice with `{"subject_id":"BOB_USER_ID"}`.
4. Log in as Bob again and preserve this token as the old session. GET /documents/{document_id} as Bob must return the protected marker.
5. DELETE /documents/{document_id}/shares/{subject_id} as Alice. The response acknowledges revocation and states max_delay_seconds = 5.
6. Acquire a fresh Bob token, retain both sessions separately, and wait more than five seconds after receiving acknowledgement.
7. Read the same document using the old Bob token, fresh Bob token and Alice token. Verify returned protected content rather than status alone.

Authenticated calls use `Authorization: Bearer ACCESS_TOKEN`. Login returns access_token, token_type, user_id and username. Document responses contain id, owner_id and content. Missing/invalid authentication returns 401; an authenticated user without read permission receives 403 without protected content; an unknown document returns 404. Only the owner can grant or revoke sharing. Granting again restores access. Repeating a revoke without a new grant does not restart its deadline.

Delayed mode records a monotonic time before acknowledging the revoke and calculates permission on each read. It does not depend on a background sleep/task. Its enforcement deadline therefore occurs no later than the client-observed acknowledgement plus five seconds. The response timing does not expose a portable exact server timestamp; the runner uses its own acknowledgement and probe timestamps.

**Reset and isolation**

POST /testing/reset with `X-Lab-Reset-Key: local-lab-reset-key` resets the fixture. Override the key with LAB_RESET_KEY if desired. Ordinary bearer authorization does not authorize reset. A successful reset removes every session, document and share and generates new user IDs; subsequent login is required. This endpoint is excluded from OpenAPI because it is privileged experiment setup, not a discovered public API operation. It must be disclosed separately in future comparisons.

Each app instance owns one SQLite connection, guarded so individual operations and reset execute atomically. Separate instances cannot read each other's sessions or documents. Response caching is disabled with Cache-Control: no-store, including protected reads and login responses.

**Independent verification**

```bash
python -m pytest -q
python -m pytest -q tests/test_document_lab.py
python -m pytest -q tests/test_document_lab_http.py
```

The last command starts three temporary loopback servers, performs the grant/read/revoke flow through HTTPX over real TCP, waits beyond each acknowledgement's five-second bound, and checks both Bob sessions plus Alice's control. It then shuts down all servers. Controlled-clock API tests independently exercise the exact delay boundary, repeated revoke, regrant, unrelated users, owner-only administration, reset and state isolation. Tests require local socket communication, including the FastAPI TestClient's socket pairs.

At Step 2 the suite passed 94 tests. By Step 5, collection, oracle, replay, generation and reduction checks brought the suite to 237 tests. Later milestones add web, monitoring and evaluation checks; see [implementation status](implementation-status.md) for current counts. Fixture verification establishes benchmark ground truth, and real HTTP tests confirm the intentionally seeded read/write defects. This is not discovery of a previously unknown real-world vulnerability or evidence of improvement over other research tools.

References used for framework integration: [FastAPI lifespan documentation](https://fastapi.tiangolo.com/advanced/events/) and [FastAPI security documentation](https://fastapi.tiangolo.com/tutorial/security/first-steps/). The explicit bearer-session dependency validates sessions in the lab store; no OAuth authorization server is implemented.
