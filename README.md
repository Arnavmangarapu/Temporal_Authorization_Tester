**Temporal Authorization Tester**

A research project for testing authorization after permissions change. The first scenario is document-sharing revocation: preserve a recipient's session, revoke sharing, and check whether protected content remains accessible beyond the application's declared propagation bound.

**Current implementation: Steps 1–8 complete; Step 9A artifact evaluation complete, broader research gates open.**

Implemented: validated configuration, the controlled lab, seeded dependency-aware generation, bounded HTTP collection, read/write verification, clean confirmation and bounded minimization. A local website supports configuration, persistent jobs, live evidence, cancellation and replay downloads. Version two supports sharing, role and ownership changes with read/write probes. Native Gitea/PocketBase adapters and real EvoMaster/RESTler compatibility runs are available. Optional Prometheus/Grafana monitoring now follows worker evidence. Final comparative evaluation remains future work; no comparative improvement or natural revocation bypass is claimed.

See the [generation/minimization guide](docs/generation-minimization.md), [oracle/replay instructions](docs/oracle-replay.md), [runner instructions](docs/runner.md), [lab instructions](docs/document-lab.md), [implementation plan](p4_implementation_plan.md), [policy contract](docs/policy-contract.md), [comparison specification](docs/research-comparisons.md) and [step status](docs/implementation-status.md).

**Base paper and research scope**

Shilpa R. G., Pushphavathi T. P. and Murthy P. V. R. (2024), *Design and Development of an Automatic Penetration Test Generation Methodology for Security of Web Applications*, Journal of Computer Science 20(10), 1176–1184. [DOI](https://doi.org/10.3844/jcssp.2024.1176.1184) · [Original PDF](https://thescipub.com/pdf/jcssp.2024.1176.1184.pdf).

The paper already derives functional sequences from models; its illustrated method inserts one penetration-test event per scenario. This project investigates annotated permission changes, justified timing bounds, retained/fresh sessions, protected-effect checks and clean replay. It is a research extension, not an exact reproduction of unavailable original code. Stateful testing alone is not a novelty claim. See [research comparisons](docs/research-comparisons.md) and the [frozen artifact-evaluation guide](docs/evaluation.md) for what is measured and what remains unproven.

The first frozen artifact campaign recorded **1,039 checks across six tracks**. All scheduling ablations detected the same planted defects; no scheduling advantage was demonstrated. These known configurations represent only two root-cause families, and existing-application profiles yielded no observed bypass. See the [results and limitations](docs/evaluation-results.md). Held-out generalization, matched modern-tool effectiveness and publication novelty remain open.

**Run and stop on Linux**

Requirements: Git and Python 3.11 or newer with venv/pip support. Docker Engine and the Compose plugin are needed for optional Prometheus/Grafana and the separate RESTler compatibility runner. The application and full regression suite were tested on Linux with Python 3.14.8; other Python versions and Windows/WSL have not been exercised here.

1. Open a Bash terminal. For a new checkout:

   ```bash
   mkdir -p ~/projects
   cd ~/projects
   git clone https://github.com/Arnavmangarapu/Temporal_Authorization_Tester.git
   cd Temporal_Authorization_Tester
   python3 --version
   ```

   If you already have a checkout, open that directory instead of cloning again. The remaining examples assume `~/projects/Temporal_Authorization_Tester`; substitute your path if different.

2. Install dependencies once:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   python -m pip install -e '.[dev,lab,web,monitoring]'
   ```

3. Start the website, worker and local metrics endpoint in **Terminal 1**:

   ```bash
   python -m temporal_auth serve --metrics-port 9464
   ```

   Leave this terminal running. Open [the website](http://127.0.0.1:8080). Choose **New experiment → Disposable document lab**; the worker starts and stops an isolated lab automatically. No separate target server or credentials are needed for this demonstration.

4. Optional: start monitoring in **Terminal 2**, from the same project directory:

   ```bash
   cd ~/projects/Temporal_Authorization_Tester
   docker info
   docker compose version
   docker compose --profile monitoring up -d --build
   ```

   Docker must already be installed and its daemon running. The first build downloads the pinned upstream images. Open [Grafana](http://127.0.0.1:3000/d/temporal-auth-worker) or [Prometheus](http://127.0.0.1:19090). Grafana has local viewer access without login. Allow a few five-second scrapes for charts to populate.

5. **Stop the application:** press **Ctrl+C in Terminal 1**, then wait for worker/target cleanup and the shell prompt. Closing the browser tab does not stop the worker.

6. **Stop monitoring:** in Terminal 2, from the project directory, run:

   ```bash
   docker compose --profile monitoring down
   ```

   This stops this project's monitoring containers and retains their data volumes. Experiment history and evidence remain in `artifacts/workspace`; ordinary shutdown does not delete them. If you also started a standalone lab using the CLI instructions below, press Ctrl+C in that lab's terminal too.

7. To start again later, activate the existing environment and run the server:

   ```bash
   cd ~/projects/Temporal_Authorization_Tester
   source .venv/bin/activate
   python -m temporal_auth serve --metrics-port 9464
   ```

   Repeat step 4 if you want Grafana again. You can omit `--metrics-port 9464` for a website/worker with monitoring disabled. Run `deactivate` after stopping the server if you want to leave the virtual environment.

**Run and stop on Windows through WSL 2**

Use WSL 2 for this version. The worker imports `fcntl` and uses POSIX signals/process groups, so running the full website worker with native Windows Python in PowerShell/CMD is not supported. The following Windows setup is documented from the current implementation and official platform instructions; it has not been tested on a Windows machine here.

1. If WSL is not installed, open **PowerShell as Administrator** and run:

   ```powershell
   wsl --install -d Ubuntu
   ```

   Restart Windows if requested, open Ubuntu, and finish creating its Linux username/password. Follow [Microsoft's WSL installation guide](https://learn.microsoft.com/en-us/windows/wsl/install) if WSL is already installed or the command needs troubleshooting. In PowerShell, check the distribution version:

   ```powershell
   wsl --list --verbose
   ```

   Ubuntu should show version **2**. If it shows version 1, convert it using `wsl --set-version Ubuntu 2`.

2. Open an **Ubuntu/WSL terminal**. All remaining Bash commands in this section run there, not in PowerShell. Install Python tooling if needed:

   ```bash
   sudo apt update
   sudo apt install git python3 python3-venv python3-pip
   python3 --version
   ```

   Confirm Python is at least 3.11, then get a new checkout inside WSL:

   ```bash
   mkdir -p ~/projects
   cd ~/projects
   git clone https://github.com/Arnavmangarapu/Temporal_Authorization_Tester.git
   cd Temporal_Authorization_Tester
   ```

   If already cloned, open that directory instead. These instructions keep the project in the [WSL Linux filesystem](https://learn.microsoft.com/en-us/windows/wsl/filesystems), which Microsoft recommends for Linux workloads. A pre-existing Windows checkout such as `D:\projects\Temporal_Authorization_Tester` is normally available as `/mnt/d/projects/Temporal_Authorization_Tester`; substitute that path consistently if using it.

3. Create a WSL-specific environment in your Linux home directory, then install the project from its root:

   ```bash
   python3 -m venv ~/.venvs/temporal-auth-wsl
   source ~/.venvs/temporal-auth-wsl/bin/activate
   python -m pip install -e '.[dev,lab,web,monitoring]'
   ```

   Keep this environment separate from virtual environments made by native Windows Python or another Linux installation.

4. In **WSL Terminal 1**, start the application:

   ```bash
   python -m temporal_auth serve --metrics-port 9464
   ```

   Leave it running and open [http://localhost:8080](http://localhost:8080) in your Windows browser. The disposable lab starts automatically when you submit an experiment.

5. Optional monitoring: use a Docker daemon that can reach the WSL worker's loopback endpoint. With Docker Desktop, use Linux containers, enable the **WSL 2 engine** and **Resources → WSL Integration → Ubuntu**, and enable **Resources → Network → Enable host networking**. Docker documents host networking for Desktop 4.34 and newer. See the official [WSL integration](https://docs.docker.com/desktop/features/wsl/) and [host networking](https://docs.docker.com/engine/network/drivers/host/) instructions.

   In **WSL Terminal 2**, run:

   ```bash
   cd ~/projects/Temporal_Authorization_Tester
   docker info
   docker compose version
   docker compose --profile monitoring up -d --build
   ```

   Open [Grafana](http://localhost:3000/d/temporal-auth-worker) and [Prometheus targets](http://localhost:19090/targets). Verify `temporal-auth-worker` is **UP**. The Compose configuration uses host networking and expects the exporter at `127.0.0.1:9464`; Docker Desktop/WSL loopback interoperability is unverified for this project. If that target is DOWN even though [worker metrics](http://localhost:9464/metrics) load, use Docker Engine in the same WSL distribution/network namespace as the worker, or use the verified native-Linux setup. Follow the [Docker Engine installation guide](https://docs.docker.com/engine/install/ubuntu/) when choosing the in-WSL daemon route; do not run competing Desktop and in-WSL engines for the same setup.

6. **Stop the application:** press **Ctrl+C in WSL Terminal 1** and wait for cleanup.

7. **Stop monitoring:** in WSL Terminal 2, from the project root, run:

   ```bash
   docker compose --profile monitoring down
   ```

   Your job history/evidence and monitoring volumes are retained. Stop the application and containers normally before shutting down WSL.

8. To start again later, open Ubuntu/WSL and run:

   ```bash
   cd ~/projects/Temporal_Authorization_Tester
   source ~/.venvs/temporal-auth-wsl/bin/activate
   python -m temporal_auth serve --metrics-port 9464
   ```

   Start Docker Desktop first if you use it, then repeat step 5 when you want monitoring. Use `deactivate` after stopping the server to leave the environment.

**Test the running application — Linux or Windows/WSL**

In the website, select **New experiment**, set the target to **Disposable document lab**, leave the request/time budgets at 500/600, click **Validate configuration**, then **Start experiment**. Use a separate experiment for each row:

| Lab behavior | Permission change | Protected action | Expected verdict |
|---|---|---|---|
| Stale session defect | Sharing revocation | Read protected content | Confirmed violation after two clean reproductions |
| Correct immediate enforcement | Sharing revocation | Read protected content | No violation observed |
| Correct bounded delay | Sharing revocation | Read protected content | No violation observed after the legitimate grace period |
| Unauthorized write side effect | Role downgrade | Write protected content | Confirmed violation, including a committed write despite HTTP 403 |

The lab defects are deliberately seeded. Correct checks typically need one five-second wait; confirmation needs discovery plus two independent replays, so allow roughly 15–30 seconds or more with startup. Use **Review evidence**, **Download evidence bundle** or **Replay with fresh state** from a completed run. Monitoring updates approximately every five seconds when enabled.

To run automated tests, open another Linux/WSL terminal in the project root and activate the environment created for that platform. Run:

```bash
python -m pytest -q
```

The latest Linux regression passed **348 tests in about two minutes**, including 20 evaluation-harness tests. Focused checks are:

```bash
python -m pytest -q tests/test_web.py
python -m pytest -q tests/test_monitoring.py
```

The tests manage their own temporary workers/targets; a manually started website or Docker monitoring stack is not required. Windows/WSL test outcomes have not been verified here.

**Standalone CLI and target development**

The commands below run in Linux Bash or inside WSL with the environment activated. They describe the manually managed lab/CLI route; the website's disposable-lab flow already manages its own target.

If the listed dependencies are already installed, the source tree can be exercised without an editable installation:

```bash
PYTHONPATH=src python -m temporal_auth validate examples/document-lab.yaml
PYTHONPATH=src python -m temporal_auth schema
python -m pytest -q
```

Expected validation output:

```text
Valid configuration: document-sharing-lab
Revocation bound: 5s after acknowledgement; probe tolerance: 0.05s.
Configuration validation only; no application was contacted or tested.
```

The example's localhost URL matches the lab command below. Password environment variables do not need to exist for configuration validation. The run command obtains credentials through the named references. The lab itself has documented demo fixture passwords, overridable through those variables.

The validate command exits with code 0 for a valid configuration and code 2 for an unreadable or invalid one. An explicitly unknown timing policy is valid configuration, but the command states that temporal checks must be inconclusive. A valid configuration is not evidence that a target exists, that credentials work, or that an application is secure.

**Run the target application**

```bash
LAB_MODE=immediate PYTHONPATH=targets python -m uvicorn document_lab.app:create_app --factory --host 127.0.0.1 --port 8001 --workers 1
```

Choose immediate, delayed, stale_session or write_side_effect through LAB_MODE. Delayed mode permits old privileges within the declared five-second bound; stale_session preserves login-time permissions, and write_side_effect deliberately commits an unauthorized write before returning 403. Keep the demonstrated loopback binding and one worker; each instance has its own disposable SQLite database.

Once started, the target exposes /health, /openapi.json and FastAPI's /docs API explorer. The separate testing-tool website starts with `temporal-auth serve`.

**Execute an experiment**

With the lab running in another terminal, set credentials matching that lab and run:

```bash
export LAB_ALICE_PASSWORD=alice-demo-password
export LAB_BOB_PASSWORD=bob-demo-password
PYTHONPATH=src python -m temporal_auth run examples/document-lab.yaml --output artifacts
```

Each run creates artifacts/{run_id}/run.json and events.jsonl. A completed default workflow attempts 12 requests. Raw collection retains verdict not_evaluated. Evaluate it offline with `temporal-auth analyze CONFIG RUN_DIRECTORY`, or use the clean check below. The runner uses the document-lab API contract; general OpenAPI-driven request generation is not implemented. The run command does not start, reset or shut down the target.

**Evaluate and confirm**

The check command resets all documents, shares and sessions in the dedicated lab before discovery and before each candidate replay. With that lab running and matching actor passwords set:

```bash
export LAB_RESET_KEY=local-lab-reset-key
PYTHONPATH=src python -m temporal_auth check examples/document-lab.yaml --output artifacts
```

Immediate and delayed modes produce no_violation_observed for the tested workflow. The seeded stale_session defect produces a candidate, followed by confirmed_violation only when two clean replays reproduce it. The default confirmed case uses 39 requests: three resets and three 12-request workflows. Its exit code is 3 to signal a confirmed finding. Evidence and confirmation details are stored in check.json and linked attempt directories. Unknown policies, failed controls and insufficient evidence remain inconclusive or unconfirmed.

**Generate, verify writes and reduce traces**

```bash
PYTHONPATH=src python -m temporal_auth plan examples/lifecycle-role-write.yaml --seed 7 > scenario.json
PYTHONPATH=src python -m temporal_auth check examples/lifecycle-role-write.yaml --scenario scenario.json --output artifacts
PYTHONPATH=src python -m temporal_auth minimize examples/lifecycle-role-write.yaml artifacts/check-SOURCE_ID --output artifacts
```

Use a real confirmed check directory for check-SOURCE_ID. check and every minimization trial reset the dedicated lab. Write findings require a matching change observed through the independent control; HTTP status alone is insufficient. The reducer only removes declared optional warmups and preserves required setup, timing and evidence actions. Every accepted reduction is clean-confirmed twice. See the guide for all six example configurations and budget accounting.

Tests require local socket communication. To omit real TCP smoke checks, use `python -m pytest -q -m 'not network'`; FastAPI TestClient checks still use local socket pairs. Verification counts are recorded in the implementation status.

**Project status and additional guides**

Start the interface with `temporal-auth serve`, or `PYTHONPATH=src python -m temporal_auth serve`, then open [the local workspace](http://127.0.0.1:8080). The default disposable lab needs no credentials. See the [web interface guide](docs/web-interface.md) and [native pilot guide](docs/external-pilots.md).

For optional monitoring, launch `temporal-auth serve --metrics-port 9464`, then `docker compose --profile monitoring up -d --build`. Open [Grafana](http://127.0.0.1:3000/d/temporal-auth-worker). See the [monitoring guide](docs/monitoring.md) for metrics, local setup, coverage and stopping services.

Steps 1–8 are implemented. Step 9 now includes a frozen artifact-evaluation harness; the broader held-out study and publication-readiness gates remain open. This repository does not establish superiority over the base paper or modern testing tools. See the [evaluation guide](docs/evaluation.md).


**Repository contents and experiment artifacts**

| Location | Contents |
|---|---|
| `src/temporal_auth/` | CLI, policies, generators, runner, oracles, replay, web worker and optional exporter |
| `targets/document_lab/` | Independent controlled application with correct and deliberately defective modes |
| `examples/` | Validated sharing, role and ownership configurations for read/write checks |
| `tests/` | Configuration, target, runner, oracle, replay, web and monitoring tests |
| `monitoring/` and `compose.yaml` | Pinned monitoring image definitions and Grafana provisioning |
| `integrations/tools.lock.json` and `scripts/` | Checksummed external-tool downloads, compatibility pilots and verification scripts |
| `docs/` | Usage guides, research scope, implementation status and milestone verification summaries |

The basic disposable-lab website and pytest suite need no downloaded external applications. To use the Gitea/PocketBase pilots, install Git and run `python scripts/fetch_pilot_tools.py` from the project root. That helper downloads the pinned **Linux x86_64** application binaries and EvoMaster jar; Java is needed when running EvoMaster. RESTler has a separate Docker build. See the [native pilot guide](docs/external-pilots.md) before running these integrations. Other CPU architectures need compatible adapters/binaries and have not been verified.

Virtual environments, credentials, local workspace metadata, downloaded tools, generated databases, build outputs and raw run artifacts are excluded from version control. `artifacts/` is created locally as you run experiments. The JSON files under [docs/results](docs/results/README.md) are historical verification summaries: local paths identify the original verification machine, and recorded source hashes describe that milestone's snapshot rather than every later documentation revision. Raw evidence, screenshots and wheel files referenced there are not bundled with a fresh clone; the guides explain how to generate new evidence.

The [original implementation plan](p4_implementation_plan.md) and [research-extension notes](cyber_research_architectures_2026-11-01.md) are dated planning documents. Use [implementation status](docs/implementation-status.md) for current capabilities and [the comparison specification](docs/research-comparisons.md) for remaining research requirements. Bundled HTMX and Public Sans assets retain their upstream licenses in `src/temporal_auth/web/static/vendor/`.
