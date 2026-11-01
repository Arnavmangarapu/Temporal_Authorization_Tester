"""Owned Docker fixture and static protected-data oracle for Dolibarr #26066."""

from contextlib import contextmanager
from dataclasses import dataclass
import json
import math
from pathlib import Path
import secrets
import subprocess
from tempfile import TemporaryDirectory
import time
from uuid import uuid4

from temporal_auth.integrations.pilot import PilotBudget, Recorder, private_json


REVISIONS = {"buggy": "c16313007a90010524cafba67acadcce036b6a9f",
             "fixed": "62ad3d12d2ee86f2f665f341565860f3e88b076a"}
DATABASE = "mariadb@sha256:d769e37960821dfdcf096954f6e7ac89f747e116c1bba98e48edd265dfc7deae"
LIST_PATH = "/api/index.php/multicurrencies?sortfield=t.rowid&sortorder=ASC&limit=100"
STEPS = ["identity_owner", "identity_allowed", "identity_restricted", "anonymous", "invalid_key",
         "owner_before", "allowed_before", "restricted_bycode", "restricted_list", "owner_after", "allowed_after"]


class ReproductionError(RuntimeError):
    pass


def command(args, *, budget, input=None, check=True, timeout=90):
    """Never expose raw bootstrap output or credential-bearing environments."""
    if budget.remaining() <= 0: raise ReproductionError("runtime_budget_exhausted")
    try:
        result = subprocess.run(args, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=max(0.01, min(timeout, budget.remaining())))
    except (OSError, subprocess.TimeoutExpired):
        raise ReproductionError("container_command_failed") from None
    if check and result.returncode: raise ReproductionError("container_command_failed")
    return result


@dataclass
class DolibarrFixture:
    origin: str
    keys: dict
    marker: str
    state: dict
    metadata: dict


@contextmanager
def managed_dolibarr(variant, *, budget, metadata, expected_image_id=None, marker=None):
    if variant not in REVISIONS: raise ValueError("unsupported_dolibarr_revision")
    image = "temporal-auth-dolibarr-26066:" + variant
    info = json.loads(command(["docker", "image", "inspect", image], budget=budget).stdout)[0]
    if info["Config"]["Labels"].get("org.temporal-auth.revision") != REVISIONS[variant]:
        raise ReproductionError("unexpected_revision_label")
    if expected_image_id and info["Id"] != expected_image_id:
        raise ReproductionError("unexpected_image_id")
    suffix = uuid4().hex
    network, database, application = ("temporal-doli-" + suffix + part for part in ("-net", "-db", "-app"))
    metadata.update(variant=variant, revision=REVISIONS[variant], app_image_id=info["Id"],
                    database_image=DATABASE, network=network, containers=[database, application],
                    bootstrap_commands=0, cleaned_up=False)
    keys = {role: secrets.token_hex(24) for role in ("owner", "allowed", "restricted")}
    marker = marker or "TAT-protected-currency-" + uuid4().hex
    if not marker.startswith("TAT-protected-currency-") or not marker.replace("-", "").isalnum():
        raise ValueError("invalid_fixture_marker")
    started = time.monotonic()
    with TemporaryDirectory(prefix="temporal-dolibarr-private-") as temporary:
        root = Path(temporary); root.chmod(0o700)
        db_password = secrets.token_hex(24)
        env = {"MARIADB_ROOT_PASSWORD": secrets.token_hex(24), "MARIADB_DATABASE": "dolibarr",
               "MARIADB_USER": "dolibarr", "MARIADB_PASSWORD": db_password,
               "DOLI_DB_PASSWORD": db_password, "DOLI_INSTANCE_ID": secrets.token_hex(24),
               "DOLI_USER_PASSWORD": secrets.token_urlsafe(24), "DOLI_MARKER": marker,
               **{"DOLI_KEY_" + role.upper(): value for role, value in keys.items()}}
        env_file = root / "fixture.env"
        env_file.write_text("".join(f"{key}={value}\n" for key, value in env.items()))
        env_file.chmod(0o600)
        try:
            command(["docker", "network", "create", network], budget=budget)
            command(["docker", "run", "-d", "--rm", "--name", database, "--network", network,
                     "--network-alias", "database", "--env-file", str(env_file),
                     "--tmpfs", "/var/lib/mysql:rw", DATABASE,
                     "--sql-mode=NO_ENGINE_SUBSTITUTION", "--character-set-server=utf8mb4",
                     "--collation-server=utf8mb4_unicode_ci"], budget=budget)
            # Readiness is a non-HTTP SQL command, counted separately from API work.
            while True:
                result = command(["docker", "exec", database, "sh", "-c",
                    'MYSQL_PWD="$MARIADB_PASSWORD" mariadb -u dolibarr dolibarr -Nse "SELECT 1"'],
                    budget=budget, check=False, timeout=10)
                metadata["bootstrap_commands"] += 1
                if result.returncode == 0 and result.stdout.strip() == b"1": break
                time.sleep(min(0.25, max(0, budget.remaining())))
            command(["docker", "run", "-d", "--rm", "--name", application, "--network", network,
                     "--env-file", str(env_file), "--publish", "127.0.0.1::80", image], budget=budget)
            origin = "http://" + command(["docker", "port", application, "80/tcp"], budget=budget).stdout.decode().strip()
            command(["docker", "exec", "--workdir", "/var/www/html/install", application,
                     "php", "step2.php", "set", "en_US"], budget=budget, timeout=180)
            metadata["bootstrap_commands"] += 1
            result = command(["docker", "exec", application, "php", "/opt/reproduction/bootstrap.php"], budget=budget)
            metadata["bootstrap_commands"] += 1
            try:
                state = json.loads(result.stdout)
            except ValueError:
                raise ReproductionError("invalid_bootstrap_state") from None
            metadata["php_version"] = command(["docker", "exec", application, "php", "-r", "echo PHP_VERSION;"], budget=budget).stdout.decode()
            metadata["bootstrap_seconds"] = time.monotonic() - started
            metadata["state"] = state
            yield DolibarrFixture(origin, keys, marker, state, metadata)
        finally:
            # Cleanup has its own bounded grace period, including on cancellation.
            failures = []
            for resource, args in [(application, ["docker", "rm", "-f", application]),
                                   (database, ["docker", "rm", "-f", database]),
                                   (network, ["docker", "network", "rm", network])]:
                try:
                    subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                    inspect = (["docker", "network", "inspect", resource] if resource == network
                               else ["docker", "container", "inspect", resource])
                    result = subprocess.run(inspect, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)
                    missing = any(text in result.stderr.lower() for text in (b"no such", b"not found"))
                    if result.returncode == 0 or not missing: failures.append(resource)
                except (OSError, subprocess.TimeoutExpired): failures.append(resource)
            metadata["cleanup_errors"] = failures
            metadata["cleaned_up"] = not failures


def analyze_static(events, *, marker, state):
    """Identity + effective-right + same-record controls, not a status-only rule."""
    def one(step):
        rows = [e for e in events if e["step"] == step]
        if len(rows) != 1: raise ValueError
        row = rows[0]
        if row["error"] or row["truncated"] or row["method"] != "GET": raise ValueError
        return row

    def contains(row):
        data = json.loads(row["body"])
        records = data if isinstance(data, list) else [data]
        return any(isinstance(record, dict) and str(record.get("id")) == str(state["currency_id"])
                   and record.get("code") == state["code"] and record.get("name") == marker for record in records)

    try:
        if not marker or state["code"] != "XTS": raise ValueError
        if [e["step"] for e in events] != STEPS: raise ValueError
        previous = -1
        for e in events:
            if e["method"] != "GET" or not all(math.isfinite(e[k]) for k in ("started", "finished")): raise ValueError
            if e["started"] < previous or e["finished"] < e["started"]: raise ValueError
            previous = e["finished"]
        actors = state["actors"]
        if len({a["id"] for a in actors.values()}) != 3: raise ValueError
        for role in ("owner", "allowed", "restricted"):
            expected = actors[role]
            if int(expected["admin"]) != (1 if role == "owner" else 0): raise ValueError
            identity = one("identity_" + role)
            if identity["status"] != 200 or identity["path"] != f"/api/index.php/users/{expected['id']}?includepermissions=1": raise ValueError
            data = json.loads(identity["body"])
            if (str(data["id"]) != str(expected["id"]) or data["login"] != role
                    or int(data["admin"]) != (1 if role == "owner" else 0)): raise ValueError
            rights = data.get("rights", {}).get("multicurrency", {}).get("currency", {}).get("read", 0)
            if bool(int(rights or 0)) != (role != "restricted") or bool(expected["currency_read"]) != (role != "restricted"): raise ValueError
        for step in ("owner_before", "allowed_before", "owner_after", "allowed_after"):
            row = one(step)
            if row["path"] != LIST_PATH or row["status"] != 200 or not contains(row): raise ValueError
        for step in ("anonymous", "invalid_key"):
            row = one(step)
            if row["path"] != LIST_PATH or row["status"] not in (401, 403) or marker in (row["body"] or ""): raise ValueError
        bycode = one("restricted_bycode")
        if bycode["path"] != "/api/index.php/multicurrencies/bycode/XTS" or bycode["status"] not in (401, 403) or marker in (bycode["body"] or ""): raise ValueError
        probe = one("restricted_list")
        if probe["path"] != LIST_PATH: raise ValueError
        if not all(one(s)["finished"] <= probe["started"] for s in ("owner_before", "allowed_before")): raise ValueError
        if not all(one(s)["started"] >= probe["finished"] for s in ("owner_after", "allowed_after")): raise ValueError
        if marker in (probe["body"] or ""):
            if not contains(probe): raise ValueError
            return {"verdict": "protected_data_disclosed", "reason": "same_currency_record_without_read_permission"}
        if probe["status"] in (401, 403):
            return {"verdict": "access_denied", "reason": "no_protected_record_with_valid_positive_controls"}
        return {"verdict": "inconclusive", "reason": "unexpected_or_empty_probe_response"}
    except (ValueError, TypeError, KeyError, AttributeError):
        return {"verdict": "inconclusive", "reason": "invalid_identity_rights_record_or_controls"}


def run_reproduction(variant, output, *, expected_image_id=None, marker=None, max_requests=100, max_seconds=300):
    if variant not in REVISIONS: raise ValueError("unsupported_dolibarr_revision")
    directory = Path(output) / (variant + "-" + uuid4().hex)
    directory.mkdir(parents=True, mode=0o700)
    budget = PilotBudget(max_requests, max_seconds)
    metadata, recorder = {}, None
    report = {"schema_version": "dolibarr-26066-reproduction-1", "variant": variant,
              "revision": REVISIONS[variant], "status": "running", "verdict": "inconclusive",
              "case": "known_static_authorization_bug", "temporal_claim": False,
              "blind_held_out": False, "new_vulnerability_claim": False}
    try:
        with managed_dolibarr(variant, budget=budget, metadata=metadata, expected_image_id=expected_image_id, marker=marker) as fixture:
            recorder = Recorder(fixture.origin, budget, directory / "events.jsonl")
            for key in fixture.keys.values(): recorder.redactor.add(key)
            sessions = {role: {"DOLAPIKEY": key} for role, key in fixture.keys.items()}
            for role in sessions:
                recorder.request("identity_" + role, "GET",
                    f"/api/index.php/users/{fixture.state['actors'][role]['id']}?includepermissions=1", headers=sessions[role])
            recorder.request("anonymous", "GET", LIST_PATH)
            recorder.request("invalid_key", "GET", LIST_PATH, headers={"DOLAPIKEY": "invalid-fixture-key"})
            for role in ("owner", "allowed"):
                recorder.request(role + "_before", "GET", LIST_PATH, headers=sessions[role])
            recorder.request("restricted_bycode", "GET", "/api/index.php/multicurrencies/bycode/XTS", headers=sessions["restricted"])
            recorder.request("restricted_list", "GET", LIST_PATH, headers=sessions["restricted"])
            for role in ("owner", "allowed"):
                recorder.request(role + "_after", "GET", LIST_PATH, headers=sessions[role])
            report["analysis"] = analyze_static(recorder.events, marker=fixture.marker, state=fixture.state)
            report.update(verdict=report["analysis"]["verdict"], status="completed", marker=fixture.marker)
    except (RuntimeError, ValueError, OSError) as error:
        report.update(status="execution_error", error="reproduction_execution_failed")
        if isinstance(error, ReproductionError): report["error"] = str(error)
    except KeyboardInterrupt:
        report.update(status="interrupted", error="cancelled")
        raise
    finally:
        if recorder: recorder.close()
        report.update(fixture=metadata, requests=budget.requests, elapsed_seconds=budget.clock() - budget.started)
        private_json(directory / "reproduction.json", report)
    return report, directory
