"""Start only project-owned disposable instances; never attach to user services."""

from contextlib import contextmanager
from dataclasses import dataclass
import getpass
import hashlib
import os
from pathlib import Path
import secrets
import re
import socket
import subprocess
from tempfile import TemporaryDirectory
import time

import httpx


VERSIONS = {"gitea": "28.3.0", "pocketbase": "0.40.6"}
EXECUTABLE_SHA256 = {
    "gitea": "5f834e8f04986f3b9206cf14743b5a6e6996ceddc238dac6409866ebda2a0686",
    "pocketbase": "8e9805c9d92c50a4ff2bce97579d13e2ddfa138cab10cf6f9e8f6db8016ffa30",
}


@dataclass
class Fixture:
    target: str
    origin: str
    username: str
    password: str
    version: str
    bootstrap_seconds: float
    readiness_requests: int
    bootstrap_commands: int = 1
    binary_sha256: str | None = None


def checked_command(args, *, cwd, timeout=30, budget=None):
    # Credentials can appear in bootstrap CLI arguments. Never log the command
    # or subprocess output, including in exceptions.
    if budget is not None:
        if budget.remaining() <= 0:
            raise RuntimeError("runtime_budget_exhausted")
        timeout = min(timeout, budget.remaining())
    try:
        result = subprocess.run(args, cwd=cwd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("fixture_bootstrap_failed") from None
    if budget is not None and budget.remaining() <= 0:
        raise RuntimeError("runtime_budget_exhausted")
    if result.returncode:
        raise RuntimeError("fixture_bootstrap_failed")
    return result.stdout.decode("utf-8", errors="replace")


@contextmanager
def managed_fixture(target: str, tools: Path, *, budget=None):
    if target not in VERSIONS:
        raise ValueError("unsupported_external_target")
    binary = (tools / target).resolve()
    if not binary.is_file():
        raise ValueError("missing_target_binary")
    version = checked_command([str(binary), "--version"], cwd=tools.resolve(), budget=budget)
    # Match the complete version token, not an arbitrary substring.
    match = re.search(r"\bversion ([^\s]+)", version)
    if not match or match.group(1) != VERSIONS[target]:
        raise ValueError("unexpected_target_version")
    with binary.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    if digest != EXECUTABLE_SHA256[target]:
        raise ValueError("unexpected_binary_digest")
    started = time.monotonic()
    with TemporaryDirectory(prefix=f"temporal-{target}-") as temp:
        root = Path(temp)
        os.chmod(root, 0o700)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        password = secrets.token_urlsafe(24)
        username = "owner" if target == "gitea" else "owner@example.test"
        if target == "pocketbase":
            common = [str(binary), "--dir", str(root / "data")]
            checked_command([*common, "superuser", "create", username, password], cwd=root, budget=budget)
            command = [*common, "serve", "--http", f"127.0.0.1:{port}"]
            health = "/api/health"
        else:
            config = root / "app.ini"
            config.write_text(
                f"RUN_USER = {getpass.getuser()}\nRUN_MODE = prod\n"
                f"WORK_PATH = {root}\n[server]\nHTTP_ADDR = 127.0.0.1\n"
                f"HTTP_PORT = {port}\nROOT_URL = {origin}/\nDISABLE_SSH = true\n"
                f"APP_DATA_PATH = {root}/data\n[database]\nDB_TYPE = sqlite3\n"
                f"PATH = {root}/gitea.db\n[repository]\nROOT = {root}/repositories\n"
                "[security]\nINSTALL_LOCK = true\n[service]\nDISABLE_REGISTRATION = true\n"
                "[actions]\nENABLED = false\n[mailer]\nENABLED = false\n"
                "[cron]\nENABLED = false\n[log]\nMODE = console\nLEVEL = error\n",
                encoding="utf-8",
            )
            config.chmod(0o600)
            common = [str(binary), "--work-path", str(root), "--config", str(config)]
            checked_command([*common, "migrate"], cwd=root, budget=budget)
            checked_command([*common, "admin", "user", "create", "--username", username,
                             "--password", password, "--email", "owner@example.test",
                             "--admin", "--must-change-password=false"], cwd=root, budget=budget)
            command = [*common, "web"]
            health = "/api/v1/version"
        process = None
        # Logs are transient and private; do not export credential-bearing debug
        # logs or databases into research evidence.
        with (root / "server.log").open("wb") as log:
            try:
                process = subprocess.Popen(command, cwd=root, stdout=log, stderr=log,
                                           stdin=subprocess.DEVNULL)
                polls = 0
                with httpx.Client(base_url=origin, trust_env=False, timeout=0.5) as client:
                    while time.monotonic() - started < 45:
                        if process.poll() is not None:
                            raise RuntimeError("fixture_start_failed")
                        polls += 1
                        if budget is not None:
                            budget.reserve(fixture=True)
                        try:
                            if client.get(health).status_code == 200:
                                break
                        except httpx.HTTPError:
                            pass
                        time.sleep(0.05)
                    else:
                        raise RuntimeError("fixture_start_timeout")
                yield Fixture(target, origin, username, password, VERSIONS[target],
                              time.monotonic() - started, polls,
                              2 if target == "gitea" else 1, digest)
            finally:
                if process is not None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
