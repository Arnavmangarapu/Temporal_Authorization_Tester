"""One separate persistent worker with durable claims and cooperative cancellation."""

import argparse
import asyncio
import fcntl
import os
from pathlib import Path
import signal

from temporal_auth.web.execution import execute_spec
from temporal_auth.web.evidence import inspect_evidence
from temporal_auth.web.models import JobSpec
from temporal_auth.web.store import Store


async def work(root, tools):
    store = Store(root)
    stopping = False
    def stop():
        nonlocal stopping
        stopping = True
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT): loop.add_signal_handler(sig, stop)
    store.interrupt_unfinished()
    while not stopping:
        job = store.claim(owner_pid=os.getpid())
        if not job:
            await asyncio.sleep(0.15)
            continue
        directory = root / "jobs" / job["id"]
        try:
            summary = await execute_spec(JobSpec.model_validate(job["spec"]), directory, tools,
                                         lambda: stopping or store.cancelled(job["id"]))
            status = "completed" if summary["engine_status"] == "completed" else "failed"
            store.finish(job["id"], "interrupted" if stopping else status, summary, summary.get("error"))
        except asyncio.CancelledError:
            partial = inspect_evidence(directory, {"status": "interrupted", "result": {}})["result"]
            store.finish(job["id"], "interrupted" if stopping else "cancelled", partial, "cancelled")
        except Exception:
            # Do not log exception locals, credentials, arbitrary response data
            # or user YAML. Partial evidence stays available in the job folder.
            partial = inspect_evidence(directory, {"status": "interrupted", "result": {}})["result"]
            store.finish(job["id"], "interrupted" if stopping else "failed", partial, "execution_failed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--metrics-port", type=int)
    args = parser.parse_args()
    args.root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (args.root / "worker.lock").open("a") as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise SystemExit(73)
        exporter = None
        if args.metrics_port is not None:
            try:
                from temporal_auth.monitoring import WorkerExporter
                exporter = WorkerExporter(Store(args.root), args.metrics_port)
            except (ImportError, OSError, ValueError):
                raise SystemExit(78) from None
        try:
            asyncio.run(work(args.root, args.tools))
        finally:
            if exporter: exporter.close()


if __name__ == "__main__": main()
