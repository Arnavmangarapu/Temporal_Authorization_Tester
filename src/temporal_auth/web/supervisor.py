"""Own a worker process group, including its temporary target children."""

import asyncio
import os
from pathlib import Path
import signal
import sys

from temporal_auth.web.execution import python_environment


class Supervisor:
    def __init__(self, store, tools, metrics_port=None):
        self.store, self.tools = store, Path(tools).resolve()
        self.metrics_port = metrics_port
        self.process = None
        self.task = None
        self.stopping = False
        self.error = None

    @property
    def healthy(self):
        return self.process is not None and self.process.returncode is None and not self.error

    async def start(self):
        self.task = asyncio.create_task(self.monitor())
        await asyncio.sleep(0)

    def kill_group(self, sig):
        if self.process:
            try: os.killpg(self.process.pid, sig)
            except ProcessLookupError: pass

    async def monitor(self):
        while not self.stopping:
            self.process = await asyncio.create_subprocess_exec(sys.executable, "-m", "temporal_auth.web.worker",
                "--root", str(self.store.root), "--tools", str(self.tools),
                *(["--metrics-port", str(self.metrics_port)] if self.metrics_port is not None else []),
                env=python_environment(), start_new_session=True,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            await self.process.wait()
            if self.process.returncode == 73:
                self.error = "Another worker already owns this workspace. Use one dashboard process."
                return
            if self.process.returncode == 78:
                self.error = "Monitoring could not start. Install the monitoring extra and use a free metrics port."
                return
            if not self.stopping:
                self.kill_group(signal.SIGKILL)
                self.store.interrupt_unfinished(owner_pid=self.process.pid)
                await asyncio.sleep(0.25)

    async def close(self):
        self.stopping = True
        if self.process and self.process.returncode is None:
            self.process.terminate()
            try: await asyncio.wait_for(self.process.wait(), 12)
            except TimeoutError:
                self.kill_group(signal.SIGKILL)
                await self.process.wait()
        if self.task:
            await self.task
        self.kill_group(signal.SIGKILL)
        if self.process:
            self.store.interrupt_unfinished(owner_pid=self.process.pid)
