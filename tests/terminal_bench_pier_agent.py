from __future__ import annotations

import asyncio
import os
import subprocess
import threading
import uuid
from pathlib import Path

from deepswe_pier_agent import _ShellBridge
from harbor.agents.base import BaseAgent
from harbor.environments.base import BaseEnvironment
from harbor.models.agent.context import AgentContext


class ZodeTerminalBenchAgent(BaseAgent):
    """Run an arbitrary Terminal-Bench task through the real Zode Endpoint."""

    def __init__(
        self,
        *args: object,
        zode_root: str,
        auth_file: str,
        **kwargs: object,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.zode_root = Path(zode_root).resolve()
        self.auth_file = Path(auth_file).resolve()
        self.workdir: str | None = None

    @staticmethod
    def name() -> str:
        return "zode-terminal-bench"

    def version(self) -> str:
        return "1"

    async def setup(self, environment: BaseEnvironment) -> None:
        probe = await environment.exec("pwd", timeout_sec=30)
        if probe.return_code != 0 or not (probe.stdout or "").strip():
            raise RuntimeError("Terminal-Bench task working directory is unavailable")
        self.workdir = (probe.stdout or "").strip()

    async def run(
        self,
        instruction: str,
        environment: BaseEnvironment,
        context: AgentContext,
    ) -> None:
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        instruction_path = self.logs_dir / "instruction.txt"
        instruction_path.write_text(instruction, encoding="utf-8")
        instruction_path.chmod(0o600)

        loop = asyncio.get_running_loop()
        bridge = _ShellBridge(loop, environment, cwd=self.workdir)
        thread = threading.Thread(target=bridge.serve_forever, daemon=True)
        thread.start()
        run_id = f"terminal-bench-{uuid.uuid4()}"
        command = [
            "cargo",
            "test",
            "--release",
            "--locked",
            "--test",
            "deepswe_e2e",
            "e2e_live_deepswe_opencode_go_records_and_completes",
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
        ]
        env = os.environ.copy()
        env.update(
            {
                "ZODE_DEEPSWE_INSTRUCTION_FILE": str(instruction_path),
                "ZODE_DEEPSWE_SHELL_URL": (
                    f"http://127.0.0.1:{bridge.server_port}/invoke"
                ),
                "ZODE_DEEPSWE_AUTH_FILE": str(self.auth_file),
                "ZODE_DEEPSWE_RUN_ID": run_id,
                "ZODE_DEEPSWE_SHELL_DESCRIPTION": (
                    "Execute a shell command in the Terminal-Bench task environment. "
                    "Use it to inspect and modify that environment and complete the task."
                ),
                "RUST_TEST_THREADS": "1",
            }
        )
        output_path = self.logs_dir / "zode-agent.log"
        output_path.touch(mode=0o600, exist_ok=False)
        try:
            with output_path.open("wb") as output:
                process = await asyncio.create_subprocess_exec(
                    *command,
                    cwd=self.zode_root,
                    env=env,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                )
                return_code = await process.wait()
        finally:
            bridge.shutdown()
            bridge.server_close()
            thread.join(timeout=5)

        bridge.assert_replay_complete()
        context.metadata = {
            "zode_test_return_code": return_code,
            "zode_log": str(output_path),
            "run_id": run_id,
            "benchmark_completed": return_code == 0,
            "task_workdir": self.workdir,
        }
        if return_code != 0:
            raise RuntimeError(
                f"Zode Terminal-Bench runtime failed with exit code {return_code}; "
                f"see {output_path}"
            )
