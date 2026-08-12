from __future__ import annotations

import base64
import json
import shlex

from harbor.agents.installed.base import with_prompt_template
from harbor.agents.installed.pi import Pi
from harbor.environments.base import BaseEnvironment
from harbor.models.agent.context import AgentContext

PROVIDER_BASE_URL = "https://opencode.ai/zen/go/v1"
CONTAINER_AUTH_FILE = "/run/zode-benchmark/opencode-auth.json"
PI_RUNTIME_BIN = "/opt/zode-pi-runtime/bin"


class PiTerminalBenchAgent(Pi):
    """Run Pi on Terminal-Bench and retain Pi's native session artifact."""

    @staticmethod
    def name() -> str:
        return "pi-terminal-bench"

    def version(self) -> str | None:
        return super().version()

    async def install(self, environment: BaseEnvironment) -> None:
        await self.exec_as_agent(
            environment,
            command=(
                f"export PATH={PI_RUNTIME_BIN}:$PATH; "
                "node --version >/dev/null && pi --version >/dev/null 2>&1"
            ),
        )

    @with_prompt_template
    async def run(
        self,
        instruction: str,
        environment: BaseEnvironment,
        context: AgentContext,
    ) -> None:
        models = {
            "providers": {
                "zode-opencode-go": {
                    "baseUrl": PROVIDER_BASE_URL,
                    "api": "openai-completions",
                    "apiKey": (
                        '!node -e \'const fs=require("fs");'
                        f'const a=JSON.parse(fs.readFileSync("{CONTAINER_AUTH_FILE}","utf8"));'
                        'process.stdout.write(a["opencode-go"].key)\''
                    ),
                    "authHeader": True,
                    "compat": {
                        "supportsDeveloperRole": False,
                        "supportsReasoningEffort": False,
                    },
                    "models": [
                        {
                            "id": "deepseek-v4-flash",
                            "name": "deepseek-v4-flash",
                            "reasoning": True,
                            "input": ["text"],
                            "contextWindow": 1_000_000,
                            "maxTokens": 128_000,
                            "cost": {
                                "input": 0,
                                "output": 0,
                                "cacheRead": 0,
                                "cacheWrite": 0,
                            },
                        }
                    ],
                }
            }
        }
        models_encoded = base64.b64encode(
            json.dumps(models, ensure_ascii=False, separators=(",", ":")).encode()
        ).decode()
        escaped_instruction = shlex.quote(instruction)
        cli_flags = self.build_cli_flags()
        if cli_flags:
            cli_flags += " "
        resume_flag = "--continue " if self._resume else ""
        await self.exec_as_agent(
            environment,
            command=(
                "mkdir -p $HOME/.pi/agent /logs/agent/pi/sessions && "
                f"printf %s {shlex.quote(models_encoded)} | base64 -d "
                "> $HOME/.pi/agent/models.json && "
                "chmod 600 $HOME/.pi/agent/models.json"
            ),
        )
        skills_command = self._build_register_skills_command()
        if skills_command:
            await self.exec_as_agent(environment, command=skills_command)
        await self.exec_as_agent(
            environment,
            command=(
                f"export PATH={PI_RUNTIME_BIN}:$PATH; "
                "pi --print --mode json --session-dir /logs/agent/pi/sessions "
                f"{resume_flag}"
                "--provider zode-opencode-go --model deepseek-v4-flash "
                f"{cli_flags}"
                f"{escaped_instruction} "
                "2>&1 </dev/null | "
                'grep -v \'"type":"message_update"\' | '
                "stdbuf -oL tee /logs/agent/pi.txt"
            ),
        )
        context.metadata = {
            "benchmark_completed": True,
            "session_source": "pi-native-session",
            "session_directory": "agent/pi/sessions",
            "provider": "opencode-go",
            "model": "deepseek-v4-flash",
        }
