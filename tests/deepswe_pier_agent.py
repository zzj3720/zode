from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shlex
import subprocess
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from pier.agents.base import BaseAgent
from pier.environments.base import BaseEnvironment
from pier.models.agent.context import AgentContext


MAX_TOOL_OUTPUT_BYTES = 64 * 1024
LIVE_AGENT_GUIDANCE = """
Work autonomously until the repository change fully satisfies every part of the
task. Before giving a final response, inspect the complete diff, trace the
affected behavior through its call sites, consider edge cases that public tests
may not cover, and run the broadest relevant test suite available in the task
repository. Do not inspect or search for hidden benchmark tests or solutions.
Do not stop at a partial fix merely because existing public tests pass. Commit
the complete final repository change before responding; the benchmark grades
the diff from the initial checkout commit to final HEAD.
""".strip()
TRACKED_EVENT_REPLAY_NAME = (
    "anko_default_function_arguments_deepseek_v4_flash.v2.events.json"
)
TRACKED_EVENT_REPLAY_SHA256 = (
    "2927398928170ac9a3a6993baf6d99b0c69357629109d92c0e9da303e0f40fec"
)


def _bounded(value: str | None) -> str:
    raw = (value or "").encode("utf-8", errors="replace")
    if len(raw) <= MAX_TOOL_OUTPUT_BYTES:
        return raw.decode("utf-8", errors="replace")
    suffix = b"\n[output truncated by Zode DeepSWE adapter]"
    return (raw[: MAX_TOOL_OUTPUT_BYTES - len(suffix)] + suffix).decode(
        "utf-8", errors="replace"
    )


class _ShellBridge(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        environment: BaseEnvironment,
        event_replay_path: Path | None = None,
        provider_replay_path: Path | None = None,
        allow_trailing_pending: bool = False,
        cwd: str | None = "/app",
    ) -> None:
        super().__init__(("127.0.0.1", 0), _ShellHandler)
        self.loop = loop
        self.environment = environment
        self.cwd = cwd
        self.recording_lock = threading.Lock()
        self.sequence = 0
        self.responses_written = 0
        self.replay_error: str | None = None
        self.replay = []
        if event_replay_path is not None:
            replay_bytes = event_replay_path.read_bytes()
            if (
                event_replay_path.name == TRACKED_EVENT_REPLAY_NAME
                and hashlib.sha256(replay_bytes).hexdigest()
                != TRACKED_EVENT_REPLAY_SHA256
            ):
                raise ValueError("tracked DeepSWE event trace digest is invalid")
            trace = json.loads(replay_bytes)
            if (
                trace.get("schema")
                not in {
                    "zode.deepswe-event-trace.v1",
                    "zode.deepswe-event-trace.v2",
                }
                or not isinstance(trace.get("integrity_sha256"), str)
                or not isinstance(trace.get("source"), dict)
                or not isinstance(trace.get("events"), list)
            ):
                raise ValueError("DeepSWE event trace is invalid")
            digest_preimage = {
                "schema": trace["schema"],
                "source": trace["source"],
                "events": trace["events"],
            }
            if trace["schema"] == "zode.deepswe-event-trace.v2":
                digest_preimage["blobs"] = trace.get("blobs", [])
            digest = hashlib.sha256(
                json.dumps(
                    digest_preimage,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            if digest != trace["integrity_sha256"]:
                raise ValueError("DeepSWE event trace integrity is invalid")
            if (
                provider_replay_path is None
                or trace["source"].get("provider_fixture_sha256")
                != hashlib.sha256(provider_replay_path.read_bytes()).hexdigest()
            ):
                raise ValueError("DeepSWE event trace does not match provider replay")
            blobs: dict[str, str] = {}
            for blob in trace.get("blobs", []):
                content = blob.get("content")
                blob_id = blob.get("blob_id")
                if not isinstance(content, str) or not isinstance(blob_id, str):
                    raise ValueError("DeepSWE event trace blob is invalid")
                encoded = content.encode("utf-8")
                digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
                if (
                    blob_id != digest
                    or blob.get("sha256") != digest
                    or blob.get("byte_len") != len(encoded)
                    or blob_id in blobs
                ):
                    raise ValueError("DeepSWE event trace blob integrity is invalid")
                blobs[blob_id] = content
            started: dict[str, dict[str, Any]] = {}
            for index, event in enumerate(trace["events"], start=1):
                if (
                    event.get("stream_version") != index
                    or not isinstance(event.get("event_schema_version"), int)
                    or not isinstance(event.get("event_type"), str)
                    or not isinstance(event.get("payload"), dict)
                ):
                    raise ValueError("DeepSWE event trace sequence is invalid")
                payload = event["payload"]
                if event["event_type"] == "async_tool_call_started":
                    record = payload.get("record", {})
                    tool_call_id = record.get("tool_call_id")
                    command = record.get("input", {}).get("Inline", {}).get("command")
                    if (
                        record.get("tool_name") != "shell"
                        or not isinstance(tool_call_id, str)
                        or not isinstance(command, str)
                        or tool_call_id in started
                    ):
                        raise ValueError("DeepSWE event trace tool input is invalid")
                    exchange = {
                        "tool_call_id": tool_call_id,
                        "command": command,
                        "outcome": None,
                    }
                    started[tool_call_id] = exchange
                    self.replay.append(exchange)
                elif event["event_type"] == "async_tool_call_completed":
                    tool_call_id = payload.get("tool_call_id")
                    content = payload.get("result", {}).get("Inline", {}).get("content")
                    if not isinstance(content, str):
                        blob_id = (
                            payload.get("result", {}).get("BlobRef", {}).get("blob_id")
                        )
                        content = blobs.get(blob_id)
                    exchange = started.get(tool_call_id)
                    if (
                        exchange is None
                        or exchange["outcome"] is not None
                        or not isinstance(content, str)
                    ):
                        raise ValueError("DeepSWE event trace tool result is invalid")
                    exchange["outcome"] = {
                        "kind": "completed",
                        "result_content": content,
                    }
                elif event["event_type"] == "async_tool_call_failed":
                    tool_call_id = payload.get("tool_call_id")
                    error = payload.get("error")
                    exchange = started.get(tool_call_id)
                    if (
                        exchange is None
                        or exchange["outcome"] is not None
                        or not isinstance(error, dict)
                        or not isinstance(error.get("class"), str)
                        or not error["class"]
                        or not isinstance(error.get("message"), str)
                        or not error["message"]
                    ):
                        raise ValueError("DeepSWE event trace tool failure is invalid")
                    exchange["outcome"] = {"kind": "failed"}
            pending = [
                index
                for index, exchange in enumerate(self.replay)
                if exchange["outcome"] is None
            ]
            if not self.replay or (
                allow_trailing_pending and pending != [len(self.replay) - 1]
            ):
                raise ValueError(
                    "DeepSWE partial failure prefix must end in exactly one pending tool outcome"
                )
            if not allow_trailing_pending and pending:
                raise ValueError("DeepSWE event trace has incomplete tool outcomes")

    def execute(self, command: str) -> dict[str, Any]:
        with self.recording_lock:
            replay_index = self.sequence
            self.sequence += 1
            expected = (
                self.replay[replay_index] if replay_index < len(self.replay) else None
            )
        actual = None
        actual_failed = False
        try:
            future = asyncio.run_coroutine_threadsafe(
                self.environment.exec(
                    f"bash -lc {shlex.quote(command)}",
                    cwd=self.cwd,
                    timeout_sec=600,
                ),
                self.loop,
            )
            result = future.result(timeout=620)
            actual = {
                "exit_code": result.return_code,
                "stdout": _bounded(result.stdout),
                "stderr": _bounded(result.stderr),
            }
        except Exception:
            if expected is None:
                raise
            actual_failed = True

        returned = actual
        response_status = 200
        replay_error = None
        if expected is not None:
            outcome = expected["outcome"]
            if expected["command"] != command:
                replay_error = "DeepSWE shell command did not match event trace"
            if outcome is None:
                if actual_failed:
                    returned = {"error": "shell execution failed"}
                    response_status = 500
            elif outcome["kind"] == "completed":
                returned = json.loads(outcome["result_content"])
                if actual_failed:
                    replay_error = replay_error or (
                        "DeepSWE shell failed but the event trace recorded completion"
                    )
                elif returned.get("exit_code") != actual["exit_code"]:
                    replay_error = replay_error or (
                        "DeepSWE shell exit code did not match event trace"
                    )
            else:
                returned = {"error": "recorded tool failure"}
                response_status = 500
                if not actual_failed:
                    replay_error = replay_error or (
                        "DeepSWE shell completed but the event trace recorded failure"
                    )
        elif self.replay:
            replay_error = "DeepSWE event replay observed an extra shell command"
        if returned is None:
            raise RuntimeError("shell execution produced no result")
        content = json.dumps(
            returned,
            ensure_ascii=False,
        )
        with self.recording_lock:
            if replay_error is not None and self.replay_error is None:
                self.replay_error = replay_error
        return response_status, {"result": {"content": content}}

    def mark_response_written(self) -> None:
        with self.recording_lock:
            self.responses_written += 1

    def observation_state(self) -> dict[str, Any]:
        with self.recording_lock:
            return {
                "schema": "zode.deepswe-shell-observation.v1",
                "requests_started": self.sequence,
                "responses_written": self.responses_written,
            }

    def assert_replay_complete(self) -> None:
        with self.recording_lock:
            replay_count = len(self.replay)
            replay_error = self.replay_error
            sequence = self.sequence
        if replay_count == 0:
            return
        if replay_error is not None:
            raise RuntimeError(replay_error)
        if sequence != replay_count:
            raise RuntimeError(
                "DeepSWE event replay did not consume every tool exchange"
            )


class _ShellHandler(BaseHTTPRequestHandler):
    server: _ShellBridge

    def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length))
            command = body.get("input", {}).get("command")
            if not isinstance(command, str) or not command.strip():
                raise ValueError("shell command is required")
            status, response = self.server.execute(command)
            encoded = json.dumps(response, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
        except Exception as error:  # keep tool failure observable to the model
            encoded = json.dumps(
                {"result": {"content": json.dumps({"error": str(error)})}}
            ).encode("utf-8")
            self.send_response(500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)
        self.wfile.flush()
        self.server.mark_response_written()

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        if self.path != "/_zode-test/observations":
            self.send_response(404)
            self.end_headers()
            return
        encoded = json.dumps(self.server.observation_state()).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class ZodeDeepSweAgent(BaseAgent):
    def __init__(
        self,
        *args: object,
        zode_root: str,
        auth_file: str,
        replay_file: str = "",
        event_replay_file: str = "",
        promote_llm_file: str = "",
        partial_failure_prefix: bool | str = False,
        **kwargs: object,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.zode_root = Path(zode_root).resolve()
        self.auth_file = Path(auth_file).resolve()
        self.replay_file = Path(replay_file).resolve() if replay_file else None
        self.event_replay_file = (
            Path(event_replay_file).resolve() if event_replay_file else None
        )
        self.promote_llm_file = (
            Path(promote_llm_file).resolve() if promote_llm_file else None
        )
        self.partial_failure_prefix = (
            partial_failure_prefix
            if isinstance(partial_failure_prefix, bool)
            else partial_failure_prefix.strip().lower() in {"1", "true", "yes"}
        )
        if (self.replay_file is None) != (self.event_replay_file is None):
            raise ValueError(
                "DeepSWE provider replay and event replay must be configured together"
            )
        if self.partial_failure_prefix and self.replay_file is None:
            raise ValueError(
                "DeepSWE partial failure replay requires both replay files"
            )
        self.initial_commit = ""

    @staticmethod
    def name() -> str:
        return "zode-deepswe"

    def version(self) -> str:
        return "8"

    async def setup(self, environment: BaseEnvironment) -> None:
        probe = await environment.exec("git rev-parse HEAD", cwd="/app", timeout_sec=30)
        commit = probe.stdout.strip()
        if (
            probe.return_code != 0
            or len(commit) != 40
            or any(character not in "0123456789abcdef" for character in commit)
        ):
            raise RuntimeError("DeepSWE task checkout is unavailable")
        self.initial_commit = commit

    async def run(
        self,
        instruction: str,
        environment: BaseEnvironment,
        context: AgentContext,
    ) -> None:
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        instruction_path = self.logs_dir / "instruction.txt"
        agent_instruction = instruction
        if self.replay_file is None:
            agent_instruction = f"{instruction.rstrip()}\n\n{LIVE_AGENT_GUIDANCE}\n"
        instruction_path.write_text(agent_instruction, encoding="utf-8")
        instruction_path.chmod(0o600)

        loop = asyncio.get_running_loop()
        bridge = _ShellBridge(
            loop,
            environment,
            self.event_replay_file,
            self.replay_file,
            self.partial_failure_prefix,
        )
        thread = threading.Thread(target=bridge.serve_forever, daemon=True)
        thread.start()
        run_id = f"deepswe-{uuid.uuid4()}"
        if self.partial_failure_prefix:
            test_name = (
                "e2e_replayed_deepswe_returned_tool_response_reaches_durable_terminal"
            )
        elif self.replay_file:
            test_name = "e2e_replayed_deepswe_recording_completes_through_real_endpoint"
        else:
            test_name = "e2e_live_deepswe_opencode_go_records_and_completes"
        command = [
            "cargo",
            "test",
            "--release",
            "--locked",
            "--test",
            "deepswe_e2e",
            test_name,
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
        ]
        env = os.environ.copy()
        env.update(
            {
                "ZODE_DEEPSWE_INSTRUCTION_FILE": str(instruction_path),
                "ZODE_DEEPSWE_SHELL_URL": f"http://127.0.0.1:{bridge.server_port}/invoke",
                "ZODE_DEEPSWE_AUTH_FILE": str(self.auth_file),
                "ZODE_DEEPSWE_RUN_ID": run_id,
                "RUST_TEST_THREADS": "1",
            }
        )
        if self.replay_file:
            env["ZODE_DEEPSWE_REPLAY_FILE"] = str(self.replay_file)
            env["ZODE_DEEPSWE_EVENT_REPLAY_FILE"] = str(self.event_replay_file)
        if self.promote_llm_file:
            env["ZODE_DEEPSWE_PROMOTE_LLM_FILE"] = str(self.promote_llm_file)
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

        if return_code == 0 and not self.partial_failure_prefix:
            collect = await environment.exec(
                "mkdir -p /logs/artifacts && "
                f"git diff --binary {shlex.quote(self.initial_commit)} HEAD "
                "> /logs/artifacts/model.patch",
                cwd="/app",
                timeout_sec=300,
            )
            if collect.return_code != 0:
                raise RuntimeError("DeepSWE benchmark patch collection failed")

        context.metadata = {
            "zode_test_return_code": return_code,
            "zode_log": str(output_path),
            "event_replay": str(self.event_replay_file or ""),
            "run_id": run_id,
            "patch_collected": return_code == 0 and not self.partial_failure_prefix,
            "partial_failure_prefix": self.partial_failure_prefix,
        }
        if return_code != 0:
            raise RuntimeError(
                f"Zode DeepSWE runtime failed with exit code {return_code}; "
                f"see {output_path}"
            )
