from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import http.server
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import threading
import urllib.parse
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import tomllib

SCHEMA = "zode.terminal-bench-paired-controller.v1"
QUEUE_SCHEMA = "zode.terminal-bench-paired-queue.v1"
CONTROL_SCHEMA = "zode.terminal-bench-paired-control.v1"
DATASET_VERSION = "terminal-bench-3.0.0"
DATASET_COMMIT = "2b0442c3c583b710ca8da14c8e601b99f2f1f244"
MODEL = "opencode-go/deepseek-v4-flash"
PI_VERSION = "0.73.1"
ATTEMPTS_PER_TASK = 4
MAX_WORKERS = 3
MIN_FREE_BYTES = 12 * 1024**3
SOURCE_EXPORT_EXCLUDES = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    "node_modules",
    "target",
}
RECORDING_RE = re.compile(
    r"ZODE_DEEPSWE_RECORDING run_id=(\S+) exchanges=(\d+) path=(\S+)"
)


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def parse_time(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as output:
        json.dump(value, output, ensure_ascii=False, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    fsync_directory(path.parent)


def append_jsonl(path: Path, value: Any) -> None:
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.chmod(path, 0o600)


@dataclass(frozen=True)
class TaskSpec:
    index: int
    name: str
    path: Path
    cpus: int
    memory_mb: int
    storage_mb: int
    gpus: int

    @property
    def pair_cpus(self) -> int:
        return self.cpus * 2

    @property
    def pair_memory_mb(self) -> int:
        return self.memory_mb * 2

    def queue_value(self) -> dict[str, Any]:
        return {
            "task": self.name,
            "task_index": self.index,
            "cpus_each": self.cpus,
            "memory_mb_each": self.memory_mb,
            "storage_mb_each": self.storage_mb,
            "gpus_each": self.gpus,
            "pair_cpus": self.pair_cpus,
            "pair_memory_mb": self.pair_memory_mb,
        }


def load_tasks(root: Path) -> list[TaskSpec]:
    tasks = []
    for index, path in enumerate(
        sorted(item for item in root.iterdir() if item.is_dir()), 1
    ):
        with (path / "task.toml").open("rb") as source:
            value = tomllib.load(source)
        environment = value.get("environment") or {}
        tasks.append(
            TaskSpec(
                index=index,
                name=path.name,
                path=path,
                cpus=int(environment.get("cpus", 1)),
                memory_mb=int(environment.get("memory_mb", 2048)),
                storage_mb=int(environment.get("storage_mb", 10240)),
                gpus=int(environment.get("gpus", 0)),
            )
        )
    if len(tasks) != 74:
        raise RuntimeError(
            f"Terminal-Bench 3.0 corpus must contain 74 tasks, found {len(tasks)}"
        )
    return tasks


def child_trial_result(job_dir: Path) -> Path:
    matches = [
        path
        for path in job_dir.glob("*/result.json")
        if path.parent != job_dir and path.is_file()
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one trial result under {job_dir}, found {len(matches)}"
        )
    return matches[0]


def verifier_summary(trial_root: Path) -> dict[str, Any] | None:
    path = trial_root / "verifier" / "ctrf.json"
    if not path.is_file():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    tests = (value.get("results") or {}).get("tests")
    if not isinstance(tests, list):
        return None
    passed = sum(test.get("status") == "passed" for test in tests)
    failed = [
        str(test.get("name"))
        for test in tests
        if test.get("status") not in {"passed", "skipped"}
    ]
    return {
        "passed": passed,
        "total": len(tests),
        "pass_fraction": passed / len(tests) if tests else None,
        "failed": failed,
    }


def token_usage(recording_path: Path) -> dict[str, int]:
    recording = json.loads(recording_path.read_text(encoding="utf-8"))
    requests = recording.get("requests")
    if recording.get("schema") != "zode.llm-http-recording.v1" or not isinstance(
        requests, list
    ):
        raise RuntimeError("provider recording envelope is invalid")
    totals = {
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "cache_hit_tokens": 0,
        "cache_miss_tokens": 0,
    }
    usage_records = 0
    for request in requests:
        response = request.get("response") or {}
        chunks = response.get("chunks") or []
        body = b"".join(bytes.fromhex(chunk["bytes_hex"]) for chunk in chunks)
        request_usage: dict[str, Any] | None = None
        for line in body.decode("utf-8", errors="replace").splitlines():
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if not payload or payload == "[DONE]":
                continue
            try:
                value = json.loads(payload)
            except json.JSONDecodeError:
                continue
            candidate = value.get("usage")
            if isinstance(candidate, dict):
                request_usage = candidate
        if request_usage is None:
            continue
        usage_records += 1
        totals["input_tokens"] += int(
            request_usage.get("prompt_tokens", request_usage.get("input_tokens", 0))
            or 0
        )
        totals["output_tokens"] += int(
            request_usage.get(
                "completion_tokens", request_usage.get("output_tokens", 0)
            )
            or 0
        )
        totals["total_tokens"] += int(request_usage.get("total_tokens", 0) or 0)
        totals["cache_hit_tokens"] += int(
            request_usage.get("prompt_cache_hit_tokens", 0) or 0
        )
        totals["cache_miss_tokens"] += int(
            request_usage.get("prompt_cache_miss_tokens", 0) or 0
        )
    if usage_records != len(requests):
        raise RuntimeError(
            f"provider usage missing: requests={len(requests)} usage={usage_records}"
        )
    if totals["total_tokens"] == 0:
        totals["total_tokens"] = totals["input_tokens"] + totals["output_tokens"]
    totals["provider_exchanges"] = len(requests)
    return totals


def archive_recording(source: Path, destination: Path) -> dict[str, Any]:
    manifest = source / "recording.json"
    if not manifest.is_file() or stat.S_IMODE(manifest.stat().st_mode) != 0o600:
        raise RuntimeError("provider recording is missing or has unsafe permissions")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    tar = subprocess.Popen(
        ["/usr/bin/tar", "-C", str(source.parent), "-cf", "-", source.name],
        stdout=subprocess.PIPE,
    )
    assert tar.stdout is not None
    zstd = subprocess.run(
        ["/opt/homebrew/bin/zstd", "-T0", "-3", "-q", "-o", str(temporary)],
        stdin=tar.stdout,
        check=False,
    )
    tar.stdout.close()
    tar_return = tar.wait()
    if tar_return != 0 or zstd.returncode != 0:
        temporary.unlink(missing_ok=True)
        raise RuntimeError("provider recording archive failed")
    os.chmod(temporary, 0o600)
    with temporary.open("rb") as archived:
        os.fsync(archived.fileno())
    temporary.replace(destination)
    fsync_directory(destination.parent)
    check = subprocess.run(
        ["/opt/homebrew/bin/zstd", "-q", "-t", str(destination)], check=False
    )
    if check.returncode != 0:
        raise RuntimeError("provider recording archive verification failed")
    value = {
        "path": str(destination),
        "bytes": destination.stat().st_size,
        "sha256": sha256(destination),
    }
    return value


class QueueStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.path = root / "queue.json"
        self.lock_path = root / "queue.lock"
        self.thread_lock = threading.RLock()

    def _locked(self, exclusive: bool) -> tuple[Any, dict[str, Any]]:
        self.lock_path.touch(mode=0o600, exist_ok=True)
        lock = self.lock_path.open("r+")
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        value = json.loads(self.path.read_text(encoding="utf-8"))
        if value.get("schema") != QUEUE_SCHEMA:
            lock.close()
            raise RuntimeError("benchmark queue schema mismatch")
        return lock, value

    def read(self) -> dict[str, Any]:
        with self.thread_lock:
            lock, value = self._locked(False)
            try:
                return value
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                lock.close()

    def mutate(self, mutation: Any) -> Any:
        with self.thread_lock:
            lock, value = self._locked(True)
            try:
                result = mutation(value)
                value["updated_at"] = now()
                atomic_json(self.path, value)
                return result
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                lock.close()


class _ControlServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], controller: Controller) -> None:
        self.controller = controller
        super().__init__(address, _ControlHandler)


class _ControlHandler(http.server.BaseHTTPRequestHandler):
    server: _ControlServer
    server_version = "ZodeTerminalBenchControl/1"
    sys_version = ""

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def send_json(self, status: int, value: Any) -> None:
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/v1/health":
            self.send_json(200, {"ok": True})
        elif path == "/v1/status":
            self.send_json(200, self.server.controller.status())
        else:
            self.send_json(404, {"error": "not_found"})

    def do_PATCH(self) -> None:
        if urllib.parse.urlsplit(self.path).path != "/v1/control":
            self.send_json(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 4096:
                raise ValueError("control body must be between 1 and 4096 bytes")
            value = json.loads(self.rfile.read(length))
            result = self.server.controller.update_control(value)
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": "invalid_control", "message": str(error)})
            return
        self.send_json(200, {"schema": CONTROL_SCHEMA, "control": result})


class Controller:
    def __init__(self, run_root: Path) -> None:
        self.run_root = run_root.resolve()
        self.config_path = self.run_root / "config.json"
        self.config = json.loads(self.config_path.read_text(encoding="utf-8"))
        if self.config.get("schema") != SCHEMA:
            raise RuntimeError("benchmark controller config schema mismatch")
        self.tasks_root = Path(self.config["tasks_root"])
        self.zode_root = Path(self.config["zode_root"])
        self.auth_file = Path(self.config["auth_file"])
        self.pi_runtime_root = Path(self.config["pi_runtime_root"])
        self.harbor = Path(self.config["harbor"])
        self.jobs_root = self.run_root / "jobs"
        self.logs_root = self.run_root / "logs"
        self.recordings_root = self.run_root / "recordings"
        self.results_path = self.run_root / "results.jsonl"
        self.comparisons_root = self.run_root / "comparisons"
        self.state_path = self.run_root / "state.json"
        self.store = QueueStore(self.run_root)
        self.results_lock = threading.Lock()
        self.tasks = load_tasks(self.tasks_root)
        self.tasks_by_name = {task.name: task for task in self.tasks}
        self.stop = threading.Event()
        self.state_lock = threading.Lock()
        self.state: dict[str, Any] = {
            "schema": SCHEMA,
            "started_at": now(),
            "updated_at": now(),
            "active_processes": {},
            "latest_pair": None,
        }
        self.api: _ControlServer | None = None
        self.api_thread: threading.Thread | None = None
        self._assert_environment()

    def _assert_environment(self) -> None:
        if (
            not self.auth_file.is_file()
            or stat.S_IMODE(self.auth_file.stat().st_mode) != 0o600
        ):
            raise RuntimeError("benchmark auth file is missing or not 0600")
        if not self.harbor.is_file():
            raise RuntimeError("Harbor executable is unavailable")
        if (
            not (self.pi_runtime_root / "bin" / "node").is_file()
            or not (self.pi_runtime_root / "bin" / "pi").exists()
        ):
            raise RuntimeError("pinned Pi runtime is unavailable")
        if (
            sha256(self.pi_runtime_root / "bin" / "node")
            != self.config["pi_runtime_node_sha256"]
            or sha256(self.pi_runtime_root / "bin" / "pi")
            != self.config["pi_runtime_cli_sha256"]
        ):
            raise RuntimeError("pinned Pi runtime changed")
        if (self.zode_root / ".git").exists():
            revision = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.zode_root,
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip()
            if revision != self.config["zode_revision"]:
                raise RuntimeError("Zode benchmark source revision changed")
        current_fingerprint = self.source_fingerprint(self.zode_root)
        if current_fingerprint != self.config["source_fingerprint"]:
            raise RuntimeError("Zode benchmark source tree changed")

    @staticmethod
    def source_fingerprint(root: Path) -> str:
        if not (root / ".git").exists():
            digest = hashlib.sha256()
            for path in sorted(
                (
                    path
                    for path in root.rglob("*")
                    if path.is_file()
                    and not set(path.relative_to(root).parts) & SOURCE_EXPORT_EXCLUDES
                ),
                key=lambda path: path.relative_to(root).as_posix(),
            ):
                relative = path.relative_to(root).as_posix()
                digest.update(relative.encode())
                digest.update(b"\0")
                with path.open("rb") as source:
                    while chunk := source.read(1024 * 1024):
                        digest.update(chunk)
                digest.update(b"\0")
            return digest.hexdigest()
        status = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=root,
            capture_output=True,
            check=True,
        ).stdout
        diff = subprocess.run(
            ["git", "diff", "--binary", "HEAD"],
            cwd=root,
            capture_output=True,
            check=True,
        ).stdout
        digest = hashlib.sha256()
        digest.update(status)
        digest.update(b"\0")
        digest.update(diff)
        for line in status.decode(errors="replace").splitlines():
            if line.startswith("?? "):
                path = root / line[3:]
                if path.is_file():
                    digest.update(line[3:].encode())
                    digest.update(b"\0")
                    digest.update(path.read_bytes())
        return digest.hexdigest()

    def persist_state(self) -> None:
        with self.state_lock:
            self.state["updated_at"] = now()
            atomic_json(self.state_path, self.state)

    def status(self) -> dict[str, Any]:
        queue = self.store.read()
        completed_pairs = sum(
            1
            for path in self.comparisons_root.glob("*/attempt-*.json")
            if path.is_file()
        )
        with self.state_lock:
            state = json.loads(json.dumps(self.state))
        return {
            "schema": CONTROL_SCHEMA,
            "dataset": DATASET_VERSION,
            "model": MODEL,
            "completed_pairs": completed_pairs,
            "target_pairs": int(queue["target_tasks"]) * ATTEMPTS_PER_TASK,
            "corpus_pairs": len(self.tasks) * ATTEMPTS_PER_TASK,
            "queue": queue,
            "controller": state,
        }

    def update_control(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise TypeError("control body must be an object")
        allowed = {
            "paused",
            "max_groups",
            "capacity_cpus",
            "capacity_memory_mb",
            "retry_lanes",
            "hold_tasks",
            "release_tasks",
        }
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown control fields: {sorted(unknown)}")
        if "paused" in value and not isinstance(value["paused"], bool):
            raise ValueError("paused must be boolean")
        if "max_groups" in value and (
            isinstance(value["max_groups"], bool)
            or not isinstance(value["max_groups"], int)
            or not 1 <= value["max_groups"] <= MAX_WORKERS
        ):
            raise ValueError("max_groups must be an integer from 1 through 3")
        for field in ("capacity_cpus", "capacity_memory_mb"):
            if field in value and (
                isinstance(value[field], bool)
                or not isinstance(value[field], int)
                or value[field] < 1
            ):
                raise ValueError(f"{field} must be a positive integer")
        retry_lanes = value.get("retry_lanes", [])
        if (
            not isinstance(retry_lanes, list)
            or any(
                isinstance(lane, bool)
                or not isinstance(lane, int)
                or not 1 <= lane <= MAX_WORKERS
                for lane in retry_lanes
            )
            or len(set(retry_lanes)) != len(retry_lanes)
        ):
            raise ValueError("retry_lanes must contain unique lane numbers 1 through 3")
        hold_tasks = value.get("hold_tasks", [])
        release_tasks = value.get("release_tasks", [])
        for field, tasks in (
            ("hold_tasks", hold_tasks),
            ("release_tasks", release_tasks),
        ):
            if (
                not isinstance(tasks, list)
                or any(not isinstance(task, str) or not task for task in tasks)
                or len(set(tasks)) != len(tasks)
            ):
                raise ValueError(f"{field} must contain unique non-empty task names")
        if set(hold_tasks) & set(release_tasks):
            raise ValueError("a task cannot be held and released in one request")

        def mutation(queue: dict[str, Any]) -> dict[str, Any]:
            for field in allowed - {"retry_lanes", "hold_tasks", "release_tasks"}:
                if field in value:
                    queue["control"][field] = value[field]
            for lane in retry_lanes:
                lease = queue["leases"].get(str(lane))
                if lease is None or lease.get("attention") is None:
                    raise ValueError(f"lane {lane} has no failed pair to retry")
                if lease.get("active_pair") is not None:
                    raise ValueError(f"lane {lane} still has an active pair")
                lease["attention"] = None
            held_tasks = queue.setdefault("held_tasks", {})
            for task in hold_tasks:
                pending_index = next(
                    (
                        index
                        for index, entry in enumerate(queue["pending"])
                        if entry["task"] == task
                    ),
                    None,
                )
                if pending_index is None:
                    raise ValueError(f"task {task} is not pending")
                held_tasks[task] = queue["pending"].pop(pending_index)
            for task in reversed(release_tasks):
                entry = held_tasks.pop(task, None)
                if entry is None:
                    raise ValueError(f"task {task} is not held")
                queue["pending"].insert(0, entry)
            queue["control"]["changed_at"] = now()
            return dict(queue["control"])

        return self.store.mutate(mutation)

    def start_api(self) -> str:
        self.api = _ControlServer(("127.0.0.1", int(self.config["api_port"])), self)
        self.api_thread = threading.Thread(
            target=self.api.serve_forever, name="tb3-control-api", daemon=True
        )
        self.api_thread.start()
        host, port = self.api.server_address
        return f"http://{host}:{port}"

    def close_api(self) -> None:
        if self.api is None:
            return
        self.api.shutdown()
        if self.api_thread is not None:
            self.api_thread.join(timeout=30)
        self.api.server_close()

    @staticmethod
    def _active_resources(queue: dict[str, Any]) -> tuple[int, int, int]:
        active = [
            lease["active_pair"]
            for lease in queue["leases"].values()
            if lease.get("active_pair") is not None
        ]
        return (
            len(active),
            sum(int(pair["pair_cpus"]) for pair in active),
            sum(int(pair["pair_memory_mb"]) for pair in active),
        )

    def claim_task(self, lane: int) -> dict[str, Any] | None:
        def mutation(queue: dict[str, Any]) -> dict[str, Any] | None:
            lane_key = str(lane)
            if lane_key in queue["leases"]:
                return dict(queue["leases"][lane_key])
            if queue["control"]["paused"]:
                return None
            pending = queue["pending"]
            if not pending:
                return None
            control = queue["control"]
            selected = next(
                (
                    index
                    for index, entry in enumerate(pending)
                    if int(entry["pair_cpus"]) <= int(control["capacity_cpus"])
                    and int(entry["pair_memory_mb"])
                    <= int(control["capacity_memory_mb"])
                ),
                None,
            )
            if selected is None:
                return None
            entry = pending.pop(selected)
            lease = {
                **entry,
                "lane": lane,
                "leased_at": now(),
                "completed_attempts": [],
                "active_pair": None,
                "attention": None,
            }
            queue["leases"][lane_key] = lease
            return dict(lease)

        return self.store.mutate(mutation)

    def begin_pair(self, lane: int) -> dict[str, Any] | None:
        def mutation(queue: dict[str, Any]) -> dict[str, Any] | None:
            control = queue["control"]
            if control["paused"]:
                return None
            lease = queue["leases"].get(str(lane))
            if lease is None or lease.get("attention") is not None:
                return None
            if lease.get("active_pair") is not None:
                return dict(lease["active_pair"])
            completed = {int(value) for value in lease["completed_attempts"]}
            missing = [
                attempt
                for attempt in range(1, ATTEMPTS_PER_TASK + 1)
                if attempt not in completed
            ]
            if not missing:
                return None
            groups, cpus, memory = self._active_resources(queue)
            pair_cpus = int(lease["pair_cpus"])
            pair_memory = int(lease["pair_memory_mb"])
            if (
                groups >= int(control["max_groups"])
                or cpus + pair_cpus > int(control["capacity_cpus"])
                or memory + pair_memory > int(control["capacity_memory_mb"])
            ):
                return None
            attempt = missing[0]
            run_suffix = uuid.uuid4().hex[:10]
            active = {
                "attempt": attempt,
                "started_at": now(),
                "pair_cpus": pair_cpus,
                "pair_memory_mb": pair_memory,
                "jobs": {
                    "zode": f"tb3-{lease['task']}-a{attempt}-zode-{run_suffix}",
                    "pi": f"tb3-{lease['task']}-a{attempt}-pi-{run_suffix}",
                },
            }
            lease["active_pair"] = active
            return dict(active)

        return self.store.mutate(mutation)

    def finish_pair(self, lane: int, pair_result: dict[str, Any]) -> None:
        attempt = int(pair_result["attempt"])
        result_path = (
            self.comparisons_root / str(pair_result["task"]) / f"attempt-{attempt}.json"
        )
        result_path.parent.mkdir(parents=True, exist_ok=True)
        with self.results_lock:
            if result_path.exists():
                existing = json.loads(result_path.read_text(encoding="utf-8"))
                if existing != pair_result:
                    raise RuntimeError(
                        "paired result conflicts with its durable result"
                    )
            else:
                atomic_json(result_path, pair_result)
            ledger_key = (str(pair_result["task"]), attempt)
            existing_keys: set[tuple[str, int]] = set()
            if self.results_path.is_file():
                existing_keys = {
                    (str(value["task"]), int(value["attempt"]))
                    for value in (
                        json.loads(line)
                        for line in self.results_path.read_text(
                            encoding="utf-8"
                        ).splitlines()
                        if line
                    )
                }
            if ledger_key not in existing_keys:
                append_jsonl(self.results_path, pair_result)

        def mutation(queue: dict[str, Any]) -> None:
            lease = queue["leases"].get(str(lane))
            if lease is None:
                raise RuntimeError("benchmark pair lease disappeared during analysis")
            if attempt in {int(value) for value in lease["completed_attempts"]}:
                return
            if lease.get("active_pair", {}).get("attempt") != attempt:
                raise RuntimeError("benchmark pair ownership changed during analysis")
            lease["completed_attempts"].append(attempt)
            lease["active_pair"] = None

        self.store.mutate(mutation)
        recording_source = pair_result["zode"].get("recording_source")
        if isinstance(recording_source, str):
            source = Path(recording_source)
            if source.is_dir():
                shutil.rmtree(source)
        with self.state_lock:
            self.state["latest_pair"] = pair_result
            self.state["active_processes"].pop(str(lane), None)
        self.persist_state()

    def mark_attention(self, lane: int, reason: str) -> None:
        safe_reason = reason[:4000]

        def mutation(queue: dict[str, Any]) -> None:
            lease = queue["leases"].get(str(lane))
            if lease is not None:
                lease["attention"] = {"at": now(), "reason": safe_reason}
                lease["active_pair"] = None
            queue["control"]["paused"] = True
            queue["control"]["pause_reason"] = safe_reason
            queue["control"]["changed_at"] = now()

        self.store.mutate(mutation)
        with self.state_lock:
            self.state["active_processes"].pop(str(lane), None)
        self.persist_state()

    def release_completed_task(self, lane: int) -> dict[str, Any]:
        def mutation(queue: dict[str, Any]) -> dict[str, Any]:
            lease = queue["leases"].get(str(lane))
            if lease is None:
                raise RuntimeError("completed benchmark lease is missing")
            if lease.get("active_pair") is not None or sorted(
                int(value) for value in lease["completed_attempts"]
            ) != list(range(1, ATTEMPTS_PER_TASK + 1)):
                raise RuntimeError("benchmark task is not complete")
            task_summary = self.task_summary(str(lease["task"]))
            queue["completed_tasks"].append(task_summary)
            del queue["leases"][str(lane)]
            return task_summary

        summary = self.store.mutate(mutation)
        destination = self.comparisons_root / str(summary["task"]) / "summary.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(destination, summary)
        return summary

    def task_summary(self, task_name: str) -> dict[str, Any]:
        pairs = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in (self.comparisons_root / task_name).glob("attempt-*.json")
        ]
        pairs.sort(key=lambda value: int(value["attempt"]))
        if len(pairs) != ATTEMPTS_PER_TASK:
            raise RuntimeError(
                f"task summary requires four paired attempts: {task_name}"
            )

        def agent_values(agent: str, field: str) -> list[float]:
            return [float(pair[agent][field]) for pair in pairs]

        zode_rewards = agent_values("zode", "reward")
        pi_rewards = agent_values("pi", "reward")
        return {
            "task": task_name,
            "completed_at": now(),
            "attempts": [pair["attempt"] for pair in pairs],
            "zode": {
                "rewards": zode_rewards,
                "pass_rate": sum(zode_rewards) / ATTEMPTS_PER_TASK,
                "duration_seconds": agent_values("zode", "duration_seconds"),
                "input_tokens": agent_values("zode", "input_tokens"),
                "output_tokens": agent_values("zode", "output_tokens"),
                "total_tokens": agent_values("zode", "total_tokens"),
            },
            "pi": {
                "rewards": pi_rewards,
                "pass_rate": sum(pi_rewards) / ATTEMPTS_PER_TASK,
                "duration_seconds": agent_values("pi", "duration_seconds"),
                "input_tokens": agent_values("pi", "input_tokens"),
                "output_tokens": agent_values("pi", "output_tokens"),
                "total_tokens": agent_values("pi", "total_tokens"),
            },
            "delta": {
                "pass_rate": (sum(zode_rewards) - sum(pi_rewards)) / ATTEMPTS_PER_TASK,
                "mean_duration_seconds": (
                    sum(agent_values("zode", "duration_seconds"))
                    - sum(agent_values("pi", "duration_seconds"))
                )
                / ATTEMPTS_PER_TASK,
                "mean_total_tokens": (
                    sum(agent_values("zode", "total_tokens"))
                    - sum(agent_values("pi", "total_tokens"))
                )
                / ATTEMPTS_PER_TASK,
            },
        }

    def _base_command(self, job_name: str, task: TaskSpec) -> list[str]:
        return [
            str(self.harbor),
            "run",
            "--job-name",
            job_name,
            "--jobs-dir",
            str(self.jobs_root),
            "--n-attempts",
            "1",
            "--n-concurrent",
            "1",
            "--max-retries",
            "0",
            "--path",
            str(task.path),
            "--model",
            MODEL,
            "--cpus",
            "limit",
            "--memory",
            "limit",
            "--yes",
        ]

    def _agent_command(self, agent: str, job_name: str, task: TaskSpec) -> list[str]:
        command = self._base_command(job_name, task)
        if agent == "zode":
            command.extend(
                [
                    "--agent",
                    "terminal_bench_pier_agent:ZodeTerminalBenchAgent",
                    "--agent-kwarg",
                    f"zode_root={self.zode_root}",
                    "--agent-kwarg",
                    f"auth_file={self.auth_file}",
                ]
            )
        elif agent == "pi":
            mounts = json.dumps(
                [
                    {
                        "type": "bind",
                        "source": str(self.auth_file),
                        "target": "/run/zode-benchmark/opencode-auth.json",
                        "read_only": True,
                    },
                    {
                        "type": "bind",
                        "source": str(self.pi_runtime_root),
                        "target": "/opt/zode-pi-runtime",
                        "read_only": True,
                    },
                ],
                separators=(",", ":"),
            )
            command.extend(
                [
                    "--agent",
                    "terminal_bench_pi_agent:PiTerminalBenchAgent",
                    "--agent-kwarg",
                    f"version={PI_VERSION}",
                    "--mounts",
                    mounts,
                    "--allow-agent-host",
                    "opencode.ai",
                ]
            )
        else:
            raise ValueError(f"unknown benchmark agent: {agent}")
        return command

    def _environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": "/Users/zuozijian/.local/bin:/opt/homebrew/bin:/usr/bin:/bin",
                "PYTHONPATH": str(self.zode_root / "tests"),
                "PYTHONUNBUFFERED": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "DOCKER_CONFIG": "/private/tmp/zode-tb3-docker-config",
                "DOCKER_HOST": "unix:///Users/zuozijian/.orbstack/run/docker.sock",
                "CARGO_TARGET_DIR": (
                    f"/private/tmp/zode-tb3-target-{self.config['zode_revision'][:12]}"
                ),
            }
        )
        return environment

    def run_pair_processes(
        self, lane: int, task: TaskSpec, active: dict[str, Any]
    ) -> dict[str, Path]:
        if shutil.disk_usage(self.run_root).free < MIN_FREE_BYTES:
            raise RuntimeError("shared benchmark disk reached its safety floor")
        jobs = active["jobs"]
        processes: dict[str, subprocess.Popen[bytes]] = {}
        logs: dict[str, Any] = {}
        try:
            for agent in ("zode", "pi"):
                job_name = str(jobs[agent])
                job_dir = self.jobs_root / job_name
                log_path = self.logs_root / f"{job_name}.log"
                if job_dir.exists() or log_path.exists():
                    raise RuntimeError(
                        f"benchmark job output already exists: {job_name}"
                    )
                log = log_path.open("xb")
                os.chmod(log_path, 0o600)
                logs[agent] = log
                processes[agent] = subprocess.Popen(
                    self._agent_command(agent, job_name, task),
                    cwd=self.zode_root,
                    env=self._environment(),
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            with self.state_lock:
                self.state["active_processes"][str(lane)] = {
                    "task": task.name,
                    "attempt": active["attempt"],
                    "started_at": active["started_at"],
                    "jobs": jobs,
                    "pids": {
                        agent: process.pid for agent, process in processes.items()
                    },
                }
            self.persist_state()
            return_codes: dict[str, int] = {}
            while len(return_codes) != len(processes):
                for agent, process in processes.items():
                    if agent in return_codes:
                        continue
                    code = process.poll()
                    if code is None:
                        continue
                    return_codes[agent] = code
                    with self.state_lock:
                        active_state = self.state["active_processes"].get(str(lane))
                        if active_state is not None:
                            active_state.setdefault("finished", {})[agent] = {
                                "at": now(),
                                "return_code": code,
                            }
                    self.persist_state()
                if (
                    any(code != 0 for code in return_codes.values())
                    or self.stop.is_set()
                ):
                    for agent, process in processes.items():
                        if agent in return_codes or process.poll() is not None:
                            continue
                        try:
                            os.killpg(process.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                    for agent, process in processes.items():
                        if agent in return_codes:
                            continue
                        try:
                            return_codes[agent] = process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            try:
                                os.killpg(process.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            return_codes[agent] = process.wait()
                    break
                self.stop.wait(0.5)
        finally:
            for log in logs.values():
                log.close()
        failed = {agent: code for agent, code in return_codes.items() if code != 0}
        if failed:
            raise RuntimeError(f"paired Harbor process failed: {failed}")
        return {agent: self.jobs_root / str(jobs[agent]) for agent in jobs}

    def _scan_pi_session(self, trial_root: Path) -> dict[str, Any]:
        session_root = trial_root / "agent" / "pi" / "sessions"
        files = sorted(path for path in session_root.rglob("*") if path.is_file())
        if not files:
            raise RuntimeError("Pi native session record is missing")
        auth = json.loads(self.auth_file.read_text(encoding="utf-8"))
        provider_key = auth.get("opencode-go", {}).get("key")
        if not isinstance(provider_key, str) or not provider_key:
            raise RuntimeError("OpenCode Go benchmark credential is unavailable")
        digest = hashlib.sha256()
        total_bytes = 0
        usage = {
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "cache_hit_tokens": 0,
            "cache_miss_tokens": 0,
        }
        assistant_messages = 0
        for path in files:
            raw = path.read_bytes()
            if provider_key.encode() in raw:
                raise RuntimeError("provider credential reached Pi session record")
            relative = path.relative_to(session_root).as_posix()
            digest.update(relative.encode())
            digest.update(b"\0")
            digest.update(raw)
            total_bytes += len(raw)
            for line in raw.splitlines():
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                message = value.get("message")
                if not isinstance(message, dict) or message.get("role") != "assistant":
                    continue
                message_usage = message.get("usage")
                if not isinstance(message_usage, dict):
                    continue
                assistant_messages += 1
                uncached_input = int(message_usage.get("input", 0) or 0)
                cache_read = int(message_usage.get("cacheRead", 0) or 0)
                output = int(message_usage.get("output", 0) or 0)
                usage["input_tokens"] += uncached_input + cache_read
                usage["output_tokens"] += output
                usage["total_tokens"] += uncached_input + cache_read + output
                usage["cache_hit_tokens"] += cache_read
                usage["cache_miss_tokens"] += uncached_input
        if assistant_messages == 0:
            raise RuntimeError("Pi native session contains no assistant usage")
        return {
            "path": str(session_root),
            "files": len(files),
            "bytes": total_bytes,
            "sha256": digest.hexdigest(),
            "assistant_messages": assistant_messages,
            "usage": usage,
        }

    def analyze_agent(
        self,
        *,
        agent_name: str,
        task: TaskSpec,
        attempt: int,
        job_dir: Path,
    ) -> dict[str, Any]:
        trial_path = child_trial_result(job_dir)
        trial = json.loads(trial_path.read_text(encoding="utf-8"))
        if trial.get("exception_info") is not None:
            raise RuntimeError(
                f"{agent_name} trial exception: {trial['exception_info']}"
            )
        rewards = (trial.get("verifier_result") or {}).get("rewards") or {}
        reward = rewards.get("reward")
        if not isinstance(reward, (int, float)):
            raise TypeError(f"{agent_name} verifier reward is missing")
        agent_result = trial.get("agent_result") or {}
        metadata = agent_result.get("metadata") or {}
        if metadata.get("benchmark_completed") is not True:
            raise RuntimeError(f"{agent_name} benchmark completion marker is missing")
        execution = trial.get("agent_execution") or {}
        started = execution.get("started_at")
        finished = execution.get("finished_at")
        if not isinstance(started, str) or not isinstance(finished, str):
            raise TypeError(f"{agent_name} execution timestamps are missing")
        duration = (parse_time(finished) - parse_time(started)).total_seconds()
        result: dict[str, Any] = {
            "agent": agent_name,
            "reward": float(reward),
            "rewards": rewards,
            "duration_seconds": duration,
            "job_dir": str(job_dir),
            "trial_result": str(trial_path),
            "verifier": verifier_summary(trial_path.parent),
        }
        if agent_name == "zode":
            log_path = Path(str(metadata.get("zode_log", "")))
            if not log_path.is_file():
                raise RuntimeError("Zode benchmark log is missing")
            log_text = log_path.read_text(encoding="utf-8", errors="replace")
            matches = RECORDING_RE.findall(log_text)
            if len(matches) != 1 or "ZODE_DEEPSWE_COMPLETE" not in log_text:
                raise RuntimeError(
                    "Zode durable completion or recording marker is missing"
                )
            run_id, exchange_text, recording_text = matches[0]
            recording_root = Path(recording_text)
            recording_path = recording_root / "recording.json"
            usage = token_usage(recording_path)
            if usage["provider_exchanges"] != int(exchange_text):
                raise RuntimeError("Zode provider exchange count is inconsistent")
            archive = archive_recording(
                recording_root,
                self.recordings_root
                / task.name
                / f"attempt-{attempt}"
                / "zode.tar.zst",
            )
            result.update(usage)
            result.update(
                {
                    "run_id": run_id,
                    "recording": archive,
                    "recording_source": str(recording_root),
                }
            )
        elif agent_name == "pi":
            session = self._scan_pi_session(trial_path.parent)
            usage = session.pop("usage")
            result.update(
                {
                    **usage,
                    "provider_exchanges": session["assistant_messages"],
                    "session": session,
                }
            )
        else:
            raise ValueError(f"unknown benchmark agent: {agent_name}")
        return result

    def analyze_pair(
        self,
        lane: int,
        task: TaskSpec,
        active: dict[str, Any],
        job_dirs: dict[str, Path],
    ) -> dict[str, Any]:
        attempt = int(active["attempt"])
        zode = self.analyze_agent(
            agent_name="zode", task=task, attempt=attempt, job_dir=job_dirs["zode"]
        )
        pi = self.analyze_agent(
            agent_name="pi", task=task, attempt=attempt, job_dir=job_dirs["pi"]
        )
        verifier_delta = None
        if zode["verifier"] is not None and pi["verifier"] is not None:
            verifier_delta = zode["verifier"]["passed"] - pi["verifier"]["passed"]
        return {
            "schema": "zode.terminal-bench-paired-result.v1",
            "completed_at": now(),
            "dataset": DATASET_VERSION,
            "dataset_commit": DATASET_COMMIT,
            "model": MODEL,
            "zode_revision": self.config["zode_revision"],
            "source_fingerprint": self.config["source_fingerprint"],
            "lane": lane,
            "task": task.name,
            "task_index": task.index,
            "attempt": attempt,
            "resources": task.queue_value(),
            "zode": zode,
            "pi": pi,
            "delta": {
                "reward": zode["reward"] - pi["reward"],
                "duration_seconds": zode["duration_seconds"] - pi["duration_seconds"],
                "total_tokens": zode["total_tokens"] - pi["total_tokens"],
                "verifier_passed": verifier_delta,
            },
        }

    def _pair_result_path(self, task: str, attempt: int) -> Path:
        return self.comparisons_root / task / f"attempt-{attempt}.json"

    def _job_dirs(self, active: dict[str, Any]) -> dict[str, Path]:
        return {
            agent: self.jobs_root / str(job_name)
            for agent, job_name in active["jobs"].items()
        }

    def execute_pair(
        self, lane: int, task: TaskSpec, active: dict[str, Any]
    ) -> dict[str, Any]:
        attempt = int(active["attempt"])
        durable_result = self._pair_result_path(task.name, attempt)
        if durable_result.is_file():
            return json.loads(durable_result.read_text(encoding="utf-8"))
        job_dirs = self._job_dirs(active)
        existing = [path for path in job_dirs.values() if path.exists()]
        if existing:
            completed = all(
                any(
                    path.is_file()
                    for path in job_dir.glob("*/result.json")
                    if path.parent != job_dir
                )
                for job_dir in job_dirs.values()
            )
            if not completed:
                raise RuntimeError(
                    "controller found an incomplete pre-existing paired job; "
                    "manual process-state diagnosis is required"
                )
        else:
            job_dirs = self.run_pair_processes(lane, task, active)
        return self.analyze_pair(lane, task, active, job_dirs)

    def _safe_error(self, error: BaseException) -> str:
        message = f"{type(error).__name__}: {error}"
        try:
            auth = json.loads(self.auth_file.read_text(encoding="utf-8"))
            provider_key = auth.get("opencode-go", {}).get("key")
            if isinstance(provider_key, str) and provider_key:
                message = message.replace(provider_key, "[REDACTED]")
        except (OSError, json.JSONDecodeError, TypeError):
            pass
        return message[:4000]

    @staticmethod
    def _print_event(value: dict[str, Any]) -> None:
        print(json.dumps(value, ensure_ascii=False, separators=(",", ":")), flush=True)

    def worker(self, lane: int) -> None:
        while not self.stop.is_set():
            try:
                queue = self.store.read()
                lease = queue["leases"].get(str(lane))
                if lease is not None and sorted(
                    int(value) for value in lease["completed_attempts"]
                ) == list(range(1, ATTEMPTS_PER_TASK + 1)):
                    summary = self.release_completed_task(lane)
                    self._print_event(
                        {
                            "event": "task_completed",
                            "at": now(),
                            "lane": lane,
                            "task": summary["task"],
                            "zode_pass_rate": summary["zode"]["pass_rate"],
                            "pi_pass_rate": summary["pi"]["pass_rate"],
                            "delta": summary["delta"],
                        }
                    )
                    continue
                if lease is None:
                    lease = self.claim_task(lane)
                    if lease is None:
                        self.stop.wait(1)
                        continue
                active = self.begin_pair(lane)
                if active is None:
                    self.stop.wait(1)
                    continue
                task = self.tasks_by_name[str(lease["task"])]
                pair_result = self.execute_pair(lane, task, active)
                self.finish_pair(lane, pair_result)
                self._print_event(
                    {
                        "event": "pair_completed",
                        "at": now(),
                        "lane": lane,
                        "task": task.name,
                        "attempt": pair_result["attempt"],
                        "zode": {
                            "reward": pair_result["zode"]["reward"],
                            "duration_seconds": pair_result["zode"]["duration_seconds"],
                            "total_tokens": pair_result["zode"]["total_tokens"],
                            "provider_exchanges": pair_result["zode"][
                                "provider_exchanges"
                            ],
                            "verifier": pair_result["zode"]["verifier"],
                        },
                        "pi": {
                            "reward": pair_result["pi"]["reward"],
                            "duration_seconds": pair_result["pi"]["duration_seconds"],
                            "total_tokens": pair_result["pi"]["total_tokens"],
                            "provider_exchanges": pair_result["pi"][
                                "provider_exchanges"
                            ],
                            "verifier": pair_result["pi"]["verifier"],
                        },
                        "delta": pair_result["delta"],
                    }
                )
            except Exception as error:  # noqa: BLE001 - any lane failure must pause new work
                reason = self._safe_error(error)
                failure = {
                    "schema": "zode.terminal-bench-controller-failure.v1",
                    "at": now(),
                    "lane": lane,
                    "reason": reason,
                }
                failure_path = (
                    self.run_root
                    / "failures"
                    / f"{now().replace(':', '-')}-lane-{lane}.json"
                )
                failure_path.parent.mkdir(parents=True, exist_ok=True)
                atomic_json(failure_path, failure)
                self.mark_attention(lane, reason)
                self._print_event({"event": "controller_halted", **failure})
                return

    def run(self) -> None:
        api_url = self.start_api()
        self.persist_state()
        self._print_event(
            {
                "event": "controller_started",
                "at": now(),
                "api": api_url,
                "run_root": str(self.run_root),
            }
        )
        workers = [
            threading.Thread(
                target=self.worker,
                args=(lane,),
                name=f"tb3-paired-lane-{lane}",
                daemon=True,
            )
            for lane in range(1, MAX_WORKERS + 1)
        ]
        for worker in workers:
            worker.start()
        try:
            while not self.stop.wait(1):
                queue = self.store.read()
                if (
                    not queue["pending"]
                    and not queue["leases"]
                    and not queue.get("held_tasks")
                ):
                    self.stop.set()
                    break
                if not any(worker.is_alive() for worker in workers):
                    break
        finally:
            for worker in workers:
                worker.join(timeout=5)
            self.close_api()
            self.persist_state()
            self._print_event(
                {
                    "event": "controller_stopped",
                    "at": now(),
                    "run_root": str(self.run_root),
                }
            )


def initialize_run(args: argparse.Namespace) -> None:
    run_root = args.run_root.resolve()
    if run_root.exists() and any(run_root.iterdir()):
        raise RuntimeError(f"benchmark run root is not empty: {run_root}")
    tasks_root = args.tasks_root.resolve()
    zode_root = args.zode_root.resolve()
    auth_file = args.auth_file.resolve()
    pi_runtime_root = args.pi_runtime_root.resolve()
    harbor = args.harbor.resolve()
    if not auth_file.is_file() or stat.S_IMODE(auth_file.stat().st_mode) != 0o600:
        raise RuntimeError("benchmark auth file is missing or not 0600")
    if not harbor.is_file():
        raise RuntimeError("Harbor executable is unavailable")
    if (
        not (pi_runtime_root / "bin" / "node").is_file()
        or not (pi_runtime_root / "bin" / "pi").exists()
    ):
        raise RuntimeError("pinned Pi runtime is unavailable")
    tasks = load_tasks(tasks_root)
    if (zode_root / ".git").exists():
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=zode_root,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        if args.zode_revision is not None and args.zode_revision != revision:
            raise RuntimeError("explicit Zode revision does not match the worktree")
    elif args.zode_revision is None:
        raise RuntimeError("an exported Zode source tree requires --zode-revision")
    else:
        revision = args.zode_revision
    fingerprint = Controller.source_fingerprint(zode_root)
    unsupported = [task for task in tasks if task.gpus > 0]
    runnable = [task for task in tasks if task.gpus == 0]
    runnable.sort(
        key=lambda task: (
            0 if task.name == "bun-sourcemap-leak" else 1,
            task.pair_cpus,
            task.pair_memory_mb,
            task.index,
        )
    )
    config = {
        "schema": SCHEMA,
        "created_at": now(),
        "dataset": DATASET_VERSION,
        "dataset_commit": DATASET_COMMIT,
        "model": MODEL,
        "pi_version": PI_VERSION,
        "tasks_root": str(tasks_root),
        "zode_root": str(zode_root),
        "auth_file": str(auth_file),
        "pi_runtime_root": str(pi_runtime_root),
        "pi_runtime_node_sha256": sha256(pi_runtime_root / "bin" / "node"),
        "pi_runtime_cli_sha256": sha256(pi_runtime_root / "bin" / "pi"),
        "harbor": str(harbor),
        "api_port": args.api_port,
        "zode_revision": revision,
        "source_fingerprint": fingerprint,
    }
    queue = {
        "schema": QUEUE_SCHEMA,
        "created_at": now(),
        "updated_at": now(),
        "dataset": DATASET_VERSION,
        "dataset_commit": DATASET_COMMIT,
        "model": MODEL,
        "attempts_per_task": ATTEMPTS_PER_TASK,
        "corpus_tasks": len(tasks),
        "target_tasks": len(runnable),
        "control": {
            "paused": args.start_paused,
            "max_groups": args.max_groups,
            "capacity_cpus": args.capacity_cpus,
            "capacity_memory_mb": args.capacity_memory_mb,
            "changed_at": now(),
            "pause_reason": "initialized_paused" if args.start_paused else None,
        },
        "pending": [task.queue_value() for task in runnable],
        "held_tasks": {},
        "leases": {},
        "completed_tasks": [],
        "unsupported": [
            {**task.queue_value(), "reason": "gpu_required"} for task in unsupported
        ],
    }
    run_root.mkdir(parents=True, exist_ok=True)
    os.chmod(run_root, 0o700)
    for name in ("jobs", "logs", "recordings", "comparisons", "failures"):
        path = run_root / name
        path.mkdir()
        os.chmod(path, 0o700)
    atomic_json(run_root / "config.json", config)
    atomic_json(run_root / "queue.json", queue)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run paired Zode/Pi Terminal-Bench 3.0 attempts"
    )
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--initialize", action="store_true")
    parser.add_argument("--initialize-only", action="store_true")
    parser.add_argument("--single-pair", action="store_true")
    parser.add_argument("--tasks-root", type=Path)
    parser.add_argument("--zode-root", type=Path)
    parser.add_argument("--zode-revision")
    parser.add_argument("--auth-file", type=Path)
    parser.add_argument("--pi-runtime-root", type=Path)
    parser.add_argument(
        "--harbor", type=Path, default=Path("/Users/zuozijian/.local/bin/harbor")
    )
    parser.add_argument("--api-port", type=int, default=60914)
    parser.add_argument("--max-groups", type=int, choices=range(1, 4), default=2)
    parser.add_argument("--capacity-cpus", type=int, default=10)
    parser.add_argument("--capacity-memory-mb", type=int, default=28672)
    parser.add_argument("--start-paused", action="store_true")
    args = parser.parse_args()
    if args.initialize and any(
        value is None
        for value in (
            args.tasks_root,
            args.zode_root,
            args.auth_file,
            args.pi_runtime_root,
        )
    ):
        parser.error(
            "--initialize requires --tasks-root, --zode-root, --auth-file, "
            "and --pi-runtime-root"
        )
    if args.initialize_only and not args.initialize:
        parser.error("--initialize-only requires --initialize")
    return args


def main() -> None:
    args = parse_args()
    if args.initialize:
        initialize_run(args)
        if args.initialize_only:
            return
    controller = Controller(args.run_root)

    if args.single_pair:
        controller.update_control({"paused": False, "max_groups": 1})
        lease = controller.claim_task(1)
        if lease is None:
            raise RuntimeError("no benchmark task is available for a single pair")
        active = controller.begin_pair(1)
        if active is None:
            raise RuntimeError("single paired attempt does not fit current capacity")
        task = controller.tasks_by_name[str(lease["task"])]
        result = controller.execute_pair(1, task, active)
        controller.finish_pair(1, result)
        controller._print_event(
            {
                "event": "single_pair_completed",
                "at": now(),
                "task": result["task"],
                "attempt": result["attempt"],
                "zode": {
                    "reward": result["zode"]["reward"],
                    "duration_seconds": result["zode"]["duration_seconds"],
                    "total_tokens": result["zode"]["total_tokens"],
                    "provider_exchanges": result["zode"]["provider_exchanges"],
                    "verifier": result["zode"]["verifier"],
                },
                "pi": {
                    "reward": result["pi"]["reward"],
                    "duration_seconds": result["pi"]["duration_seconds"],
                    "total_tokens": result["pi"]["total_tokens"],
                    "provider_exchanges": result["pi"]["provider_exchanges"],
                    "verifier": result["pi"]["verifier"],
                },
                "delta": result["delta"],
            }
        )
        return

    def stop(_signum: int, _frame: Any) -> None:
        controller.stop.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    controller.run()


if __name__ == "__main__":
    main()
