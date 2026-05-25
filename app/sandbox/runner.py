import hashlib
import json
import os
import resource
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from app.monitoring.process_monitor import ProcessMonitor
from app.sandbox.policy import SandboxCommandPolicy


@dataclass
class ResourceLimits:
    timeout_seconds: int
    max_cpu_seconds: int
    max_memory_mb: int
    max_open_files: int


@dataclass
class SandboxRunResult:
    run_id: str
    command: list[str]
    command_hash: str
    working_directory: str
    pid: int | None
    status: str
    failure_reason: str | None
    policy_allowed: bool
    policy_reason: str | None
    monitoring_enabled: bool
    samples_count: int
    samples_output_path: str
    started_at: str
    finished_at: str
    created_at: str
    updated_at: str
    duration_seconds: float
    exit_code: int | None
    timed_out: bool
    killed_by_timeout: bool
    stdout: str
    stderr: str
    resource_limits: ResourceLimits


class SandboxRunner:
    def __init__(
        self,
        output_path: str = "data/raw/sandbox_runs.jsonl",
        samples_output_path: str = "data/raw/process_samples.jsonl",
    ):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.samples_output_path = Path(samples_output_path)
        self.samples_output_path.parent.mkdir(parents=True, exist_ok=True)
        self.command_policy = SandboxCommandPolicy()
        self.process_monitor = ProcessMonitor(output_path=str(self.samples_output_path))

    def run(
        self,
        command: list[str],
        timeout_seconds: int = 10,
        max_cpu_seconds: int = 5,
        max_memory_mb: int = 256,
        max_open_files: int = 64,
        working_directory: str | None = None,
        monitoring_enabled: bool = True,
        monitor_interval_seconds: float = 0.2,
    ) -> SandboxRunResult:
        run_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        started_at = now
        created_at = now
        start_time = time.time()
        process = None
        stdout = ""
        stderr = ""
        exit_code = None
        timed_out = False
        killed_by_timeout = False
        failure_reason = None
        status = "running"
        resolved_working_directory = str(Path(working_directory or os.getcwd()).resolve())
        samples_count = 0
        stop_monitoring = threading.Event()
        monitor_thread = None

        limits = ResourceLimits(
            timeout_seconds=timeout_seconds,
            max_cpu_seconds=max_cpu_seconds,
            max_memory_mb=max_memory_mb,
            max_open_files=max_open_files,
        )

        policy_decision = self.command_policy.validate(command, resolved_working_directory)

        if not policy_decision.allowed:
            finished_at = datetime.now(timezone.utc).isoformat()
            duration_seconds = round(time.time() - start_time, 4)

            result = SandboxRunResult(
                run_id=run_id,
                command=command,
                command_hash=self._hash_command(command),
                working_directory=resolved_working_directory,
                pid=None,
                status="blocked",
                failure_reason="blocked_by_policy",
                policy_allowed=False,
                policy_reason=policy_decision.reason,
                monitoring_enabled=False,
                samples_count=0,
                samples_output_path=str(self.samples_output_path),
                started_at=started_at,
                finished_at=finished_at,
                created_at=created_at,
                updated_at=finished_at,
                duration_seconds=duration_seconds,
                exit_code=None,
                timed_out=False,
                killed_by_timeout=False,
                stdout="",
                stderr=f"blocked_by_policy: {policy_decision.reason}",
                resource_limits=limits,
            )

            self._store_result(result)
            return result

        def limit_resources():
            memory_bytes = max_memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_CPU, (max_cpu_seconds, max_cpu_seconds))
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
            resource.setrlimit(resource.RLIMIT_NOFILE, (max_open_files, max_open_files))

        def collect_samples():
            nonlocal samples_count

            while not stop_monitoring.is_set():
                sample = self.process_monitor.sample(run_id, process.pid)
                samples_count += 1

                if not sample.alive:
                    break

                stop_monitoring.wait(monitor_interval_seconds)

        try:
            process = subprocess.Popen(
                command,
                cwd=resolved_working_directory,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=limit_resources,
                start_new_session=True,
            )

            if monitoring_enabled:
                monitor_thread = threading.Thread(target=collect_samples, daemon=True)
                monitor_thread.start()

            try:
                stdout, stderr = process.communicate(timeout=timeout_seconds)
                exit_code = process.returncode
                status = "completed" if exit_code == 0 else "failed"
                failure_reason = None if exit_code == 0 else "process_exited_with_error"
            except subprocess.TimeoutExpired:
                timed_out = True
                killed_by_timeout = True
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate()
                exit_code = process.returncode
                status = "timed_out"
                failure_reason = "timeout_exceeded"

        except FileNotFoundError as exc:
            stderr = str(exc)
            status = "failed"
            failure_reason = "command_not_found"

        except PermissionError as exc:
            stderr = str(exc)
            status = "failed"
            failure_reason = "permission_denied"

        except Exception as exc:
            stderr = str(exc)
            status = "failed"
            failure_reason = "unexpected_error"

        finally:
            stop_monitoring.set()

            if monitor_thread is not None:
                monitor_thread.join(timeout=2)

        finished_at = datetime.now(timezone.utc).isoformat()
        updated_at = finished_at
        duration_seconds = round(time.time() - start_time, 4)

        result = SandboxRunResult(
            run_id=run_id,
            command=command,
            command_hash=self._hash_command(command),
            working_directory=resolved_working_directory,
            pid=process.pid if process else None,
            status=status,
            failure_reason=failure_reason,
            policy_allowed=True,
            policy_reason=policy_decision.reason,
            monitoring_enabled=monitoring_enabled and process is not None,
            samples_count=samples_count,
            samples_output_path=str(self.samples_output_path),
            started_at=started_at,
            finished_at=finished_at,
            created_at=created_at,
            updated_at=updated_at,
            duration_seconds=duration_seconds,
            exit_code=exit_code,
            timed_out=timed_out,
            killed_by_timeout=killed_by_timeout,
            stdout=stdout,
            stderr=stderr,
            resource_limits=limits,
        )

        self._store_result(result)
        return result

    def _hash_command(self, command: list[str]) -> str:
        normalized = "\0".join(command)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def _store_result(self, result: SandboxRunResult) -> None:
        with self.output_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(asdict(result), ensure_ascii=False) + "\n")
