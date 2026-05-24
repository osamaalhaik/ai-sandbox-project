import json
import os
import resource
import signal
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class SandboxRunResult:
    run_id: str
    command: list[str]
    pid: int | None
    started_at: str
    finished_at: str
    duration_seconds: float
    exit_code: int | None
    timed_out: bool
    stdout: str
    stderr: str
    max_cpu_seconds: int
    max_memory_mb: int


class SandboxRunner:
    def __init__(self, output_path: str = "data/raw/sandbox_runs.jsonl"):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

    def run(
        self,
        command: list[str],
        timeout_seconds: int = 10,
        max_cpu_seconds: int = 5,
        max_memory_mb: int = 256,
    ) -> SandboxRunResult:
        run_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = time.time()
        process = None
        stdout = ""
        stderr = ""
        exit_code = None
        timed_out = False

        def limit_resources():
            memory_bytes = max_memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_CPU, (max_cpu_seconds, max_cpu_seconds))
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=limit_resources,
                start_new_session=True,
            )

            try:
                stdout, stderr = process.communicate(timeout=timeout_seconds)
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate()
                exit_code = process.returncode

        except Exception as exc:
            stderr = str(exc)

        finished_at = datetime.now(timezone.utc).isoformat()
        duration_seconds = round(time.time() - start_time, 4)

        result = SandboxRunResult(
            run_id=run_id,
            command=command,
            pid=process.pid if process else None,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=duration_seconds,
            exit_code=exit_code,
            timed_out=timed_out,
            stdout=stdout,
            stderr=stderr,
            max_cpu_seconds=max_cpu_seconds,
            max_memory_mb=max_memory_mb,
        )

        self._store_result(result)
        return result

    def _store_result(self, result: SandboxRunResult) -> None:
        with self.output_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(asdict(result), ensure_ascii=False) + "\n")
