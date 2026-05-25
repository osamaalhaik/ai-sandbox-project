import json
import os
import signal
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from app.tracing.strace_parser import StraceParser


@dataclass
class StraceRunResult:
    run_id: str
    command: list[str]
    started_at: str
    finished_at: str
    duration_seconds: float
    exit_code: int | None
    timed_out: bool
    stdout: str
    stderr: str
    trace_log_path: str
    events_count: int
    unique_syscalls_count: int
    category_counts: dict[str, int]


class StraceRunner:
    def __init__(
        self,
        traces_dir: str = "data/raw/strace",
        runs_output_path: str = "data/raw/strace_runs.jsonl",
        events_output_path: str = "data/raw/syscall_events.jsonl",
    ):
        self.traces_dir = Path(traces_dir)
        self.traces_dir.mkdir(parents=True, exist_ok=True)
        self.runs_output_path = Path(runs_output_path)
        self.runs_output_path.parent.mkdir(parents=True, exist_ok=True)
        self.parser = StraceParser(output_path=events_output_path)

    def run(
        self,
        command: list[str],
        timeout_seconds: int = 10,
        working_directory: str | None = None,
    ) -> StraceRunResult:
        run_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = time.time()
        trace_log_path = self.traces_dir / f"{run_id}.log"
        stdout = ""
        stderr = ""
        exit_code = None
        timed_out = False
        resolved_working_directory = str(Path(working_directory or os.getcwd()).resolve())

        strace_command = [
            "strace",
            "-f",
            "-tt",
            "-e",
            "trace=file,process,network",
            "-o",
            str(trace_log_path),
            *command,
        ]

        process = subprocess.Popen(
            strace_command,
            cwd=resolved_working_directory,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
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

        events = self.parser.parse_file(run_id, str(trace_log_path), persist=True)
        finished_at = datetime.now(timezone.utc).isoformat()
        duration_seconds = round(time.time() - start_time, 4)

        result = StraceRunResult(
            run_id=run_id,
            command=command,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=duration_seconds,
            exit_code=exit_code,
            timed_out=timed_out,
            stdout=stdout,
            stderr=stderr,
            trace_log_path=str(trace_log_path),
            events_count=len(events),
            unique_syscalls_count=len({event.syscall for event in events}),
            category_counts=self.category_counts(events),
        )

        self.store_result(result)
        return result

    def category_counts(self, events) -> dict[str, int]:
        counts = {}

        for event in events:
            counts[event.category] = counts.get(event.category, 0) + 1

        return counts

    def store_result(self, result: StraceRunResult) -> None:
        with self.runs_output_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(asdict(result), ensure_ascii=False) + "\n")
