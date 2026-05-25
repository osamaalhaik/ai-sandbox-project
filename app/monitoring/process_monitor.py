import json
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import psutil


@dataclass
class ProcessSample:
    run_id: str
    pid: int
    timestamp: str
    name: str | None
    status: str | None
    cpu_percent: float
    memory_rss_mb: float
    memory_vms_mb: float
    threads_count: int
    children_count: int
    open_files_count: int
    alive: bool
    error: str | None


class ProcessMonitor:
    def __init__(self, output_path: str = "data/raw/process_samples.jsonl"):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

    def sample(self, run_id: str, pid: int) -> ProcessSample:
        timestamp = datetime.now(timezone.utc).isoformat()

        try:
            process = psutil.Process(pid)
            memory_info = process.memory_info()
            current_status = process.status()
            children = process.children(recursive=True)

            try:
                open_files_count = len(process.open_files())
            except psutil.Error:
                open_files_count = 0

            sample = ProcessSample(
                run_id=run_id,
                pid=pid,
                timestamp=timestamp,
                name=process.name(),
                status=current_status,
                cpu_percent=process.cpu_percent(interval=None),
                memory_rss_mb=round(memory_info.rss / 1024 / 1024, 4),
                memory_vms_mb=round(memory_info.vms / 1024 / 1024, 4),
                threads_count=process.num_threads(),
                children_count=len(children),
                open_files_count=open_files_count,
                alive=process.is_running() and current_status != psutil.STATUS_ZOMBIE,
                error=None,
            )

        except psutil.NoSuchProcess:
            sample = self._error_sample(run_id, pid, timestamp, "no_such_process")

        except psutil.AccessDenied:
            sample = self._error_sample(run_id, pid, timestamp, "access_denied")

        except Exception as exc:
            sample = self._error_sample(run_id, pid, timestamp, str(exc))

        self._store_sample(sample)
        return sample

    def monitor_until_exit(
        self,
        run_id: str,
        pid: int,
        interval_seconds: float = 0.2,
        max_duration_seconds: int = 30,
    ) -> list[ProcessSample]:
        samples = []
        started_at = time.time()

        try:
            process = psutil.Process(pid)
            process.cpu_percent(interval=None)
        except psutil.Error:
            sample = self.sample(run_id, pid)
            return [sample]

        while True:
            elapsed = time.time() - started_at

            if elapsed > max_duration_seconds:
                break

            sample = self.sample(run_id, pid)
            samples.append(sample)

            if not psutil.pid_exists(pid):
                break

            try:
                if not process.is_running() or process.status() == psutil.STATUS_ZOMBIE:
                    break
            except psutil.Error:
                break

            time.sleep(interval_seconds)

        return samples

    def _error_sample(
        self,
        run_id: str,
        pid: int,
        timestamp: str,
        error: str,
    ) -> ProcessSample:
        return ProcessSample(
            run_id=run_id,
            pid=pid,
            timestamp=timestamp,
            name=None,
            status=None,
            cpu_percent=0.0,
            memory_rss_mb=0.0,
            memory_vms_mb=0.0,
            threads_count=0,
            children_count=0,
            open_files_count=0,
            alive=False,
            error=error,
        )

    def _store_sample(self, sample: ProcessSample) -> None:
        with self.output_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(asdict(sample), ensure_ascii=False) + "\n")
