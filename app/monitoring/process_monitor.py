import json
import threading
import time
from dataclasses import asdict, dataclass, field
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
    root_pid: int | None = None
    target_pid: int | None = None
    wrapper_pid: int | None = None
    process_count: int = 0
    monitored_pids: list[int] = field(default_factory=list)
    connections_count: int = 0


class ProcessMonitor:
    def __init__(
        self,
        output_path: str = "data/raw/process_samples.jsonl",
    ):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        self._write_lock = threading.Lock()

    def sample(
        self,
        run_id: str,
        pid: int,
    ) -> ProcessSample:
        return self.sample_tree(
            run_id=run_id,
            root_pid=pid,
            include_root=True,
        )

    def sample_tree(
        self,
        run_id: str,
        root_pid: int,
        include_root: bool = True,
        wrapper_pid: int | None = None,
    ) -> ProcessSample:
        timestamp = datetime.now(
            timezone.utc
        ).isoformat()

        try:
            root_process = psutil.Process(
                root_pid
            )
        except psutil.NoSuchProcess:
            sample = self._error_sample(
                run_id=run_id,
                pid=root_pid,
                root_pid=root_pid,
                wrapper_pid=wrapper_pid,
                timestamp=timestamp,
                error="no_such_process",
                alive=False,
            )
            self._store_sample(sample)
            return sample
        except psutil.AccessDenied:
            sample = self._error_sample(
                run_id=run_id,
                pid=root_pid,
                root_pid=root_pid,
                wrapper_pid=wrapper_pid,
                timestamp=timestamp,
                error="access_denied",
                alive=True,
            )
            self._store_sample(sample)
            return sample

        processes = self._discover_tree(
            root_process=root_process,
            include_root=include_root,
        )

        target_process = self._select_target(
            root_process=root_process,
            processes=processes,
            include_root=include_root,
        )

        if not processes:
            root_alive = self._is_alive(
                root_process
            )

            sample = self._error_sample(
                run_id=run_id,
                pid=root_pid,
                root_pid=root_pid,
                wrapper_pid=wrapper_pid,
                timestamp=timestamp,
                error="no_monitored_processes",
                alive=root_alive,
            )
            self._store_sample(sample)
            return sample

        cpu_percent = 0.0
        memory_rss_bytes = 0
        memory_vms_bytes = 0
        threads_count = 0
        open_files_count = 0
        connections_count = 0
        monitored_pids: list[int] = []
        active_processes: list[psutil.Process] = []

        for process in processes:
            try:
                process_status = process.status()

                if process_status == psutil.STATUS_ZOMBIE:
                    continue

                if not process.is_running():
                    continue

                memory_info = process.memory_info()

                cpu_percent += float(
                    process.cpu_percent(
                        interval=None
                    )
                    or 0.0
                )
                memory_rss_bytes += int(
                    memory_info.rss
                )
                memory_vms_bytes += int(
                    memory_info.vms
                )
                threads_count += int(
                    process.num_threads()
                )
                open_files_count += (
                    self._open_files_count(
                        process
                    )
                )
                connections_count += (
                    self._connections_count(
                        process
                    )
                )

                monitored_pids.append(
                    process.pid
                )
                active_processes.append(
                    process
                )

            except (
                psutil.NoSuchProcess,
                psutil.ZombieProcess,
            ):
                continue
            except psutil.AccessDenied:
                monitored_pids.append(
                    process.pid
                )
                active_processes.append(
                    process
                )

        monitored_pids = sorted(
            set(monitored_pids)
        )

        if (
            target_process is None
            or target_process.pid not in monitored_pids
        ):
            target_process = (
                active_processes[0]
                if active_processes
                else None
            )

        target_pid = (
            target_process.pid
            if target_process is not None
            else None
        )

        result_pid = (
            target_pid
            if target_pid is not None
            else root_pid
        )

        process_count = len(
            monitored_pids
        )

        sample = ProcessSample(
            run_id=run_id,
            pid=result_pid,
            timestamp=timestamp,
            name=self._safe_process_value(
                target_process,
                "name",
            ),
            status=self._safe_process_value(
                target_process,
                "status",
            ),
            cpu_percent=round(
                cpu_percent,
                4,
            ),
            memory_rss_mb=round(
                memory_rss_bytes
                / 1024
                / 1024,
                4,
            ),
            memory_vms_mb=round(
                memory_vms_bytes
                / 1024
                / 1024,
                4,
            ),
            threads_count=threads_count,
            children_count=max(
                process_count - 1,
                0,
            ),
            open_files_count=open_files_count,
            alive=bool(
                active_processes
            ),
            error=None,
            root_pid=root_pid,
            target_pid=target_pid,
            wrapper_pid=wrapper_pid,
            process_count=process_count,
            monitored_pids=monitored_pids,
            connections_count=connections_count,
        )

        self._store_sample(sample)
        return sample

    def monitor_until_exit(
        self,
        run_id: str,
        pid: int,
        interval_seconds: float = 0.2,
        max_duration_seconds: int = 30,
        include_root: bool = True,
        wrapper_pid: int | None = None,
    ) -> list[ProcessSample]:
        samples: list[ProcessSample] = []
        started_at = time.monotonic()

        while True:
            elapsed = (
                time.monotonic()
                - started_at
            )

            if elapsed > max_duration_seconds:
                break

            sample = self.sample_tree(
                run_id=run_id,
                root_pid=pid,
                include_root=include_root,
                wrapper_pid=wrapper_pid,
            )

            samples.append(sample)

            if (
                not sample.alive
                and not psutil.pid_exists(pid)
            ):
                break

            time.sleep(
                interval_seconds
            )

        return samples

    def _discover_tree(
        self,
        root_process: psutil.Process,
        include_root: bool,
    ) -> list[psutil.Process]:
        discovered: dict[
            tuple[int, float],
            psutil.Process,
        ] = {}

        if include_root:
            self._add_process(
                discovered,
                root_process,
            )

        try:
            descendants = root_process.children(
                recursive=True
            )
        except psutil.Error:
            descendants = []

        for process in descendants:
            self._add_process(
                discovered,
                process,
            )

        return sorted(
            discovered.values(),
            key=self._process_sort_key,
        )

    def _add_process(
        self,
        discovered: dict[
            tuple[int, float],
            psutil.Process,
        ],
        process: psutil.Process,
    ) -> None:
        try:
            identity = (
                process.pid,
                process.create_time(),
            )
        except psutil.Error:
            return

        discovered[identity] = process

    def _select_target(
        self,
        root_process: psutil.Process,
        processes: list[psutil.Process],
        include_root: bool,
    ) -> psutil.Process | None:
        if include_root:
            return root_process

        if not processes:
            return None

        try:
            direct_children = {
                child.pid
                for child in root_process.children(
                    recursive=False
                )
            }
        except psutil.Error:
            direct_children = set()

        direct_candidates = [
            process
            for process in processes
            if process.pid in direct_children
        ]

        candidates = (
            direct_candidates
            if direct_candidates
            else processes
        )

        return min(
            candidates,
            key=self._process_sort_key,
        )

    def _process_sort_key(
        self,
        process: psutil.Process,
    ) -> tuple[float, int]:
        try:
            return (
                process.create_time(),
                process.pid,
            )
        except psutil.Error:
            return (
                float("inf"),
                process.pid,
            )

    def _safe_process_value(
        self,
        process: psutil.Process | None,
        method_name: str,
    ):
        if process is None:
            return None

        try:
            method = getattr(
                process,
                method_name,
            )
            return method()
        except psutil.Error:
            return None

    def _open_files_count(
        self,
        process: psutil.Process,
    ) -> int:
        try:
            return len(
                process.open_files()
            )
        except psutil.Error:
            return 0

    def _connections_count(
        self,
        process: psutil.Process,
    ) -> int:
        try:
            connection_method = getattr(
                process,
                "net_connections",
                None,
            )

            if connection_method is None:
                return 0

            return len(
                connection_method(
                    kind="inet"
                )
            )
        except (
            psutil.Error,
            OSError,
        ):
            return 0

    def _is_alive(
        self,
        process: psutil.Process,
    ) -> bool:
        try:
            return (
                process.is_running()
                and process.status()
                != psutil.STATUS_ZOMBIE
            )
        except psutil.Error:
            return False

    def _error_sample(
        self,
        run_id: str,
        pid: int,
        root_pid: int,
        wrapper_pid: int | None,
        timestamp: str,
        error: str,
        alive: bool,
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
            alive=alive,
            error=error,
            root_pid=root_pid,
            target_pid=None,
            wrapper_pid=wrapper_pid,
            process_count=0,
            monitored_pids=[],
            connections_count=0,
        )

    def _store_sample(
        self,
        sample: ProcessSample,
    ) -> None:
        payload = json.dumps(
            asdict(sample),
            ensure_ascii=False,
        )

        with self._write_lock:
            with self.output_path.open(
                "a",
                encoding="utf-8",
            ) as file:
                file.write(
                    payload + "\n"
                )
