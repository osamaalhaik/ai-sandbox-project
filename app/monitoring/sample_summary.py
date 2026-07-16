import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class ProcessSampleSummary:
    run_id: str
    samples_count: int
    first_timestamp: str | None
    last_timestamp: str | None
    observed_duration_seconds: float
    max_cpu_percent: float
    avg_cpu_percent: float
    max_memory_rss_mb: float
    avg_memory_rss_mb: float
    max_memory_vms_mb: float
    avg_memory_vms_mb: float
    max_threads_count: int
    max_children_count: int
    max_open_files_count: int
    observed_statuses: list[str]
    errors_count: int
    had_errors: bool
    last_sample_alive: bool
    summary_created_at: str
    root_pid: int | None
    target_pid: int | None
    wrapper_pid: int | None
    max_processes_count: int
    max_connections_count: int
    observed_pids: list[int]


class ProcessSampleSummarizer:
    def __init__(
        self,
        samples_path: str = "data/raw/process_samples.jsonl",
        output_path: str = "data/processed/process_sample_summaries.jsonl",
    ):
        self.samples_path = Path(samples_path)
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    def summarize(
        self,
        run_id: str,
        persist: bool = True,
    ) -> ProcessSampleSummary:
        samples = self.load_samples(run_id)
        summary = self._build_summary(
            run_id,
            samples,
        )

        if persist:
            self._store_summary(summary)

        return summary

    def load_samples(
        self,
        run_id: str,
    ) -> list[dict]:
        if not self.samples_path.exists():
            return []

        records = []

        for line in self.samples_path.read_text(
            encoding="utf-8"
        ).splitlines():
            if not line.strip():
                continue

            record = json.loads(line)

            if record.get("run_id") == run_id:
                records.append(record)

        return records

    def _build_summary(
        self,
        run_id: str,
        samples: list[dict],
    ) -> ProcessSampleSummary:
        now = datetime.now(
            timezone.utc
        ).isoformat()

        if not samples:
            return ProcessSampleSummary(
                run_id=run_id,
                samples_count=0,
                first_timestamp=None,
                last_timestamp=None,
                observed_duration_seconds=0.0,
                max_cpu_percent=0.0,
                avg_cpu_percent=0.0,
                max_memory_rss_mb=0.0,
                avg_memory_rss_mb=0.0,
                max_memory_vms_mb=0.0,
                avg_memory_vms_mb=0.0,
                max_threads_count=0,
                max_children_count=0,
                max_open_files_count=0,
                observed_statuses=[],
                errors_count=0,
                had_errors=False,
                last_sample_alive=False,
                summary_created_at=now,
                root_pid=None,
                target_pid=None,
                wrapper_pid=None,
                max_processes_count=0,
                max_connections_count=0,
                observed_pids=[],
            )

        cpu_values = [
            float(
                item.get("cpu_percent")
                or 0.0
            )
            for item in samples
        ]

        rss_values = [
            float(
                item.get("memory_rss_mb")
                or 0.0
            )
            for item in samples
        ]

        vms_values = [
            float(
                item.get("memory_vms_mb")
                or 0.0
            )
            for item in samples
        ]

        threads_values = [
            int(
                item.get("threads_count")
                or 0
            )
            for item in samples
        ]

        children_values = [
            int(
                item.get("children_count")
                or 0
            )
            for item in samples
        ]

        open_files_values = [
            int(
                item.get("open_files_count")
                or 0
            )
            for item in samples
        ]

        process_values = [
            self._process_count(item)
            for item in samples
        ]

        connection_values = [
            int(
                item.get("connections_count")
                or 0
            )
            for item in samples
        ]

        statuses = sorted(
            {
                str(item.get("status"))
                for item in samples
                if item.get("status") is not None
            }
        )

        valid_runtime_sample_observed = any(
            item.get("error") is None
            and self._process_count(item) > 0
            for item in samples
        )

        errors_count = sum(
            1
            for item in samples
            if item.get("error")
            not in (
                None,
                "no_such_process",
            )
            and not (
                item.get("error")
                == "no_monitored_processes"
                and valid_runtime_sample_observed
            )
        )

        first_timestamp = samples[0].get(
            "timestamp"
        )
        last_timestamp = samples[-1].get(
            "timestamp"
        )

        root_pid = self._first_integer(
            samples,
            "root_pid",
            fallback_key="pid",
        )

        target_pid = self._first_integer(
            samples,
            "target_pid",
            fallback_key="pid",
        )

        wrapper_pid = self._first_integer(
            samples,
            "wrapper_pid",
        )

        observed_pids = self._observed_pids(
            samples
        )

        return ProcessSampleSummary(
            run_id=run_id,
            samples_count=len(samples),
            first_timestamp=first_timestamp,
            last_timestamp=last_timestamp,
            observed_duration_seconds=self._duration_seconds(
                first_timestamp,
                last_timestamp,
            ),
            max_cpu_percent=round(
                max(cpu_values),
                4,
            ),
            avg_cpu_percent=round(
                self._average(cpu_values),
                4,
            ),
            max_memory_rss_mb=round(
                max(rss_values),
                4,
            ),
            avg_memory_rss_mb=round(
                self._average(rss_values),
                4,
            ),
            max_memory_vms_mb=round(
                max(vms_values),
                4,
            ),
            avg_memory_vms_mb=round(
                self._average(vms_values),
                4,
            ),
            max_threads_count=max(
                threads_values
            ),
            max_children_count=max(
                children_values
            ),
            max_open_files_count=max(
                open_files_values
            ),
            observed_statuses=statuses,
            errors_count=errors_count,
            had_errors=errors_count > 0,
            last_sample_alive=bool(
                samples[-1].get("alive")
            ),
            summary_created_at=now,
            root_pid=root_pid,
            target_pid=target_pid,
            wrapper_pid=wrapper_pid,
            max_processes_count=max(
                process_values
            ),
            max_connections_count=max(
                connection_values
            ),
            observed_pids=observed_pids,
        )

    def _process_count(
        self,
        item: dict,
    ) -> int:
        value = item.get("process_count")

        if value is not None:
            return int(value)

        if (
            item.get("pid") is not None
            and bool(item.get("alive"))
        ):
            return 1

        return 0

    def _first_integer(
        self,
        samples: list[dict],
        key: str,
        fallback_key: str | None = None,
    ) -> int | None:
        for item in samples:
            value = item.get(key)

            if value is not None:
                return int(value)

        if fallback_key is not None:
            for item in samples:
                value = item.get(
                    fallback_key
                )

                if value is not None:
                    return int(value)

        return None

    def _observed_pids(
        self,
        samples: list[dict],
    ) -> list[int]:
        values: set[int] = set()

        for item in samples:
            monitored_pids = item.get(
                "monitored_pids"
            )

            if isinstance(
                monitored_pids,
                list,
            ):
                values.update(
                    int(pid)
                    for pid in monitored_pids
                    if pid is not None
                )
                continue

            if (
                item.get("pid") is not None
                and bool(item.get("alive"))
            ):
                values.add(
                    int(item["pid"])
                )

        return sorted(values)

    def _average(
        self,
        values: list[float],
    ) -> float:
        if not values:
            return 0.0

        return sum(values) / len(values)

    def _duration_seconds(
        self,
        first_timestamp: str | None,
        last_timestamp: str | None,
    ) -> float:
        if not first_timestamp or not last_timestamp:
            return 0.0

        first = datetime.fromisoformat(
            first_timestamp
        )
        last = datetime.fromisoformat(
            last_timestamp
        )

        return round(
            (
                last
                - first
            ).total_seconds(),
            4,
        )

    def _store_summary(
        self,
        summary: ProcessSampleSummary,
    ) -> None:
        with self.output_path.open(
            "a",
            encoding="utf-8",
        ) as file:
            file.write(
                json.dumps(
                    asdict(summary),
                    ensure_ascii=False,
                )
                + "\n"
            )
