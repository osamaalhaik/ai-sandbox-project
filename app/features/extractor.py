import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class BehavioralFeatures:
    run_id: str
    command_hash: str
    executable: str | None
    command_length: int
    status: str
    exit_code: int | None
    policy_allowed: bool
    blocked_by_policy: bool
    timed_out: bool
    killed_by_timeout: bool
    duration_seconds: float
    samples_count: int
    observed_duration_seconds: float
    max_cpu_percent: float
    avg_cpu_percent: float
    max_memory_rss_mb: float
    avg_memory_rss_mb: float
    max_memory_vms_mb: float
    avg_memory_vms_mb: float
    memory_rss_to_limit_ratio: float
    memory_vms_to_limit_ratio: float
    max_threads_count: int
    max_children_count: int
    max_open_files_count: int
    open_files_to_limit_ratio: float
    observed_statuses_count: int
    errors_count: int
    had_monitoring_errors: bool
    last_sample_alive: bool
    non_zero_exit: bool
    abnormal_termination: bool


class BehavioralFeatureExtractor:
    def __init__(
        self,
        runs_path: str = "data/raw/sandbox_runs.jsonl",
        summaries_path: str = "data/processed/process_sample_summaries.jsonl",
        output_path: str = "data/processed/behavioral_features.jsonl",
    ):
        self.runs_path = Path(runs_path)
        self.summaries_path = Path(summaries_path)
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

    def extract_latest(self, persist: bool = True) -> BehavioralFeatures:
        run_record = self._read_latest_record(self.runs_path)
        summary_record = self._find_record_by_run_id(self.summaries_path, run_record["run_id"])

        features = self.extract_from_records(run_record, summary_record)

        if persist:
            self._store_features(features)

        return features

    def extract_by_run_id(self, run_id: str, persist: bool = True) -> BehavioralFeatures:
        run_record = self._find_record_by_run_id(self.runs_path, run_id)
        summary_record = self._find_record_by_run_id(self.summaries_path, run_id)

        features = self.extract_from_records(run_record, summary_record)

        if persist:
            self._store_features(features)

        return features

    def extract_from_records(self, run_record: dict, summary_record: dict | None) -> BehavioralFeatures:
        command = run_record.get("command") or []
        resource_limits = run_record.get("resource_limits") or {}
        summary = summary_record or {}

        max_memory_mb = float(resource_limits.get("max_memory_mb") or 0.0)
        max_open_files = float(resource_limits.get("max_open_files") or 0.0)
        max_memory_rss_mb = float(summary.get("max_memory_rss_mb") or 0.0)
        max_memory_vms_mb = float(summary.get("max_memory_vms_mb") or 0.0)
        max_open_files_count = int(summary.get("max_open_files_count") or 0)
        exit_code = run_record.get("exit_code")
        status = str(run_record.get("status") or "unknown")
        blocked_by_policy = run_record.get("failure_reason") == "blocked_by_policy"
        timed_out = bool(run_record.get("timed_out"))
        killed_by_timeout = bool(run_record.get("killed_by_timeout"))
        non_zero_exit = exit_code is not None and exit_code != 0
        abnormal_termination = status in {"failed", "timed_out", "blocked"} or non_zero_exit

        return BehavioralFeatures(
            run_id=run_record["run_id"],
            command_hash=str(run_record.get("command_hash") or ""),
            executable=command[0] if command else None,
            command_length=len(command),
            status=status,
            exit_code=exit_code,
            policy_allowed=bool(run_record.get("policy_allowed")),
            blocked_by_policy=blocked_by_policy,
            timed_out=timed_out,
            killed_by_timeout=killed_by_timeout,
            duration_seconds=float(run_record.get("duration_seconds") or 0.0),
            samples_count=int(summary.get("samples_count") or 0),
            observed_duration_seconds=float(summary.get("observed_duration_seconds") or 0.0),
            max_cpu_percent=float(summary.get("max_cpu_percent") or 0.0),
            avg_cpu_percent=float(summary.get("avg_cpu_percent") or 0.0),
            max_memory_rss_mb=max_memory_rss_mb,
            avg_memory_rss_mb=float(summary.get("avg_memory_rss_mb") or 0.0),
            max_memory_vms_mb=max_memory_vms_mb,
            avg_memory_vms_mb=float(summary.get("avg_memory_vms_mb") or 0.0),
            memory_rss_to_limit_ratio=self._safe_ratio(max_memory_rss_mb, max_memory_mb),
            memory_vms_to_limit_ratio=self._safe_ratio(max_memory_vms_mb, max_memory_mb),
            max_threads_count=int(summary.get("max_threads_count") or 0),
            max_children_count=int(summary.get("max_children_count") or 0),
            max_open_files_count=max_open_files_count,
            open_files_to_limit_ratio=self._safe_ratio(max_open_files_count, max_open_files),
            observed_statuses_count=len(summary.get("observed_statuses") or []),
            errors_count=int(summary.get("errors_count") or 0),
            had_monitoring_errors=bool(summary.get("had_errors")),
            last_sample_alive=bool(summary.get("last_sample_alive")),
            non_zero_exit=non_zero_exit,
            abnormal_termination=abnormal_termination,
        )

    def _read_latest_record(self, path: Path) -> dict:
        if not path.exists():
            raise FileNotFoundError(str(path))

        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

        if not lines:
            raise ValueError("no_records_found")

        return json.loads(lines[-1])

    def _find_record_by_run_id(self, path: Path, run_id: str) -> dict | None:
        if not path.exists():
            return None

        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue

            record = json.loads(line)

            if record.get("run_id") == run_id:
                return record

        return None

    def _safe_ratio(self, value: float, limit: float) -> float:
        if limit <= 0:
            return 0.0

        return round(value / limit, 6)

    def _store_features(self, features: BehavioralFeatures) -> None:
        with self.output_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(asdict(features), ensure_ascii=False) + "\n")
