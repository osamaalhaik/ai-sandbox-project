import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class SyscallSummary:
    run_id: str
    total_syscalls: int
    file_syscalls_count: int
    process_syscalls_count: int
    network_syscalls_count: int
    other_syscalls_count: int
    successful_syscalls_count: int
    failed_syscalls_count: int
    unique_syscalls_count: int
    unique_paths_count: int
    sensitive_paths_accessed: list[str]
    sensitive_paths_count: int
    execve_count: int
    openat_count: int
    access_count: int
    connect_count: int
    summary_created_at: str


class SyscallSummarizer:
    def __init__(
        self,
        events_path: str = "data/raw/syscall_events.jsonl",
        output_path: str = "data/processed/syscall_summaries.jsonl",
    ):
        self.events_path = Path(events_path)
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

    def summarize(self, run_id: str, persist: bool = True) -> SyscallSummary:
        events = self.load_events(run_id)
        summary = self.build_summary(run_id, events)

        if persist:
            self.store_summary(summary)

        return summary

    def load_events(self, run_id: str) -> list[dict]:
        if not self.events_path.exists():
            return []

        records = []

        for line in self.events_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue

            record = json.loads(line)

            if record.get("run_id") == run_id:
                records.append(record)

        return records

    def build_summary(self, run_id: str, events: list[dict]) -> SyscallSummary:
        syscalls = [str(event.get("syscall") or "") for event in events]
        paths = [str(event.get("path")) for event in events if event.get("path") is not None]
        sensitive_paths = self.find_sensitive_paths(paths)

        return SyscallSummary(
            run_id=run_id,
            total_syscalls=len(events),
            file_syscalls_count=self.count_category(events, "file"),
            process_syscalls_count=self.count_category(events, "process"),
            network_syscalls_count=self.count_category(events, "network"),
            other_syscalls_count=self.count_category(events, "other"),
            successful_syscalls_count=sum(1 for event in events if event.get("success") is True),
            failed_syscalls_count=sum(1 for event in events if event.get("success") is False),
            unique_syscalls_count=len({item for item in syscalls if item}),
            unique_paths_count=len(set(paths)),
            sensitive_paths_accessed=sensitive_paths,
            sensitive_paths_count=len(sensitive_paths),
            execve_count=syscalls.count("execve"),
            openat_count=syscalls.count("openat"),
            access_count=syscalls.count("access"),
            connect_count=syscalls.count("connect"),
            summary_created_at=datetime.now(timezone.utc).isoformat(),
        )

    def count_category(self, events: list[dict], category: str) -> int:
        return sum(1 for event in events if event.get("category") == category)

    def find_sensitive_paths(self, paths: list[str]) -> list[str]:
        sensitive_prefixes = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/root",
            "/proc/kcore",
            "/etc/ssh",
        ]

        matched = []

        for path in sorted(set(paths)):
            if any(path == item or path.startswith(f"{item}/") for item in sensitive_prefixes):
                matched.append(path)

        return matched

    def store_summary(self, summary: SyscallSummary) -> None:
        with self.output_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(asdict(summary), ensure_ascii=False) + "\n")
