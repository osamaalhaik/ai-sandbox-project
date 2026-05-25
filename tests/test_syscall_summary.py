import json
import tempfile
import unittest
from pathlib import Path

from app.tracing.syscall_summary import SyscallSummarizer


class SyscallSummarizerTests(unittest.TestCase):
    def create_summarizer(self):
        temp_dir = tempfile.TemporaryDirectory()
        base_path = Path(temp_dir.name)
        events_path = base_path / "syscall_events.jsonl"
        summaries_path = base_path / "syscall_summaries.jsonl"
        summarizer = SyscallSummarizer(
            events_path=str(events_path),
            output_path=str(summaries_path),
        )
        return temp_dir, events_path, summaries_path, summarizer

    def write_events(self, events_path, records):
        with events_path.open("w", encoding="utf-8") as file:
            for record in records:
                file.write(json.dumps(record) + "\n")

    def read_jsonl(self, path):
        if not path.exists():
            return []

        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def test_missing_run_returns_empty_summary(self):
        temp_dir, events_path, summaries_path, summarizer = self.create_summarizer()

        try:
            summary = summarizer.summarize("missing-run", persist=False)

            self.assertEqual(summary.run_id, "missing-run")
            self.assertEqual(summary.total_syscalls, 0)
            self.assertEqual(summary.file_syscalls_count, 0)
            self.assertEqual(summary.process_syscalls_count, 0)
            self.assertEqual(summary.network_syscalls_count, 0)
            self.assertEqual(summary.failed_syscalls_count, 0)
            self.assertEqual(summary.unique_syscalls_count, 0)
            self.assertEqual(summary.unique_paths_count, 0)
            self.assertEqual(summary.sensitive_paths_accessed, [])
            self.assertEqual(summary.sensitive_paths_count, 0)
        finally:
            temp_dir.cleanup()

    def test_summary_counts_are_calculated_correctly(self):
        temp_dir, events_path, summaries_path, summarizer = self.create_summarizer()

        try:
            run_id = "run-001"
            records = [
                {
                    "run_id": run_id,
                    "syscall": "execve",
                    "category": "process",
                    "path": "/usr/bin/python",
                    "success": True,
                    "error": None,
                },
                {
                    "run_id": run_id,
                    "syscall": "openat",
                    "category": "file",
                    "path": "/etc/passwd",
                    "success": True,
                    "error": None,
                },
                {
                    "run_id": run_id,
                    "syscall": "access",
                    "category": "file",
                    "path": "/etc/shadow",
                    "success": False,
                    "error": "EACCES",
                },
                {
                    "run_id": run_id,
                    "syscall": "connect",
                    "category": "network",
                    "path": None,
                    "success": True,
                    "error": None,
                },
                {
                    "run_id": run_id,
                    "syscall": "uname",
                    "category": "other",
                    "path": None,
                    "success": True,
                    "error": None,
                },
                {
                    "run_id": "other-run",
                    "syscall": "openat",
                    "category": "file",
                    "path": "/tmp/ignored",
                    "success": True,
                    "error": None,
                },
            ]

            self.write_events(events_path, records)

            summary = summarizer.summarize(run_id, persist=False)

            self.assertEqual(summary.total_syscalls, 5)
            self.assertEqual(summary.file_syscalls_count, 2)
            self.assertEqual(summary.process_syscalls_count, 1)
            self.assertEqual(summary.network_syscalls_count, 1)
            self.assertEqual(summary.other_syscalls_count, 1)
            self.assertEqual(summary.successful_syscalls_count, 4)
            self.assertEqual(summary.failed_syscalls_count, 1)
            self.assertEqual(summary.unique_syscalls_count, 5)
            self.assertEqual(summary.unique_paths_count, 3)
            self.assertEqual(summary.execve_count, 1)
            self.assertEqual(summary.openat_count, 1)
            self.assertEqual(summary.access_count, 1)
            self.assertEqual(summary.connect_count, 1)
        finally:
            temp_dir.cleanup()

    def test_sensitive_paths_are_detected(self):
        temp_dir, events_path, summaries_path, summarizer = self.create_summarizer()

        try:
            run_id = "run-002"
            records = [
                {
                    "run_id": run_id,
                    "syscall": "openat",
                    "category": "file",
                    "path": "/etc/passwd",
                    "success": True,
                    "error": None,
                },
                {
                    "run_id": run_id,
                    "syscall": "openat",
                    "category": "file",
                    "path": "/etc/ssh/sshd_config",
                    "success": True,
                    "error": None,
                },
                {
                    "run_id": run_id,
                    "syscall": "openat",
                    "category": "file",
                    "path": "/home/osama/file.txt",
                    "success": True,
                    "error": None,
                },
            ]

            self.write_events(events_path, records)

            summary = summarizer.summarize(run_id, persist=False)

            self.assertEqual(summary.sensitive_paths_count, 2)
            self.assertIn("/etc/passwd", summary.sensitive_paths_accessed)
            self.assertIn("/etc/ssh/sshd_config", summary.sensitive_paths_accessed)
            self.assertNotIn("/home/osama/file.txt", summary.sensitive_paths_accessed)
        finally:
            temp_dir.cleanup()

    def test_summary_is_persisted_to_jsonl(self):
        temp_dir, events_path, summaries_path, summarizer = self.create_summarizer()

        try:
            run_id = "run-003"
            records = [
                {
                    "run_id": run_id,
                    "syscall": "execve",
                    "category": "process",
                    "path": "/usr/bin/python",
                    "success": True,
                    "error": None,
                }
            ]

            self.write_events(events_path, records)

            summary = summarizer.summarize(run_id, persist=True)
            persisted_records = self.read_jsonl(summaries_path)

            self.assertEqual(len(persisted_records), 1)
            self.assertEqual(persisted_records[0]["run_id"], summary.run_id)
            self.assertEqual(persisted_records[0]["total_syscalls"], 1)
            self.assertEqual(persisted_records[0]["execve_count"], 1)
        finally:
            temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
