import json
import tempfile
import unittest
from pathlib import Path

from app.monitoring.sample_summary import ProcessSampleSummarizer


class ProcessSampleTransientTests(unittest.TestCase):
    def build_summary(
        self,
        records,
    ):
        temporary_directory = tempfile.TemporaryDirectory()
        directory = Path(
            temporary_directory.name
        )
        samples_path = directory / "samples.jsonl"
        output_path = directory / "summary.jsonl"

        samples_path.write_text(
            "\n".join(
                json.dumps(record)
                for record in records
            )
            + "\n",
            encoding="utf-8",
        )

        summary = ProcessSampleSummarizer(
            samples_path=str(
                samples_path
            ),
            output_path=str(
                output_path
            ),
        ).summarize(
            records[0]["run_id"],
            persist=False,
        )

        return temporary_directory, summary

    def test_transient_empty_tree_is_not_error_after_target_appears(self):
        records = [
            {
                "run_id": "transient-target",
                "pid": 100,
                "timestamp": "2026-01-01T00:00:00+00:00",
                "alive": True,
                "error": "no_monitored_processes",
                "process_count": 0,
            },
            {
                "run_id": "transient-target",
                "pid": 100,
                "timestamp": "2026-01-01T00:00:00.100000+00:00",
                "alive": True,
                "error": "no_monitored_processes",
                "process_count": 0,
            },
            {
                "run_id": "transient-target",
                "pid": 104,
                "timestamp": "2026-01-01T00:00:00.200000+00:00",
                "alive": True,
                "error": None,
                "process_count": 1,
                "status": "tracing-stop",
                "memory_rss_mb": 5.0,
                "memory_vms_mb": 12.0,
                "threads_count": 1,
                "monitored_pids": [
                    104
                ],
            },
        ]

        temporary_directory, summary = self.build_summary(
            records
        )

        try:
            self.assertEqual(
                summary.errors_count,
                0,
            )
            self.assertFalse(
                summary.had_errors
            )
            self.assertEqual(
                summary.samples_count,
                3,
            )
        finally:
            temporary_directory.cleanup()

    def test_empty_tree_remains_error_when_target_never_appears(self):
        records = [
            {
                "run_id": "missing-target",
                "pid": 200,
                "timestamp": "2026-01-01T00:00:00+00:00",
                "alive": True,
                "error": "no_monitored_processes",
                "process_count": 0,
            },
            {
                "run_id": "missing-target",
                "pid": 200,
                "timestamp": "2026-01-01T00:00:00.100000+00:00",
                "alive": False,
                "error": "no_monitored_processes",
                "process_count": 0,
            },
        ]

        temporary_directory, summary = self.build_summary(
            records
        )

        try:
            self.assertEqual(
                summary.errors_count,
                2,
            )
            self.assertTrue(
                summary.had_errors
            )
        finally:
            temporary_directory.cleanup()


if __name__ == "__main__":
    unittest.main()
