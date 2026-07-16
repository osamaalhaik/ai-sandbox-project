import json
import tempfile
import unittest
from pathlib import Path

from app.monitoring.sample_summary import ProcessSampleSummarizer


class ProcessTreeSummaryTests(unittest.TestCase):
    def summarize(
        self,
        run_id,
        records,
    ):
        temporary_directory = (
            tempfile.TemporaryDirectory()
        )

        directory = Path(
            temporary_directory.name
        )

        samples_path = (
            directory
            / "samples.jsonl"
        )

        output_path = (
            directory
            / "summaries.jsonl"
        )

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
            run_id,
            persist=False,
        )

        return (
            temporary_directory,
            summary,
        )

    def test_traced_tree_metadata_is_preserved(self):
        records = [
            {
                "run_id": "traced-tree",
                "pid": 501,
                "root_pid": 500,
                "target_pid": 501,
                "wrapper_pid": 500,
                "timestamp": "2026-01-01T00:00:00+00:00",
                "status": "running",
                "cpu_percent": 2.0,
                "memory_rss_mb": 10.0,
                "memory_vms_mb": 20.0,
                "threads_count": 2,
                "children_count": 1,
                "open_files_count": 3,
                "connections_count": 1,
                "process_count": 2,
                "monitored_pids": [
                    501,
                    502,
                ],
                "alive": True,
                "error": None,
            },
            {
                "run_id": "traced-tree",
                "pid": 501,
                "root_pid": 500,
                "target_pid": 501,
                "wrapper_pid": 500,
                "timestamp": "2026-01-01T00:00:01+00:00",
                "status": "sleeping",
                "cpu_percent": 4.0,
                "memory_rss_mb": 18.0,
                "memory_vms_mb": 30.0,
                "threads_count": 4,
                "children_count": 2,
                "open_files_count": 5,
                "connections_count": 2,
                "process_count": 3,
                "monitored_pids": [
                    501,
                    502,
                    503,
                ],
                "alive": True,
                "error": None,
            },
        ]

        temporary_directory, summary = self.summarize(
            "traced-tree",
            records,
        )

        try:
            self.assertEqual(
                summary.root_pid,
                500,
            )
            self.assertEqual(
                summary.wrapper_pid,
                500,
            )
            self.assertEqual(
                summary.target_pid,
                501,
            )
            self.assertEqual(
                summary.max_processes_count,
                3,
            )
            self.assertEqual(
                summary.max_connections_count,
                2,
            )
            self.assertEqual(
                summary.observed_pids,
                [
                    501,
                    502,
                    503,
                ],
            )
        finally:
            temporary_directory.cleanup()

    def test_legacy_samples_remain_supported(self):
        records = [
            {
                "run_id": "legacy-run",
                "pid": 700,
                "timestamp": "2026-01-01T00:00:00+00:00",
                "status": "running",
                "cpu_percent": 1.0,
                "memory_rss_mb": 5.0,
                "memory_vms_mb": 12.0,
                "threads_count": 1,
                "children_count": 0,
                "open_files_count": 0,
                "alive": True,
                "error": None,
            }
        ]

        temporary_directory, summary = self.summarize(
            "legacy-run",
            records,
        )

        try:
            self.assertEqual(
                summary.root_pid,
                700,
            )
            self.assertEqual(
                summary.target_pid,
                700,
            )
            self.assertIsNone(
                summary.wrapper_pid
            )
            self.assertEqual(
                summary.max_processes_count,
                1,
            )
            self.assertEqual(
                summary.observed_pids,
                [700],
            )
        finally:
            temporary_directory.cleanup()

    def test_empty_summary_contains_tree_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = ProcessSampleSummarizer(
                samples_path=str(
                    Path(directory)
                    / "missing.jsonl"
                ),
                output_path=str(
                    Path(directory)
                    / "summary.jsonl"
                ),
            ).summarize(
                "empty-run",
                persist=False,
            )

            self.assertIsNone(
                summary.root_pid
            )
            self.assertIsNone(
                summary.target_pid
            )
            self.assertIsNone(
                summary.wrapper_pid
            )
            self.assertEqual(
                summary.max_processes_count,
                0,
            )
            self.assertEqual(
                summary.max_connections_count,
                0,
            )
            self.assertEqual(
                summary.observed_pids,
                [],
            )


if __name__ == "__main__":
    unittest.main()
