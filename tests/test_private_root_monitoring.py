import json
import tempfile
import unittest
from pathlib import Path

from app.monitoring.sample_summary import (
    ProcessSampleSummarizer,
)
from app.sandbox.private_root_runner import (
    PrivateRootRunner,
)


ROOT_DIR = Path(__file__).resolve().parents[1]


class PrivateRootMonitoringTests(
    unittest.TestCase
):
    def create_runner(self):
        temporary_directory = (
            tempfile.TemporaryDirectory()
        )

        directory = Path(
            temporary_directory.name
        )

        runner = PrivateRootRunner(
            output_path=str(
                directory
                / "private_root_runs.jsonl"
            ),
            samples_output_path=str(
                directory
                / "private_root_samples.jsonl"
            ),
        )

        return (
            temporary_directory,
            directory,
            runner,
        )

    def run_process_tree(self):
        (
            temporary_directory,
            directory,
            runner,
        ) = self.create_runner()

        result = runner.run(
            command=[
                str(
                    ROOT_DIR
                    / "venv/bin/python"
                ),
                "scripts/demo_private_root_process_tree.py",
            ],
            working_directory=str(
                ROOT_DIR
            ),
            timeout_seconds=8,
            monitoring_enabled=True,
            monitor_interval_seconds=0.03,
        )

        return (
            temporary_directory,
            directory,
            result,
        )

    def test_private_root_generates_process_samples(self):
        (
            temporary_directory,
            directory,
            result,
        ) = self.run_process_tree()

        try:
            samples_path = Path(
                result.samples_output_path
            )

            self.assertEqual(
                result.status,
                "completed",
                msg=result.stderr,
            )

            self.assertTrue(
                result.monitoring_enabled
            )

            self.assertGreater(
                result.samples_count,
                0,
            )

            self.assertTrue(
                samples_path.exists()
            )

            records = [
                json.loads(line)
                for line in samples_path.read_text(
                    encoding="utf-8"
                ).splitlines()
                if line.strip()
            ]

            matching = [
                record
                for record in records
                if record.get("run_id")
                == result.run_id
            ]

            self.assertEqual(
                len(matching),
                result.samples_count,
            )

            self.assertTrue(
                all(
                    record.get(
                        "wrapper_pid"
                    )
                    == result.wrapper_pid
                    for record in matching
                )
            )

        finally:
            temporary_directory.cleanup()

    def test_private_root_aggregates_target_and_children(self):
        (
            temporary_directory,
            directory,
            result,
        ) = self.run_process_tree()

        try:
            target = json.loads(
                result.stdout.strip()
            )

            self.assertEqual(
                target["pid"],
                1,
            )

            self.assertIsNotNone(
                result.target_pid
            )

            self.assertIn(
                result.target_pid,
                result.monitored_pids,
            )

            self.assertNotIn(
                result.wrapper_pid,
                result.monitored_pids,
            )

            self.assertGreaterEqual(
                result.max_processes_observed,
                3,
            )

            self.assertGreaterEqual(
                len(
                    result.monitored_pids
                ),
                3,
            )

        finally:
            temporary_directory.cleanup()

    def test_process_summary_preserves_private_root_tree(self):
        (
            temporary_directory,
            directory,
            result,
        ) = self.run_process_tree()

        try:
            summary = ProcessSampleSummarizer(
                samples_path=(
                    result.samples_output_path
                ),
                output_path=str(
                    directory
                    / "summaries.jsonl"
                ),
            ).summarize(
                result.run_id,
                persist=False,
            )

            self.assertEqual(
                summary.root_pid,
                result.monitor_root_pid,
            )

            self.assertEqual(
                summary.wrapper_pid,
                result.wrapper_pid,
            )

            self.assertEqual(
                summary.target_pid,
                result.target_pid,
            )

            self.assertGreaterEqual(
                summary.max_processes_count,
                3,
            )

            self.assertGreaterEqual(
                len(
                    summary.observed_pids
                ),
                3,
            )

            self.assertFalse(
                summary.had_errors
            )

        finally:
            temporary_directory.cleanup()

    def test_private_root_monitoring_can_be_disabled(self):
        (
            temporary_directory,
            directory,
            runner,
        ) = self.create_runner()

        try:
            result = runner.run(
                command=[
                    str(
                        ROOT_DIR
                        / "venv/bin/python"
                    ),
                    "scripts/demo_private_root.py",
                ],
                working_directory=str(
                    ROOT_DIR
                ),
                timeout_seconds=8,
                monitoring_enabled=False,
            )

            self.assertEqual(
                result.status,
                "completed",
                msg=result.stderr,
            )

            self.assertFalse(
                result.monitoring_enabled
            )

            self.assertEqual(
                result.samples_count,
                0,
            )

            self.assertIsNone(
                result.monitor_root_pid
            )

            self.assertIsNone(
                result.target_pid
            )

            self.assertEqual(
                result.monitored_pids,
                [],
            )

            self.assertEqual(
                result.max_processes_observed,
                0,
            )

            self.assertFalse(
                Path(
                    result.samples_output_path
                ).exists()
            )

        finally:
            temporary_directory.cleanup()


if __name__ == "__main__":
    unittest.main()
