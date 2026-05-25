import json
import tempfile
import unittest
from pathlib import Path

from app.sandbox.runner import SandboxRunner


ROOT_DIR = Path(__file__).resolve().parents[1]


class MonitoringIntegrationTests(unittest.TestCase):
    def create_runner(self):
        temp_dir = tempfile.TemporaryDirectory()
        base_path = Path(temp_dir.name)
        runs_path = base_path / "sandbox_runs.jsonl"
        samples_path = base_path / "process_samples.jsonl"
        runner = SandboxRunner(
            output_path=str(runs_path),
            samples_output_path=str(samples_path),
        )
        return temp_dir, runs_path, samples_path, runner

    def read_jsonl(self, path):
        if not path.exists():
            return []

        lines = path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines]

    def test_sandbox_run_generates_process_samples_with_same_run_id(self):
        temp_dir, runs_path, samples_path, runner = self.create_runner()

        try:
            result = runner.run(
                command=["python", "scripts/demo_monitored_process.py"],
                working_directory=str(ROOT_DIR),
                monitor_interval_seconds=0.1,
            )

            run_records = self.read_jsonl(runs_path)
            sample_records = self.read_jsonl(samples_path)

            self.assertEqual(result.status, "completed")
            self.assertTrue(result.monitoring_enabled)
            self.assertGreater(result.samples_count, 0)
            self.assertEqual(len(run_records), 1)
            self.assertGreater(len(sample_records), 0)
            self.assertEqual(run_records[0]["run_id"], result.run_id)

            for sample in sample_records:
                self.assertEqual(sample["run_id"], result.run_id)
                self.assertEqual(sample["pid"], result.pid)
                self.assertIn("timestamp", sample)
                self.assertIn("memory_rss_mb", sample)
                self.assertIn("cpu_percent", sample)
                self.assertIn("alive", sample)
        finally:
            temp_dir.cleanup()

    def test_monitoring_can_be_disabled_for_sandbox_run(self):
        temp_dir, runs_path, samples_path, runner = self.create_runner()

        try:
            result = runner.run(
                command=["echo", "monitoring disabled"],
                working_directory=str(ROOT_DIR),
                monitoring_enabled=False,
            )

            run_records = self.read_jsonl(runs_path)
            sample_records = self.read_jsonl(samples_path)

            self.assertEqual(result.status, "completed")
            self.assertFalse(result.monitoring_enabled)
            self.assertEqual(result.samples_count, 0)
            self.assertEqual(len(run_records), 1)
            self.assertEqual(len(sample_records), 0)
        finally:
            temp_dir.cleanup()

    def test_blocked_command_does_not_generate_process_samples(self):
        temp_dir, runs_path, samples_path, runner = self.create_runner()

        try:
            result = runner.run(
                command=["rm", "-rf", "/tmp/unsafe-monitoring-test"],
                working_directory=str(ROOT_DIR),
            )

            run_records = self.read_jsonl(runs_path)
            sample_records = self.read_jsonl(samples_path)

            self.assertEqual(result.status, "blocked")
            self.assertFalse(result.policy_allowed)
            self.assertFalse(result.monitoring_enabled)
            self.assertEqual(result.samples_count, 0)
            self.assertEqual(len(run_records), 1)
            self.assertEqual(len(sample_records), 0)
        finally:
            temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
