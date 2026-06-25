import json
import tempfile
import unittest
from pathlib import Path

from app.sandbox.runner import SandboxRunner


ROOT_DIR = Path(__file__).resolve().parents[1]


class SandboxRunnerTests(unittest.TestCase):
    def create_runner(self):
        temp_dir = tempfile.TemporaryDirectory()
        output_path = Path(temp_dir.name) / "sandbox_runs.jsonl"
        runner = SandboxRunner(output_path=str(output_path))
        return temp_dir, output_path, runner

    def read_last_record(self, output_path):
        lines = output_path.read_text(encoding="utf-8").splitlines()
        return json.loads(lines[-1])

    def test_echo_command_completes_successfully(self):
        temp_dir, output_path, runner = self.create_runner()

        try:
            result = runner.run(
                command=["echo", "test ok"],
                working_directory=str(ROOT_DIR),
            )

            record = self.read_last_record(output_path)

            self.assertEqual(result.status, "completed")
            self.assertEqual(result.exit_code, 0)
            self.assertFalse(result.timed_out)
            self.assertEqual(result.stdout, "test ok\n")
            self.assertTrue(result.policy_allowed)
            self.assertEqual(record["status"], "completed")
        finally:
            temp_dir.cleanup()

    def test_timeout_kills_long_running_process(self):
        temp_dir, output_path, runner = self.create_runner()

        try:
            result = runner.run(
                command=["sleep", "5"],
                timeout_seconds=1,
                working_directory=str(ROOT_DIR),
            )

            record = self.read_last_record(output_path)

            self.assertEqual(result.status, "timed_out")
            self.assertEqual(result.failure_reason, "timeout_exceeded")
            self.assertTrue(result.timed_out)
            self.assertTrue(result.killed_by_timeout)
            self.assertEqual(record["status"], "timed_out")
        finally:
            temp_dir.cleanup()

    def test_blocked_executable_is_not_started(self):
        temp_dir, output_path, runner = self.create_runner()

        try:
            result = runner.run(
                command=["rm", "-rf", "/tmp/unsafe-demo"],
                working_directory=str(ROOT_DIR),
            )

            record = self.read_last_record(output_path)

            self.assertEqual(result.status, "blocked")
            self.assertEqual(result.failure_reason, "blocked_by_policy")
            self.assertFalse(result.policy_allowed)
            self.assertEqual(result.policy_reason, "confirmation_required")
            self.assertIsNone(result.pid)
            self.assertEqual(record["status"], "blocked")
        finally:
            temp_dir.cleanup()

    def test_unsafe_python_mode_is_blocked(self):
        temp_dir, output_path, runner = self.create_runner()

        try:
            result = runner.run(
                command=["python", "-c", "print(123)"],
                working_directory=str(ROOT_DIR),
            )

            record = self.read_last_record(output_path)

            self.assertEqual(result.status, "blocked")
            self.assertEqual(result.failure_reason, "blocked_by_policy")
            self.assertFalse(result.policy_allowed)
            self.assertEqual(result.policy_reason, "unsafe_python_mode")
            self.assertIsNone(result.pid)
            self.assertEqual(record["policy_reason"], "unsafe_python_mode")
        finally:
            temp_dir.cleanup()

    def test_python_script_inside_scripts_directory_is_allowed(self):
        temp_dir, output_path, runner = self.create_runner()

        try:
            result = runner.run(
                command=["python", "scripts/demo_safe_process.py"],
                working_directory=str(ROOT_DIR),
            )

            record = self.read_last_record(output_path)

            self.assertEqual(result.status, "completed")
            self.assertEqual(result.exit_code, 0)
            self.assertTrue(result.policy_allowed)
            self.assertIn("safe_process_started", result.stdout)
            self.assertEqual(record["status"], "completed")
        finally:
            temp_dir.cleanup()

    def test_open_files_limit_is_enforced(self):
        temp_dir, output_path, runner = self.create_runner()

        try:
            result = runner.run(
                command=["python", "scripts/demo_open_files_stress.py"],
                max_open_files=32,
                timeout_seconds=8,
                working_directory=str(ROOT_DIR),
            )

            record = self.read_last_record(output_path)

            self.assertEqual(result.status, "failed")
            self.assertEqual(result.exit_code, 3)
            self.assertIn("open_files_limit_reached", result.stdout)
            self.assertEqual(record["resource_limits"]["max_open_files"], 32)
        finally:
            temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
