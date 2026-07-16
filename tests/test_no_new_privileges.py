import tempfile
import unittest
from pathlib import Path

from app.sandbox.linux_security import read_no_new_privileges
from app.sandbox.runner import SandboxRunner


ROOT_DIR = Path(__file__).resolve().parents[1]


class NoNewPrivilegesTests(unittest.TestCase):
    def create_runner(self):
        temporary_directory = (
            tempfile.TemporaryDirectory()
        )

        directory = Path(
            temporary_directory.name
        )

        runner = SandboxRunner(
            output_path=str(
                directory
                / "runs.jsonl"
            ),
            samples_output_path=str(
                directory
                / "samples.jsonl"
            ),
        )

        return (
            temporary_directory,
            runner,
        )

    def test_proc_status_reader_returns_boolean(self):
        value = read_no_new_privileges()

        self.assertIsInstance(
            value,
            bool,
        )

    def test_sandbox_child_has_no_new_privileges(self):
        temporary_directory, runner = (
            self.create_runner()
        )

        try:
            result = runner.run(
                command=[
                    "python",
                    "scripts/demo_no_new_privileges.py",
                ],
                working_directory=str(
                    ROOT_DIR
                ),
                monitor_interval_seconds=0.03,
            )

            self.assertEqual(
                result.status,
                "completed",
                msg=result.stderr,
            )
            self.assertEqual(
                result.exit_code,
                0,
            )
            self.assertIn(
                "NoNewPrivs=1",
                result.stdout,
            )
            self.assertTrue(
                result.no_new_privileges_enabled
            )
        finally:
            temporary_directory.cleanup()

    def test_blocked_command_does_not_claim_control(self):
        temporary_directory, runner = (
            self.create_runner()
        )

        try:
            result = runner.run(
                command=[
                    "rm",
                    "-rf",
                    "/tmp/no-new-privileges-test",
                ],
                working_directory=str(
                    ROOT_DIR
                ),
            )

            self.assertEqual(
                result.status,
                "blocked",
            )
            self.assertFalse(
                result.no_new_privileges_enabled
            )
        finally:
            temporary_directory.cleanup()


if __name__ == "__main__":
    unittest.main()
