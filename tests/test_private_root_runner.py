import json
import sys
import tempfile
import unittest
from pathlib import Path

from app.sandbox.private_root_runner import (
    PrivateRootRunner,
)


ROOT_DIR = Path(__file__).resolve().parents[1]


class PrivateRootRunnerTests(
    unittest.TestCase
):
    def create_runner(self):
        temporary_directory = (
            tempfile.TemporaryDirectory()
        )

        runner = PrivateRootRunner(
            output_path=str(
                Path(
                    temporary_directory.name
                )
                / "private_root_runs.jsonl"
            )
        )

        return (
            temporary_directory,
            runner,
        )

    def run_probe(self):
        temporary_directory, runner = (
            self.create_runner()
        )

        result = runner.run(
            command=[
                sys.executable,
                "scripts/demo_private_root.py",
            ],
            working_directory=str(
                ROOT_DIR
            ),
            timeout_seconds=8,
        )

        return (
            temporary_directory,
            result,
        )

    def test_preflight_is_available(self):
        temporary_directory, runner = (
            self.create_runner()
        )

        try:
            preflight = runner.preflight()

            self.assertTrue(
                preflight["linux"]
            )

            self.assertTrue(
                preflight["available"]
            )

            self.assertEqual(
                preflight[
                    "unprivileged_userns_clone"
                ],
                1,
            )

        finally:
            temporary_directory.cleanup()

    def test_private_root_is_verified(self):
        temporary_directory, result = (
            self.run_probe()
        )

        try:
            self.assertEqual(
                result.status,
                "completed",
                msg=result.stderr,
            )

            self.assertTrue(
                result.namespace_enabled
            )

            self.assertTrue(
                result.private_root_enabled
            )

            self.assertTrue(
                result.root_tmpfs
            )

            self.assertTrue(
                result.proc_mounted
            )

            self.assertTrue(
                result.host_root_hidden
            )

            self.assertTrue(
                result.proc_root_private
            )

        finally:
            temporary_directory.cleanup()

    def test_target_remains_pid_one(self):
        temporary_directory, result = (
            self.run_probe()
        )

        try:
            target = json.loads(
                result.stdout.strip()
            )

            self.assertEqual(
                result.child_evidence[
                    "pid"
                ],
                1,
            )

            self.assertEqual(
                target["pid"],
                1,
            )

            self.assertEqual(
                target["ppid"],
                0,
            )

        finally:
            temporary_directory.cleanup()

    def test_security_controls_survive_exec(self):
        temporary_directory, result = (
            self.run_probe()
        )

        try:
            target = json.loads(
                result.stdout.strip()
            )

            self.assertTrue(
                result.capabilities_dropped
            )

            self.assertTrue(
                result.no_new_privileges_enabled
            )

            self.assertTrue(
                target[
                    "capabilities_dropped"
                ]
            )

            self.assertTrue(
                target[
                    "no_new_privileges"
                ]
            )

            self.assertEqual(
                target["status"][
                    "CapEff"
                ],
                "0000000000000000",
            )

            self.assertEqual(
                target["status"][
                    "CapBnd"
                ],
                "0000000000000000",
            )

        finally:
            temporary_directory.cleanup()

    def test_filesystem_and_network_are_isolated(self):
        temporary_directory, result = (
            self.run_probe()
        )

        try:
            target = json.loads(
                result.stdout.strip()
            )

            self.assertTrue(
                result.project_read_only
            )

            self.assertTrue(
                result.workspace_tmpfs
            )

            self.assertTrue(
                result.workspace_restricted
            )

            self.assertTrue(
                result.network_isolated
            )

            self.assertTrue(
                target[
                    "project_write_blocked"
                ]
            )

            self.assertTrue(
                target[
                    "workspace_write_succeeded"
                ]
            )

            self.assertEqual(
                target[
                    "network_interfaces"
                ],
                ["lo"],
            )

        finally:
            temporary_directory.cleanup()

    def test_minimal_etc_and_cleanup(self):
        temporary_directory, result = (
            self.run_probe()
        )

        try:
            target = json.loads(
                result.stdout.strip()
            )

            self.assertTrue(
                result.minimal_etc
            )

            self.assertFalse(
                target[
                    "shadow_present"
                ]
            )

            self.assertIn(
                "passwd",
                target[
                    "etc_entries"
                ],
            )

            self.assertIn(
                "group",
                target[
                    "etc_entries"
                ],
            )

            self.assertFalse(
                target[
                    "host_root_alias_present"
                ]
            )

            self.assertTrue(
                result.private_root_cleaned
            )

            self.assertFalse(
                Path(
                    result.private_root_dir
                ).exists()
            )

        finally:
            temporary_directory.cleanup()


if __name__ == "__main__":
    unittest.main()
