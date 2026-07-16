import json
import sys
import tempfile
import unittest
from pathlib import Path

from app.sandbox.namespace_runner import (
    NamespaceProfile,
    NamespaceRunner,
)


ROOT_DIR = Path(__file__).resolve().parents[1]


class NamespaceFilesystemTests(
    unittest.TestCase
):
    def create_runner(self):
        temporary_directory = (
            tempfile.TemporaryDirectory()
        )

        runner = NamespaceRunner(
            output_path=str(
                Path(
                    temporary_directory.name
                )
                / "namespace_runs.jsonl"
            )
        )

        return (
            temporary_directory,
            runner,
        )

    def run_filesystem_probe(self):
        temporary_directory, runner = (
            self.create_runner()
        )

        result = runner.run(
            command=[
                sys.executable,
                "scripts/demo_filesystem_isolation.py",
            ],
            working_directory=str(
                ROOT_DIR
            ),
            timeout_seconds=5,
        )

        return (
            temporary_directory,
            result,
        )

    def test_workspace_is_tmpfs_and_restricted(self):
        temporary_directory, result = (
            self.run_filesystem_probe()
        )

        try:
            filesystem = (
                result.child_evidence[
                    "filesystem"
                ]
            )

            self.assertEqual(
                result.status,
                "completed",
                msg=result.stderr,
            )

            self.assertTrue(
                result.filesystem_isolated
            )

            self.assertTrue(
                result.workspace_tmpfs
            )

            self.assertTrue(
                result.workspace_restricted
            )

            self.assertEqual(
                filesystem[
                    "workspace_mount"
                ][
                    "filesystem_type"
                ],
                "tmpfs",
            )

            options = set(
                filesystem[
                    "workspace_mount"
                ][
                    "mount_options"
                ]
            ) | set(
                filesystem[
                    "workspace_mount"
                ][
                    "super_options"
                ]
            )

            self.assertTrue(
                {
                    "nosuid",
                    "nodev",
                    "noexec",
                }.issubset(
                    options
                )
            )
        finally:
            temporary_directory.cleanup()

    def test_project_is_read_only_and_workspace_is_writable(self):
        temporary_directory, result = (
            self.run_filesystem_probe()
        )

        try:
            target = json.loads(
                result.stdout.strip()
            )

            self.assertTrue(
                result.project_read_only
            )

            self.assertTrue(
                target[
                    "project_readable"
                ]
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

            self.assertTrue(
                target[
                    "workspace_file_exists"
                ]
            )

            self.assertTrue(
                target[
                    "filesystem_isolated"
                ]
            )
        finally:
            temporary_directory.cleanup()

    def test_workspace_directory_is_cleaned(self):
        temporary_directory, result = (
            self.run_filesystem_probe()
        )

        try:
            self.assertTrue(
                result.workspace_cleaned
            )

            self.assertFalse(
                Path(
                    result.workspace_dir
                ).exists()
            )
        finally:
            temporary_directory.cleanup()

    def test_filesystem_profile_can_be_disabled(self):
        temporary_directory, runner = (
            self.create_runner()
        )

        try:
            result = runner.run(
                command=[
                    sys.executable,
                    "scripts/demo_namespace_probe.py",
                ],
                working_directory=str(
                    ROOT_DIR
                ),
                timeout_seconds=5,
                profile=NamespaceProfile(
                    filesystem_isolation=False,
                    project_read_only=False,
                ),
            )

            self.assertEqual(
                result.status,
                "completed",
                msg=result.stderr,
            )

            self.assertTrue(
                result.namespace_enabled
            )

            self.assertFalse(
                result.filesystem_isolated
            )

            self.assertFalse(
                result.project_read_only
            )

            self.assertTrue(
                result.workspace_cleaned
            )
        finally:
            temporary_directory.cleanup()


if __name__ == "__main__":
    unittest.main()
