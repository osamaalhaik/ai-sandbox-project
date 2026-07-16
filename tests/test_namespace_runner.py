import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.sandbox.namespace_runner import (
    NamespaceProfile,
    NamespaceRunner,
)


ROOT_DIR = Path(__file__).resolve().parents[1]


class NamespaceRunnerTests(unittest.TestCase):
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

    def test_namespace_preflight_is_available(self):
        temporary_directory, runner = (
            self.create_runner()
        )

        try:
            result = runner.preflight()

            self.assertTrue(
                result["linux"]
            )
            self.assertTrue(
                result["available"]
            )
            self.assertEqual(
                result[
                    "unprivileged_userns_clone"
                ],
                1,
            )
            self.assertGreater(
                result[
                    "max_user_namespaces"
                ],
                0,
            )
        finally:
            temporary_directory.cleanup()

    def test_full_namespace_profile_is_verified(self):
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
            )

            target_output = json.loads(
                result.stdout.strip()
            )

            self.assertEqual(
                result.status,
                "completed",
                msg=result.stderr,
            )
            self.assertTrue(
                result.namespace_enabled
            )
            self.assertTrue(
                result.network_isolated
            )
            self.assertTrue(
                result.no_new_privileges_enabled
            )
            self.assertEqual(
                result.child_evidence["pid"],
                1,
            )
            self.assertEqual(
                target_output["pid"],
                1,
            )
            self.assertEqual(
                target_output[
                    "namespace_active"
                ],
                "1",
            )
            self.assertTrue(
                target_output[
                    "no_new_privileges"
                ]
            )
            self.assertEqual(
                target_output[
                    "network_interfaces"
                ],
                ["lo"],
            )
            self.assertTrue(
                all(
                    result.namespace_checks.values()
                )
            )
        finally:
            temporary_directory.cleanup()

    def test_profile_without_network_namespace(self):
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
                    network_isolation=False
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
            self.assertNotIn(
                "net",
                result.namespace_checks,
            )
            self.assertFalse(
                result.network_isolated
            )
        finally:
            temporary_directory.cleanup()

    def test_token_starting_with_dash_is_supported(self):
        temporary_directory, runner = (
            self.create_runner()
        )

        try:
            with patch(
                "app.sandbox.namespace_runner."
                "secrets.token_urlsafe",
                return_value=(
                    "-token-starting-with-dash"
                ),
            ):
                result = runner.run(
                    command=[
                        sys.executable,
                        "scripts/demo_namespace_probe.py",
                    ],
                    working_directory=str(
                        ROOT_DIR
                    ),
                    timeout_seconds=5,
                )

            self.assertEqual(
                result.status,
                "completed",
                msg=result.stderr,
            )
            self.assertTrue(
                result.namespace_enabled
            )
            self.assertTrue(
                result.no_new_privileges_enabled
            )
        finally:
            temporary_directory.cleanup()

    def test_namespace_timeout_kills_execution(self):
        temporary_directory, runner = (
            self.create_runner()
        )

        try:
            result = runner.run(
                command=[
                    "sleep",
                    "5",
                ],
                working_directory=str(
                    ROOT_DIR
                ),
                timeout_seconds=0.3,
            )

            self.assertEqual(
                result.status,
                "timed_out",
            )
            self.assertTrue(
                result.timed_out
            )
            self.assertEqual(
                result.failure_reason,
                "namespace_timeout_exceeded",
            )
        finally:
            temporary_directory.cleanup()


if __name__ == "__main__":
    unittest.main()
