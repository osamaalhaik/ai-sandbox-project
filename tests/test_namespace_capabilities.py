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

CAPABILITY_FIELDS = (
    "CapInh",
    "CapPrm",
    "CapEff",
    "CapBnd",
    "CapAmb",
)


class NamespaceCapabilityTests(unittest.TestCase):
    def run_probe(
        self,
        profile=None,
    ):
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

        result = runner.run(
            command=[
                sys.executable,
                "scripts/demo_namespace_probe.py",
            ],
            working_directory=str(
                ROOT_DIR
            ),
            timeout_seconds=5,
            profile=profile,
        )

        return (
            temporary_directory,
            result,
        )

    def assert_capabilities_zero(
        self,
        status,
    ):
        for field in CAPABILITY_FIELDS:
            with self.subTest(
                field=field
            ):
                self.assertIn(
                    field,
                    status,
                )
                self.assertEqual(
                    int(
                        status[field],
                        16,
                    ),
                    0,
                )

    def test_entrypoint_evidence_has_zero_capabilities(self):
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
                result.capabilities_dropped
            )
            self.assertTrue(
                result.namespace_enabled
            )
            self.assert_capabilities_zero(
                result.child_evidence[
                    "status"
                ]
            )
        finally:
            temporary_directory.cleanup()

    def test_target_keeps_zero_capabilities_after_exec(self):
        temporary_directory, result = (
            self.run_probe()
        )

        try:
            target = json.loads(
                result.stdout.strip()
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
            self.assert_capabilities_zero(
                target["status"]
            )
        finally:
            temporary_directory.cleanup()

    def test_capabilities_drop_without_network_namespace(self):
        temporary_directory, result = (
            self.run_probe(
                NamespaceProfile(
                    network_isolation=False
                )
            )
        )

        try:
            self.assertEqual(
                result.status,
                "completed",
                msg=result.stderr,
            )
            self.assertTrue(
                result.capabilities_dropped
            )
            self.assertNotIn(
                "net",
                result.namespace_checks,
            )
            self.assert_capabilities_zero(
                result.child_evidence[
                    "status"
                ]
            )
        finally:
            temporary_directory.cleanup()


if __name__ == "__main__":
    unittest.main()
