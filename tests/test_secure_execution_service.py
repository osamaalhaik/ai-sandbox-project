import json
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from app.security.secure_execution import (
    SecureExecutionDenied,
    SecureExecutionService,
)


@dataclass
class FakeRunResult:
    run_id: str
    status: str
    failure_reason: str | None
    private_root_enabled: bool
    private_root_cleaned: bool
    resource_controls_enabled: bool
    cgroup_attached: bool
    cgroup_cleaned: bool
    cpu_throttled: bool
    oom_killed: bool
    pids_limit_hit: bool
    samples_count: int
    max_processes_observed: int
    stdout: str
    stderr: str


class FakeRunner:
    def __init__(self):
        self.calls = []

    def run(self, **kwargs):
        self.calls.append(
            kwargs
        )

        return FakeRunResult(
            run_id="fake-run-id",
            status="completed",
            failure_reason=None,
            private_root_enabled=True,
            private_root_cleaned=True,
            resource_controls_enabled=True,
            cgroup_attached=True,
            cgroup_cleaned=True,
            cpu_throttled=True,
            oom_killed=False,
            pids_limit_hit=False,
            samples_count=4,
            max_processes_observed=2,
            stdout="secure-output",
            stderr="",
        )


class SecureExecutionServiceTests(
    unittest.TestCase
):
    def create_service(self):
        temporary_directory = (
            tempfile.TemporaryDirectory()
        )

        output_path = (
            Path(
                temporary_directory.name
            )
            / "secure-executions.jsonl"
        )

        runner = FakeRunner()

        service = SecureExecutionService(
            output_path=str(
                output_path
            ),
            runner=runner,
        )

        return (
            temporary_directory,
            output_path,
            runner,
            service,
        )

    def test_blocked_strategy_fails_closed(self):
        (
            temporary_directory,
            output_path,
            runner,
            service,
        ) = self.create_service()

        try:
            with self.assertRaises(
                SecureExecutionDenied
            ):
                service.execute(
                    command=[
                        "echo",
                        "blocked",
                    ],
                    working_directory="/tmp",
                    execution_strategy=(
                        "do_not_execute"
                    ),
                )

            self.assertEqual(
                runner.calls,
                [],
            )

            self.assertFalse(
                output_path.exists()
            )

        finally:
            temporary_directory.cleanup()

    def test_confirmation_requires_approval(self):
        (
            temporary_directory,
            output_path,
            runner,
            service,
        ) = self.create_service()

        try:
            with self.assertRaises(
                SecureExecutionDenied
            ):
                service.execute(
                    command=[
                        "echo",
                        "review",
                    ],
                    working_directory="/tmp",
                    execution_strategy=(
                        "restricted_sandbox_"
                        "with_confirmation"
                    ),
                    approval_verified=False,
                )

            self.assertEqual(
                runner.calls,
                [],
            )

        finally:
            temporary_directory.cleanup()

    def test_execution_uses_profile_and_persists(self):
        (
            temporary_directory,
            output_path,
            runner,
            service,
        ) = self.create_service()

        try:
            record = service.execute(
                command=[
                    "echo",
                    "secure",
                ],
                working_directory="/tmp",
                execution_strategy=(
                    "restricted_sandbox"
                ),
                gateway_decision_id=(
                    "gateway-test"
                ),
            )

            self.assertEqual(
                len(runner.calls),
                1,
            )

            call = runner.calls[0]

            self.assertEqual(
                call[
                    "resource_limits"
                ].memory_max_bytes,
                268435456,
            )

            self.assertEqual(
                record[
                    "execution_profile"
                ],
                "standard",
            )

            self.assertEqual(
                record[
                    "gateway_decision_id"
                ],
                "gateway-test",
            )

            self.assertEqual(
                record["status"],
                "completed",
            )

            persisted = [
                json.loads(line)
                for line in (
                    output_path.read_text(
                        encoding="utf-8"
                    ).splitlines()
                )
                if line.strip()
            ]

            self.assertEqual(
                len(persisted),
                1,
            )

            self.assertEqual(
                persisted[0][
                    "secure_execution_id"
                ],
                record[
                    "secure_execution_id"
                ],
            )

        finally:
            temporary_directory.cleanup()

    def test_cgroup_evidence_is_exposed(self):
        (
            temporary_directory,
            output_path,
            runner,
            service,
        ) = self.create_service()

        try:
            record = service.execute(
                command=[
                    "echo",
                    "evidence",
                ],
                working_directory="/tmp",
                execution_strategy=(
                    "lightweight_sandbox"
                ),
            )

            self.assertTrue(
                record[
                    "private_root_enabled"
                ]
            )

            self.assertTrue(
                record[
                    "resource_controls_enabled"
                ]
            )

            self.assertTrue(
                record[
                    "cgroup_attached"
                ]
            )

            self.assertTrue(
                record[
                    "cgroup_cleaned"
                ]
            )

            self.assertTrue(
                record[
                    "cpu_throttled"
                ]
            )

            self.assertFalse(
                record[
                    "oom_killed"
                ]
            )

            self.assertEqual(
                record[
                    "samples_count"
                ],
                4,
            )

            self.assertEqual(
                len(
                    service.latest()
                ),
                1,
            )

            self.assertIsNotNone(
                service.find(
                    record[
                        "secure_execution_id"
                    ]
                )
            )

        finally:
            temporary_directory.cleanup()


if __name__ == "__main__":
    unittest.main()
