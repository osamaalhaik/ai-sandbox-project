import tempfile
import unittest
from pathlib import Path

from app.sandbox.cgroup_v2 import (
    CgroupV2Handle,
    CgroupV2Limits,
)
from app.sandbox.private_root_runner import (
    PrivateRootRunner,
)


ROOT_DIR = Path(__file__).resolve().parents[1]


class FakeCgroupManager:
    def __init__(
        self,
        snapshot=None,
        cleanup_result=True,
    ):
        self.snapshot_value = (
            snapshot
            or {
                "cpu_throttled": False,
                "oom_killed": False,
                "pids_limit_hit": False,
            }
        )

        self.cleanup_result = (
            cleanup_result
        )

        self.created = []
        self.attached = []
        self.cleaned = []

    def create_run(
        self,
        run_id,
        limits,
    ):
        handle = CgroupV2Handle(
            run_id=run_id,
            path=f"/fake/{run_id}",
            limits={
                "cpu_quota_us": (
                    limits.cpu_quota_us
                )
            },
            created_at="unit-test",
        )

        self.created.append(
            handle
        )

        return handle

    def attach_pid(
        self,
        handle,
        process_id,
    ):
        self.attached.append(
            (
                handle,
                process_id,
            )
        )

    def snapshot(
        self,
        handle,
    ):
        return {
            "run_id": (
                handle.run_id
            ),
            **self.snapshot_value,
        }

    def cleanup(
        self,
        handle,
        kill_remaining=False,
    ):
        self.cleaned.append(
            (
                handle,
                kill_remaining,
            )
        )

        return self.cleanup_result


class PrivateRootCgroupTests(
    unittest.TestCase
):
    def run_with_manager(
        self,
        manager,
        limits=None,
    ):
        temporary_directory = (
            tempfile.TemporaryDirectory()
        )

        directory = Path(
            temporary_directory.name
        )

        runner = PrivateRootRunner(
            output_path=str(
                directory
                / "runs.jsonl"
            ),
            samples_output_path=str(
                directory
                / "samples.jsonl"
            ),
            cgroup_manager=manager,
        )

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
            resource_limits=(
                limits
                or CgroupV2Limits()
            ),
        )

        return (
            temporary_directory,
            result,
        )

    def test_cgroup_is_attached_before_target_execution(self):
        manager = FakeCgroupManager()

        temporary_directory, result = (
            self.run_with_manager(
                manager
            )
        )

        try:
            self.assertEqual(
                result.status,
                "completed",
                msg=result.stderr,
            )

            self.assertTrue(
                result.resource_controls_enabled
            )

            self.assertTrue(
                result.cgroup_attached
            )

            self.assertEqual(
                len(
                    manager.attached
                ),
                1,
            )

            self.assertEqual(
                manager.attached[0][1],
                result.wrapper_pid,
            )

            self.assertTrue(
                result.cgroup_cleaned
            )

        finally:
            temporary_directory.cleanup()

    def test_cgroup_snapshot_is_preserved(self):
        manager = FakeCgroupManager(
            snapshot={
                "cpu_throttled": True,
                "oom_killed": False,
                "pids_limit_hit": True,
            }
        )

        temporary_directory, result = (
            self.run_with_manager(
                manager
            )
        )

        try:
            self.assertTrue(
                result.cpu_throttled
            )

            self.assertFalse(
                result.oom_killed
            )

            self.assertTrue(
                result.pids_limit_hit
            )

            self.assertEqual(
                result.cgroup_snapshot[
                    "run_id"
                ],
                result.run_id,
            )

        finally:
            temporary_directory.cleanup()

    def test_oom_event_classifies_run_failure(self):
        manager = FakeCgroupManager(
            snapshot={
                "cpu_throttled": False,
                "oom_killed": True,
                "pids_limit_hit": False,
            }
        )

        temporary_directory, result = (
            self.run_with_manager(
                manager
            )
        )

        try:
            self.assertEqual(
                result.status,
                "failed",
            )

            self.assertEqual(
                result.failure_reason,
                "cgroup_memory_limit_exceeded",
            )

            self.assertTrue(
                result.oom_killed
            )

        finally:
            temporary_directory.cleanup()

    def test_cleanup_failure_is_reported(self):
        manager = FakeCgroupManager(
            cleanup_result=False
        )

        temporary_directory, result = (
            self.run_with_manager(
                manager
            )
        )

        try:
            self.assertEqual(
                result.status,
                "failed",
            )

            self.assertEqual(
                result.failure_reason,
                "cgroup_cleanup_failed",
            )

            self.assertFalse(
                result.cgroup_cleaned
            )

        finally:
            temporary_directory.cleanup()


if __name__ == "__main__":
    unittest.main()
