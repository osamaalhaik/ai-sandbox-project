import os
import tempfile
import unittest
from pathlib import Path

from app.sandbox.cgroup_v2 import (
    CgroupV2Limits,
    CgroupV2Manager,
)


class CgroupV2ManagerTests(
    unittest.TestCase
):
    def create_fake_root(self):
        temporary_directory = (
            tempfile.TemporaryDirectory()
        )

        root = Path(
            temporary_directory.name
        )

        (
            root
            / "cgroup.controllers"
        ).write_text(
            "cpu memory pids io\n",
            encoding="utf-8",
        )

        (
            root
            / "cgroup.subtree_control"
        ).write_text(
            "",
            encoding="utf-8",
        )

        (
            root
            / "cgroup.procs"
        ).write_text(
            f"{os.getpid()}\n",
            encoding="utf-8",
        )

        return (
            temporary_directory,
            root,
        )

    def test_limits_validation(self):
        limits = CgroupV2Limits(
            cpu_quota_us=20000,
            cpu_period_us=100000,
            memory_max_bytes=33554432,
            memory_swap_max_bytes=0,
            pids_max=12,
        )

        limits.validate()

        with self.assertRaises(
            ValueError
        ):
            CgroupV2Limits(
                memory_max_bytes=1024
            ).validate()

    def test_prepare_enables_required_controllers(self):
        temporary_directory, root = (
            self.create_fake_root()
        )

        try:
            manager = CgroupV2Manager(
                cgroup_mount=str(root),
                delegated_root=str(root),
            )

            result = manager.prepare()

            self.assertTrue(
                result["prepared"]
            )

            self.assertEqual(
                set(
                    result[
                        "subtree_control"
                    ]
                ),
                {
                    "cpu",
                    "memory",
                    "pids",
                },
            )

            self.assertTrue(
                (
                    root
                    / "manager"
                    / "cgroup.procs"
                ).exists()
            )

        finally:
            temporary_directory.cleanup()

    def test_create_run_writes_limits(self):
        temporary_directory, root = (
            self.create_fake_root()
        )

        try:
            manager = CgroupV2Manager(
                cgroup_mount=str(root),
                delegated_root=str(root),
            )

            handle = manager.create_run(
                "unit-test",
                CgroupV2Limits(
                    cpu_quota_us=20000,
                    cpu_period_us=100000,
                    memory_max_bytes=33554432,
                    memory_swap_max_bytes=0,
                    pids_max=12,
                ),
            )

            path = Path(
                handle.path
            )

            self.assertEqual(
                (
                    path
                    / "cpu.max"
                ).read_text(
                    encoding="utf-8"
                ),
                "20000 100000",
            )

            self.assertEqual(
                (
                    path
                    / "memory.max"
                ).read_text(
                    encoding="utf-8"
                ),
                "33554432",
            )

            self.assertEqual(
                (
                    path
                    / "pids.max"
                ).read_text(
                    encoding="utf-8"
                ),
                "12",
            )

        finally:
            temporary_directory.cleanup()

    def test_snapshot_parses_enforcement_events(self):
        temporary_directory, root = (
            self.create_fake_root()
        )

        try:
            manager = CgroupV2Manager(
                cgroup_mount=str(root),
                delegated_root=str(root),
            )

            handle = manager.create_run(
                "events",
                CgroupV2Limits(),
            )

            path = Path(
                handle.path
            )

            (
                path
                / "cpu.stat"
            ).write_text(
                (
                    "usage_usec 1000\n"
                    "nr_periods 10\n"
                    "nr_throttled 3\n"
                    "throttled_usec 500\n"
                ),
                encoding="utf-8",
            )

            (
                path
                / "memory.events"
            ).write_text(
                (
                    "low 0\n"
                    "high 0\n"
                    "max 2\n"
                    "oom 1\n"
                    "oom_kill 1\n"
                ),
                encoding="utf-8",
            )

            (
                path
                / "pids.events"
            ).write_text(
                "max 4\n",
                encoding="utf-8",
            )

            snapshot = manager.snapshot(
                handle
            )

            self.assertTrue(
                snapshot[
                    "cpu_throttled"
                ]
            )

            self.assertTrue(
                snapshot[
                    "oom_killed"
                ]
            )

            self.assertTrue(
                snapshot[
                    "pids_limit_hit"
                ]
            )

        finally:
            temporary_directory.cleanup()


if __name__ == "__main__":
    unittest.main()
