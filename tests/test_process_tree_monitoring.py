import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import psutil

from app.monitoring.process_monitor import ProcessMonitor


ROOT_DIR = Path(__file__).resolve().parents[1]


class ProcessTreeMonitoringTests(unittest.TestCase):
    def create_monitor(self):
        temporary_directory = (
            tempfile.TemporaryDirectory()
        )

        output_path = (
            Path(temporary_directory.name)
            / "process_samples.jsonl"
        )

        monitor = ProcessMonitor(
            output_path=str(output_path)
        )

        return (
            temporary_directory,
            output_path,
            monitor,
        )

    def start_tree_process(self):
        return subprocess.Popen(
            [
                sys.executable,
                "scripts/demo_process_tree.py",
            ],
            cwd=str(ROOT_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )

    def test_direct_process_tree_is_aggregated(self):
        (
            temporary_directory,
            output_path,
            monitor,
        ) = self.create_monitor()

        process = self.start_tree_process()
        samples = []

        try:
            deadline = (
                time.monotonic()
                + 2.5
            )

            while (
                time.monotonic() < deadline
                and process.poll() is None
            ):
                sample = monitor.sample_tree(
                    run_id="tree-aggregation",
                    root_pid=process.pid,
                    include_root=True,
                )

                samples.append(sample)

                if sample.process_count >= 3:
                    break

                time.sleep(0.03)

            stdout, stderr = process.communicate(
                timeout=5
            )

            self.assertEqual(
                process.returncode,
                0,
                msg=stderr,
            )
            self.assertIn(
                "process_tree_demo_finished",
                stdout,
            )
            self.assertTrue(samples)
            self.assertGreaterEqual(
                max(
                    sample.process_count
                    for sample in samples
                ),
                3,
            )
            self.assertGreaterEqual(
                max(
                    sample.children_count
                    for sample in samples
                ),
                2,
            )
            self.assertGreater(
                max(
                    sample.memory_rss_mb
                    for sample in samples
                ),
                0,
            )
            self.assertGreaterEqual(
                max(
                    sample.threads_count
                    for sample in samples
                ),
                3,
            )
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()

            temporary_directory.cleanup()

    def test_sample_method_remains_compatible(self):
        (
            temporary_directory,
            output_path,
            monitor,
        ) = self.create_monitor()

        process = subprocess.Popen(
            ["sleep", "0.5"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            sample = monitor.sample(
                run_id="compatibility",
                pid=process.pid,
            )

            self.assertEqual(
                sample.pid,
                process.pid,
            )
            self.assertEqual(
                sample.root_pid,
                process.pid,
            )
            self.assertEqual(
                sample.target_pid,
                process.pid,
            )
            self.assertIsNone(
                sample.wrapper_pid
            )
            self.assertGreaterEqual(
                sample.process_count,
                1,
            )
            self.assertIn(
                process.pid,
                sample.monitored_pids,
            )
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait()

            temporary_directory.cleanup()

    def test_missing_process_returns_error_sample(self):
        (
            temporary_directory,
            output_path,
            monitor,
        ) = self.create_monitor()

        missing_pid = (
            max(psutil.pids())
            + 100000
        )

        try:
            sample = monitor.sample_tree(
                run_id="missing-process",
                root_pid=missing_pid,
            )

            self.assertFalse(
                sample.alive
            )
            self.assertEqual(
                sample.error,
                "no_such_process",
            )
            self.assertEqual(
                sample.process_count,
                0,
            )
            self.assertEqual(
                sample.monitored_pids,
                [],
            )
        finally:
            temporary_directory.cleanup()

    def test_monitored_process_ids_are_unique(self):
        (
            temporary_directory,
            output_path,
            monitor,
        ) = self.create_monitor()

        process = self.start_tree_process()

        try:
            deadline = (
                time.monotonic()
                + 2.5
            )
            selected_sample = None

            while (
                time.monotonic() < deadline
                and process.poll() is None
            ):
                sample = monitor.sample_tree(
                    run_id="unique-processes",
                    root_pid=process.pid,
                )

                if sample.process_count >= 3:
                    selected_sample = sample
                    break

                time.sleep(0.03)

            process.communicate(
                timeout=5
            )

            self.assertIsNotNone(
                selected_sample
            )
            self.assertEqual(
                len(
                    selected_sample.monitored_pids
                ),
                len(
                    set(
                        selected_sample.monitored_pids
                    )
                ),
            )
            self.assertEqual(
                selected_sample.process_count,
                len(
                    selected_sample.monitored_pids
                ),
            )
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()

            temporary_directory.cleanup()


if __name__ == "__main__":
    unittest.main()
