import unittest

from app.features.extractor import BehavioralFeatureExtractor


class SyscallFeatureExtractorTests(unittest.TestCase):
    def setUp(self):
        self.extractor = BehavioralFeatureExtractor()

    def build_run_record(self):
        return {
            "run_id": "run-syscall-001",
            "command": ["python", "scripts/demo_safe_process.py"],
            "command_hash": "hash-syscall-001",
            "status": "completed",
            "exit_code": 0,
            "policy_allowed": True,
            "failure_reason": None,
            "timed_out": False,
            "killed_by_timeout": False,
            "duration_seconds": 1.0,
            "resource_limits": {
                "timeout_seconds": 10,
                "max_cpu_seconds": 5,
                "max_memory_mb": 256,
                "max_open_files": 64,
            },
        }

    def build_process_summary(self):
        return {
            "run_id": "run-syscall-001",
            "samples_count": 5,
            "observed_duration_seconds": 1.0,
            "max_cpu_percent": 5.0,
            "avg_cpu_percent": 2.0,
            "max_memory_rss_mb": 32.0,
            "avg_memory_rss_mb": 16.0,
            "max_memory_vms_mb": 64.0,
            "avg_memory_vms_mb": 32.0,
            "max_threads_count": 1,
            "max_children_count": 0,
            "max_open_files_count": 2,
            "observed_statuses": ["running", "sleeping"],
            "errors_count": 0,
            "had_errors": False,
            "last_sample_alive": False,
        }

    def test_syscall_summary_features_are_extracted(self):
        run_record = self.build_run_record()
        process_summary = self.build_process_summary()
        syscall_summary = {
            "run_id": "run-syscall-001",
            "total_syscalls": 100,
            "file_syscalls_count": 80,
            "process_syscalls_count": 2,
            "network_syscalls_count": 1,
            "other_syscalls_count": 17,
            "successful_syscalls_count": 90,
            "failed_syscalls_count": 10,
            "unique_syscalls_count": 8,
            "unique_paths_count": 20,
            "sensitive_paths_count": 1,
            "execve_count": 1,
            "openat_count": 30,
            "access_count": 5,
            "connect_count": 1,
        }

        features = self.extractor.extract_from_records(
            run_record,
            process_summary,
            syscall_summary,
        )

        self.assertEqual(features.total_syscalls, 100)
        self.assertEqual(features.file_syscalls_count, 80)
        self.assertEqual(features.process_syscalls_count, 2)
        self.assertEqual(features.network_syscalls_count, 1)
        self.assertEqual(features.other_syscalls_count, 17)
        self.assertEqual(features.successful_syscalls_count, 90)
        self.assertEqual(features.failed_syscalls_count, 10)
        self.assertEqual(features.unique_syscalls_count, 8)
        self.assertEqual(features.unique_paths_count, 20)
        self.assertEqual(features.sensitive_paths_count, 1)
        self.assertEqual(features.execve_count, 1)
        self.assertEqual(features.openat_count, 30)
        self.assertEqual(features.access_count, 5)
        self.assertEqual(features.connect_count, 1)
        self.assertTrue(features.has_network_activity)
        self.assertTrue(features.accessed_sensitive_paths)

    def test_missing_syscall_summary_defaults_to_zero_features(self):
        run_record = self.build_run_record()
        process_summary = self.build_process_summary()

        features = self.extractor.extract_from_records(
            run_record,
            process_summary,
            None,
        )

        self.assertEqual(features.total_syscalls, 0)
        self.assertEqual(features.file_syscalls_count, 0)
        self.assertEqual(features.process_syscalls_count, 0)
        self.assertEqual(features.network_syscalls_count, 0)
        self.assertEqual(features.other_syscalls_count, 0)
        self.assertEqual(features.successful_syscalls_count, 0)
        self.assertEqual(features.failed_syscalls_count, 0)
        self.assertEqual(features.unique_syscalls_count, 0)
        self.assertEqual(features.unique_paths_count, 0)
        self.assertEqual(features.sensitive_paths_count, 0)
        self.assertEqual(features.execve_count, 0)
        self.assertEqual(features.openat_count, 0)
        self.assertEqual(features.access_count, 0)
        self.assertEqual(features.connect_count, 0)
        self.assertFalse(features.has_network_activity)
        self.assertFalse(features.accessed_sensitive_paths)

    def test_connect_count_marks_network_activity_even_without_network_category_count(self):
        run_record = self.build_run_record()
        process_summary = self.build_process_summary()
        syscall_summary = {
            "run_id": "run-syscall-001",
            "network_syscalls_count": 0,
            "connect_count": 1,
            "sensitive_paths_count": 0,
        }

        features = self.extractor.extract_from_records(
            run_record,
            process_summary,
            syscall_summary,
        )

        self.assertEqual(features.network_syscalls_count, 0)
        self.assertEqual(features.connect_count, 1)
        self.assertTrue(features.has_network_activity)
        self.assertFalse(features.accessed_sensitive_paths)

    def test_sensitive_paths_count_marks_sensitive_access(self):
        run_record = self.build_run_record()
        process_summary = self.build_process_summary()
        syscall_summary = {
            "run_id": "run-syscall-001",
            "network_syscalls_count": 0,
            "connect_count": 0,
            "sensitive_paths_count": 2,
        }

        features = self.extractor.extract_from_records(
            run_record,
            process_summary,
            syscall_summary,
        )

        self.assertEqual(features.sensitive_paths_count, 2)
        self.assertFalse(features.has_network_activity)
        self.assertTrue(features.accessed_sensitive_paths)


if __name__ == "__main__":
    unittest.main()
