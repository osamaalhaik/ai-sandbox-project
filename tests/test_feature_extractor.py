import unittest

from app.features.extractor import BehavioralFeatureExtractor


class BehavioralFeatureExtractorTests(unittest.TestCase):
    def setUp(self):
        self.extractor = BehavioralFeatureExtractor()

    def build_run_record(self, **overrides):
        record = {
            "run_id": "run-001",
            "command": ["python", "scripts/demo.py"],
            "command_hash": "hash-001",
            "status": "completed",
            "exit_code": 0,
            "policy_allowed": True,
            "failure_reason": None,
            "timed_out": False,
            "killed_by_timeout": False,
            "duration_seconds": 2.5,
            "resource_limits": {
                "timeout_seconds": 10,
                "max_cpu_seconds": 5,
                "max_memory_mb": 256,
                "max_open_files": 64,
            },
        }

        record.update(overrides)
        return record

    def build_summary_record(self, **overrides):
        record = {
            "run_id": "run-001",
            "samples_count": 10,
            "observed_duration_seconds": 2.0,
            "max_cpu_percent": 15.0,
            "avg_cpu_percent": 5.0,
            "max_memory_rss_mb": 64.0,
            "avg_memory_rss_mb": 32.0,
            "max_memory_vms_mb": 128.0,
            "avg_memory_vms_mb": 70.0,
            "max_threads_count": 2,
            "max_children_count": 1,
            "max_open_files_count": 8,
            "observed_statuses": ["running", "sleeping"],
            "errors_count": 0,
            "had_errors": False,
            "last_sample_alive": False,
        }

        record.update(overrides)
        return record

    def test_completed_process_features_are_extracted(self):
        run_record = self.build_run_record()
        summary_record = self.build_summary_record()

        features = self.extractor.extract_from_records(run_record, summary_record)

        self.assertEqual(features.run_id, "run-001")
        self.assertEqual(features.executable, "python")
        self.assertEqual(features.command_length, 2)
        self.assertEqual(features.status, "completed")
        self.assertEqual(features.exit_code, 0)
        self.assertTrue(features.policy_allowed)
        self.assertFalse(features.blocked_by_policy)
        self.assertFalse(features.timed_out)
        self.assertFalse(features.killed_by_timeout)
        self.assertEqual(features.samples_count, 10)
        self.assertEqual(features.max_memory_rss_mb, 64.0)
        self.assertEqual(features.observed_statuses_count, 2)
        self.assertFalse(features.non_zero_exit)
        self.assertFalse(features.abnormal_termination)

    def test_blocked_process_features_are_extracted_without_summary(self):
        run_record = self.build_run_record(
            command=["rm", "-rf", "/tmp/demo"],
            status="blocked",
            exit_code=None,
            policy_allowed=False,
            failure_reason="blocked_by_policy",
            duration_seconds=0.001,
        )

        features = self.extractor.extract_from_records(run_record, None)

        self.assertEqual(features.status, "blocked")
        self.assertEqual(features.executable, "rm")
        self.assertFalse(features.policy_allowed)
        self.assertTrue(features.blocked_by_policy)
        self.assertEqual(features.samples_count, 0)
        self.assertEqual(features.max_memory_rss_mb, 0.0)
        self.assertEqual(features.memory_rss_to_limit_ratio, 0.0)
        self.assertEqual(features.open_files_to_limit_ratio, 0.0)
        self.assertFalse(features.non_zero_exit)
        self.assertTrue(features.abnormal_termination)

    def test_timed_out_process_features_are_extracted(self):
        run_record = self.build_run_record(
            command=["sleep", "5"],
            status="timed_out",
            exit_code=-9,
            timed_out=True,
            killed_by_timeout=True,
            failure_reason="timeout_exceeded",
        )

        summary_record = self.build_summary_record(samples_count=4)

        features = self.extractor.extract_from_records(run_record, summary_record)

        self.assertEqual(features.status, "timed_out")
        self.assertTrue(features.timed_out)
        self.assertTrue(features.killed_by_timeout)
        self.assertTrue(features.non_zero_exit)
        self.assertTrue(features.abnormal_termination)
        self.assertEqual(features.samples_count, 4)

    def test_resource_ratios_are_calculated_correctly(self):
        run_record = self.build_run_record(
            resource_limits={
                "timeout_seconds": 10,
                "max_cpu_seconds": 5,
                "max_memory_mb": 256,
                "max_open_files": 64,
            }
        )

        summary_record = self.build_summary_record(
            max_memory_rss_mb=128.0,
            max_memory_vms_mb=256.0,
            max_open_files_count=32,
        )

        features = self.extractor.extract_from_records(run_record, summary_record)

        self.assertEqual(features.memory_rss_to_limit_ratio, 0.5)
        self.assertEqual(features.memory_vms_to_limit_ratio, 1.0)
        self.assertEqual(features.open_files_to_limit_ratio, 0.5)

    def test_missing_summary_defaults_to_zero_monitoring_features(self):
        run_record = self.build_run_record()

        features = self.extractor.extract_from_records(run_record, None)

        self.assertEqual(features.samples_count, 0)
        self.assertEqual(features.observed_duration_seconds, 0.0)
        self.assertEqual(features.max_cpu_percent, 0.0)
        self.assertEqual(features.avg_cpu_percent, 0.0)
        self.assertEqual(features.max_memory_rss_mb, 0.0)
        self.assertEqual(features.avg_memory_rss_mb, 0.0)
        self.assertEqual(features.observed_statuses_count, 0)
        self.assertEqual(features.errors_count, 0)
        self.assertFalse(features.had_monitoring_errors)
        self.assertFalse(features.last_sample_alive)
        self.assertFalse(features.abnormal_termination)


if __name__ == "__main__":
    unittest.main()
