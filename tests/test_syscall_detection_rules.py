import unittest

from app.detection.rules import RuleBasedDetector


class SyscallDetectionRuleTests(unittest.TestCase):
    def setUp(self):
        self.detector = RuleBasedDetector()

    def build_features(self, **overrides):
        features = {
            "run_id": "run-syscall-detection-001",
            "command_hash": "hash-syscall-detection-001",
            "executable": "python",
            "status": "completed",
            "exit_code": 0,
            "policy_allowed": True,
            "blocked_by_policy": False,
            "timed_out": False,
            "killed_by_timeout": False,
            "duration_seconds": 1.0,
            "samples_count": 5,
            "observed_duration_seconds": 1.0,
            "max_cpu_percent": 5.0,
            "avg_cpu_percent": 2.0,
            "max_memory_rss_mb": 32.0,
            "avg_memory_rss_mb": 16.0,
            "max_memory_vms_mb": 64.0,
            "avg_memory_vms_mb": 32.0,
            "memory_rss_to_limit_ratio": 0.125,
            "memory_vms_to_limit_ratio": 0.25,
            "max_threads_count": 1,
            "max_children_count": 0,
            "max_open_files_count": 2,
            "open_files_to_limit_ratio": 0.03125,
            "observed_statuses_count": 2,
            "errors_count": 0,
            "had_monitoring_errors": False,
            "last_sample_alive": False,
            "non_zero_exit": False,
            "abnormal_termination": False,
            "total_syscalls": 100,
            "file_syscalls_count": 80,
            "process_syscalls_count": 2,
            "network_syscalls_count": 0,
            "other_syscalls_count": 18,
            "successful_syscalls_count": 95,
            "failed_syscalls_count": 0,
            "unique_syscalls_count": 8,
            "unique_paths_count": 20,
            "sensitive_paths_count": 0,
            "execve_count": 1,
            "openat_count": 30,
            "access_count": 5,
            "connect_count": 0,
            "has_network_activity": False,
            "accessed_sensitive_paths": False,
        }

        features.update(overrides)
        return features

    def rule_ids(self, result):
        return [item.rule_id for item in result.triggered_rules]

    def test_sensitive_path_access_triggers_syscall_rule(self):
        features = self.build_features(
            sensitive_paths_count=1,
            accessed_sensitive_paths=True,
        )

        result = self.detector.detect_from_features(features)

        self.assertEqual(result.risk_score, 45)
        self.assertEqual(result.risk_level, "suspicious")
        self.assertEqual(result.triggered_rules_count, 1)
        self.assertEqual(self.rule_ids(result), ["SENSITIVE_PATH_ACCESS"])

    def test_network_activity_triggers_syscall_rule(self):
        features = self.build_features(
            network_syscalls_count=1,
            connect_count=1,
            has_network_activity=True,
        )

        result = self.detector.detect_from_features(features)

        self.assertEqual(result.risk_score, 20)
        self.assertEqual(result.risk_level, "low")
        self.assertEqual(result.triggered_rules_count, 1)
        self.assertEqual(self.rule_ids(result), ["NETWORK_ACTIVITY_OBSERVED"])

    def test_failed_syscall_activity_triggers_syscall_rule(self):
        features = self.build_features(
            failed_syscalls_count=10,
        )

        result = self.detector.detect_from_features(features)

        self.assertEqual(result.risk_score, 15)
        self.assertEqual(result.risk_level, "low")
        self.assertEqual(result.triggered_rules_count, 1)
        self.assertEqual(self.rule_ids(result), ["FAILED_SYSCALL_ACTIVITY"])

    def test_failed_syscall_activity_below_threshold_does_not_trigger(self):
        features = self.build_features(
            failed_syscalls_count=9,
        )

        result = self.detector.detect_from_features(features)

        self.assertEqual(result.risk_score, 0)
        self.assertEqual(result.risk_level, "low")
        self.assertEqual(result.triggered_rules_count, 0)
        self.assertEqual(self.rule_ids(result), [])

    def test_combined_syscall_rules_generate_high_risk(self):
        features = self.build_features(
            network_syscalls_count=1,
            connect_count=1,
            has_network_activity=True,
            sensitive_paths_count=1,
            accessed_sensitive_paths=True,
            failed_syscalls_count=10,
        )

        result = self.detector.detect_from_features(features)

        self.assertEqual(result.risk_score, 80)
        self.assertEqual(result.risk_level, "high")
        self.assertEqual(result.triggered_rules_count, 3)
        self.assertEqual(
            self.rule_ids(result),
            [
                "SENSITIVE_PATH_ACCESS",
                "NETWORK_ACTIVITY_OBSERVED",
                "FAILED_SYSCALL_ACTIVITY",
            ],
        )


if __name__ == "__main__":
    unittest.main()
