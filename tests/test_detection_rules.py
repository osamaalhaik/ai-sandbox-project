import unittest

from app.detection.rules import RuleBasedDetector


class RuleBasedDetectorTests(unittest.TestCase):
    def setUp(self):
        self.detector = RuleBasedDetector()

    def build_features(self, **overrides):
        features = {
            "run_id": "run-001",
            "command_hash": "hash-001",
            "executable": "python",
            "status": "completed",
            "exit_code": 0,
            "policy_allowed": True,
            "blocked_by_policy": False,
            "timed_out": False,
            "killed_by_timeout": False,
            "duration_seconds": 2.0,
            "samples_count": 10,
            "observed_duration_seconds": 2.0,
            "max_cpu_percent": 0.0,
            "avg_cpu_percent": 0.0,
            "max_memory_rss_mb": 20.0,
            "avg_memory_rss_mb": 10.0,
            "max_memory_vms_mb": 30.0,
            "avg_memory_vms_mb": 15.0,
            "memory_rss_to_limit_ratio": 0.10,
            "memory_vms_to_limit_ratio": 0.20,
            "max_threads_count": 1,
            "max_children_count": 0,
            "max_open_files_count": 0,
            "open_files_to_limit_ratio": 0.0,
            "observed_statuses_count": 2,
            "errors_count": 0,
            "had_monitoring_errors": False,
            "last_sample_alive": False,
            "non_zero_exit": False,
            "abnormal_termination": False,
        }

        features.update(overrides)
        return features

    def rule_ids(self, result):
        return [item.rule_id for item in result.triggered_rules]

    def test_safe_process_has_low_risk_with_no_rules(self):
        features = self.build_features()

        result = self.detector.detect_from_features(features)

        self.assertEqual(result.risk_score, 0)
        self.assertEqual(result.risk_level, "low")
        self.assertEqual(result.triggered_rules_count, 0)
        self.assertEqual(result.triggered_rules, [])
        self.assertIn("No suspicious behavior", result.security_explanation)

    def test_blocked_command_generates_high_risk(self):
        features = self.build_features(
            executable="rm",
            status="blocked",
            policy_allowed=False,
            blocked_by_policy=True,
            samples_count=0,
            abnormal_termination=True,
        )

        result = self.detector.detect_from_features(features)

        self.assertEqual(result.risk_score, 70)
        self.assertEqual(result.risk_level, "high")
        self.assertEqual(result.triggered_rules_count, 1)
        self.assertEqual(self.rule_ids(result), ["POLICY_BLOCKED_COMMAND"])

    def test_timed_out_process_generates_suspicious_risk(self):
        features = self.build_features(
            executable="sleep",
            status="timed_out",
            exit_code=-9,
            timed_out=True,
            killed_by_timeout=True,
            non_zero_exit=True,
            abnormal_termination=True,
        )

        result = self.detector.detect_from_features(features)

        self.assertEqual(result.risk_score, 35)
        self.assertEqual(result.risk_level, "suspicious")
        self.assertEqual(self.rule_ids(result), ["PROCESS_TIMEOUT"])

    def test_non_zero_exit_generates_low_risk(self):
        features = self.build_features(
            status="failed",
            exit_code=2,
            non_zero_exit=True,
            abnormal_termination=True,
        )

        result = self.detector.detect_from_features(features)

        self.assertEqual(result.risk_score, 15)
        self.assertEqual(result.risk_level, "low")
        self.assertEqual(self.rule_ids(result), ["NON_ZERO_EXIT"])

    def test_high_memory_usage_triggers_memory_rule(self):
        features = self.build_features(
            memory_rss_to_limit_ratio=0.90,
            memory_vms_to_limit_ratio=0.20,
        )

        result = self.detector.detect_from_features(features)

        self.assertEqual(result.risk_score, 30)
        self.assertEqual(result.risk_level, "suspicious")
        self.assertEqual(self.rule_ids(result), ["HIGH_RSS_MEMORY_USAGE"])

    def test_high_open_files_usage_triggers_open_files_rule(self):
        features = self.build_features(
            open_files_to_limit_ratio=0.90,
        )

        result = self.detector.detect_from_features(features)

        self.assertEqual(result.risk_score, 30)
        self.assertEqual(result.risk_level, "suspicious")
        self.assertEqual(self.rule_ids(result), ["HIGH_OPEN_FILES_USAGE"])

    def test_child_process_creation_triggers_child_process_rule(self):
        features = self.build_features(
            max_children_count=5,
        )

        result = self.detector.detect_from_features(features)

        self.assertEqual(result.risk_score, 30)
        self.assertEqual(result.risk_level, "suspicious")
        self.assertEqual(self.rule_ids(result), ["HIGH_CHILD_PROCESS_COUNT"])

    def test_monitoring_errors_trigger_monitoring_rule(self):
        features = self.build_features(
            errors_count=1,
            had_monitoring_errors=True,
        )

        result = self.detector.detect_from_features(features)

        self.assertEqual(result.risk_score, 10)
        self.assertEqual(result.risk_level, "low")
        self.assertEqual(self.rule_ids(result), ["MONITORING_ERRORS_OBSERVED"])

    def test_allowed_process_without_samples_triggers_no_samples_rule(self):
        features = self.build_features(
            samples_count=0,
            policy_allowed=True,
            blocked_by_policy=False,
        )

        result = self.detector.detect_from_features(features)

        self.assertEqual(result.risk_score, 10)
        self.assertEqual(result.risk_level, "low")
        self.assertEqual(self.rule_ids(result), ["NO_RUNTIME_SAMPLES"])

    def test_multiple_rules_are_capped_at_100(self):
        features = self.build_features(
            executable="rm",
            status="blocked",
            policy_allowed=False,
            blocked_by_policy=True,
            timed_out=True,
            killed_by_timeout=True,
            non_zero_exit=True,
            memory_rss_to_limit_ratio=0.90,
            memory_vms_to_limit_ratio=1.0,
            open_files_to_limit_ratio=0.90,
            max_children_count=5,
            had_monitoring_errors=True,
            abnormal_termination=True,
        )

        result = self.detector.detect_from_features(features)

        self.assertEqual(result.risk_score, 100)
        self.assertEqual(result.risk_level, "high")
        self.assertGreater(result.triggered_rules_count, 1)


if __name__ == "__main__":
    unittest.main()
