import json
import tempfile
import unittest
from pathlib import Path

from app.detection.rules import RuleBasedDetector
from app.features.extractor import BehavioralFeatureExtractor
from app.monitoring.sample_summary import ProcessSampleSummarizer
from app.sandbox.runner import SandboxRunner


ROOT_DIR = Path(__file__).resolve().parents[1]


class DetectionPipelineTests(unittest.TestCase):
    def create_pipeline(self):
        temp_dir = tempfile.TemporaryDirectory()
        base_path = Path(temp_dir.name)
        runs_path = base_path / "sandbox_runs.jsonl"
        samples_path = base_path / "process_samples.jsonl"
        summaries_path = base_path / "process_sample_summaries.jsonl"
        features_path = base_path / "behavioral_features.jsonl"
        detection_path = base_path / "detection_results.jsonl"

        runner = SandboxRunner(
            output_path=str(runs_path),
            samples_output_path=str(samples_path),
        )

        summarizer = ProcessSampleSummarizer(
            samples_path=str(samples_path),
            output_path=str(summaries_path),
        )

        extractor = BehavioralFeatureExtractor(
            runs_path=str(runs_path),
            summaries_path=str(summaries_path),
            output_path=str(features_path),
        )

        detector = RuleBasedDetector(
            features_path=str(features_path),
            output_path=str(detection_path),
        )

        return temp_dir, runs_path, samples_path, summaries_path, features_path, detection_path, runner, summarizer, extractor, detector

    def read_jsonl(self, path):
        if not path.exists():
            return []

        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def rule_ids(self, detection_result):
        return [item.rule_id for item in detection_result.triggered_rules]

    def run_full_detection_pipeline(self, runner, summarizer, extractor, detector, command, **kwargs):
        run_result = runner.run(
            command=command,
            working_directory=str(ROOT_DIR),
            **kwargs,
        )

        sample_summary = summarizer.summarize(run_result.run_id)
        features = extractor.extract_by_run_id(run_result.run_id)
        detection_result = detector.detect_by_run_id(run_result.run_id)

        return run_result, sample_summary, features, detection_result

    def test_safe_process_pipeline_returns_low_risk(self):
        (
            temp_dir,
            runs_path,
            samples_path,
            summaries_path,
            features_path,
            detection_path,
            runner,
            summarizer,
            extractor,
            detector,
        ) = self.create_pipeline()

        try:
            run_result, sample_summary, features, detection_result = self.run_full_detection_pipeline(
                runner,
                summarizer,
                extractor,
                detector,
                ["python", "scripts/demo_monitored_process.py"],
                monitor_interval_seconds=0.1,
            )

            detection_records = self.read_jsonl(detection_path)

            self.assertEqual(run_result.status, "completed")
            self.assertGreater(sample_summary.samples_count, 0)
            self.assertEqual(features.status, "completed")
            self.assertEqual(detection_result.risk_score, 0)
            self.assertEqual(detection_result.risk_level, "low")
            self.assertEqual(detection_result.triggered_rules_count, 0)
            self.assertEqual(self.rule_ids(detection_result), [])
            self.assertEqual(len(detection_records), 1)
            self.assertEqual(detection_records[0]["run_id"], run_result.run_id)
        finally:
            temp_dir.cleanup()

    def test_blocked_command_pipeline_returns_high_risk(self):
        (
            temp_dir,
            runs_path,
            samples_path,
            summaries_path,
            features_path,
            detection_path,
            runner,
            summarizer,
            extractor,
            detector,
        ) = self.create_pipeline()

        try:
            run_result, sample_summary, features, detection_result = self.run_full_detection_pipeline(
                runner,
                summarizer,
                extractor,
                detector,
                ["rm", "-rf", "/tmp/detection-pipeline-test"],
            )

            detection_records = self.read_jsonl(detection_path)

            self.assertEqual(run_result.status, "blocked")
            self.assertEqual(sample_summary.samples_count, 0)
            self.assertEqual(features.status, "blocked")
            self.assertTrue(features.blocked_by_policy)
            self.assertEqual(detection_result.risk_score, 70)
            self.assertEqual(detection_result.risk_level, "high")
            self.assertEqual(detection_result.triggered_rules_count, 1)
            self.assertEqual(self.rule_ids(detection_result), ["POLICY_BLOCKED_COMMAND"])
            self.assertEqual(len(detection_records), 1)
            self.assertEqual(detection_records[0]["run_id"], run_result.run_id)
        finally:
            temp_dir.cleanup()

    def test_timeout_pipeline_returns_suspicious_risk(self):
        (
            temp_dir,
            runs_path,
            samples_path,
            summaries_path,
            features_path,
            detection_path,
            runner,
            summarizer,
            extractor,
            detector,
        ) = self.create_pipeline()

        try:
            run_result, sample_summary, features, detection_result = self.run_full_detection_pipeline(
                runner,
                summarizer,
                extractor,
                detector,
                ["sleep", "5"],
                timeout_seconds=1,
                monitor_interval_seconds=0.1,
            )

            detection_records = self.read_jsonl(detection_path)

            self.assertEqual(run_result.status, "timed_out")
            self.assertTrue(features.timed_out)
            self.assertTrue(features.killed_by_timeout)
            self.assertEqual(detection_result.risk_score, 35)
            self.assertEqual(detection_result.risk_level, "suspicious")
            self.assertEqual(detection_result.triggered_rules_count, 1)
            self.assertEqual(self.rule_ids(detection_result), ["PROCESS_TIMEOUT"])
            self.assertEqual(len(detection_records), 1)
            self.assertEqual(detection_records[0]["run_id"], run_result.run_id)
        finally:
            temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
