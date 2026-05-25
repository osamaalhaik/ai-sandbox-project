import json
import tempfile
import unittest
from pathlib import Path

from app.features.extractor import BehavioralFeatureExtractor
from app.monitoring.sample_summary import ProcessSampleSummarizer
from app.sandbox.runner import SandboxRunner


ROOT_DIR = Path(__file__).resolve().parents[1]


class BehavioralPipelineTests(unittest.TestCase):
    def create_pipeline(self):
        temp_dir = tempfile.TemporaryDirectory()
        base_path = Path(temp_dir.name)
        runs_path = base_path / "sandbox_runs.jsonl"
        samples_path = base_path / "process_samples.jsonl"
        summaries_path = base_path / "process_sample_summaries.jsonl"
        features_path = base_path / "behavioral_features.jsonl"

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

        return temp_dir, runs_path, samples_path, summaries_path, features_path, runner, summarizer, extractor

    def read_jsonl(self, path):
        if not path.exists():
            return []

        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def test_successful_behavior_pipeline_produces_consistent_outputs(self):
        (
            temp_dir,
            runs_path,
            samples_path,
            summaries_path,
            features_path,
            runner,
            summarizer,
            extractor,
        ) = self.create_pipeline()

        try:
            run_result = runner.run(
                command=["python", "scripts/demo_monitored_process.py"],
                working_directory=str(ROOT_DIR),
                monitor_interval_seconds=0.1,
            )

            sample_summary = summarizer.summarize(run_result.run_id)
            features = extractor.extract_by_run_id(run_result.run_id)

            run_records = self.read_jsonl(runs_path)
            sample_records = self.read_jsonl(samples_path)
            summary_records = self.read_jsonl(summaries_path)
            feature_records = self.read_jsonl(features_path)

            self.assertEqual(run_result.status, "completed")
            self.assertEqual(sample_summary.run_id, run_result.run_id)
            self.assertEqual(features.run_id, run_result.run_id)
            self.assertEqual(len(run_records), 1)
            self.assertGreater(len(sample_records), 0)
            self.assertEqual(len(summary_records), 1)
            self.assertEqual(len(feature_records), 1)
            self.assertGreater(sample_summary.samples_count, 0)
            self.assertGreater(features.samples_count, 0)
            self.assertEqual(features.executable, "python")
            self.assertFalse(features.abnormal_termination)

            for sample in sample_records:
                self.assertEqual(sample["run_id"], run_result.run_id)
                self.assertEqual(sample["pid"], run_result.pid)

            self.assertEqual(run_records[0]["run_id"], run_result.run_id)
            self.assertEqual(summary_records[0]["run_id"], run_result.run_id)
            self.assertEqual(feature_records[0]["run_id"], run_result.run_id)
        finally:
            temp_dir.cleanup()

    def test_blocked_command_pipeline_produces_blocked_features_without_samples(self):
        (
            temp_dir,
            runs_path,
            samples_path,
            summaries_path,
            features_path,
            runner,
            summarizer,
            extractor,
        ) = self.create_pipeline()

        try:
            run_result = runner.run(
                command=["rm", "-rf", "/tmp/blocked-pipeline-test"],
                working_directory=str(ROOT_DIR),
            )

            sample_summary = summarizer.summarize(run_result.run_id)
            features = extractor.extract_by_run_id(run_result.run_id)

            run_records = self.read_jsonl(runs_path)
            sample_records = self.read_jsonl(samples_path)
            summary_records = self.read_jsonl(summaries_path)
            feature_records = self.read_jsonl(features_path)

            self.assertEqual(run_result.status, "blocked")
            self.assertFalse(run_result.policy_allowed)
            self.assertEqual(sample_summary.samples_count, 0)
            self.assertEqual(features.status, "blocked")
            self.assertEqual(features.executable, "rm")
            self.assertTrue(features.blocked_by_policy)
            self.assertTrue(features.abnormal_termination)
            self.assertEqual(features.samples_count, 0)
            self.assertEqual(len(run_records), 1)
            self.assertEqual(len(sample_records), 0)
            self.assertEqual(len(summary_records), 1)
            self.assertEqual(len(feature_records), 1)
            self.assertEqual(run_records[0]["run_id"], run_result.run_id)
            self.assertEqual(summary_records[0]["run_id"], run_result.run_id)
            self.assertEqual(feature_records[0]["run_id"], run_result.run_id)
        finally:
            temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
