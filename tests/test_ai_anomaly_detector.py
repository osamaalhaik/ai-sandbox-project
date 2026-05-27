import json
import tempfile
import unittest
from pathlib import Path

from app.ai.anomaly_detector import AIAnomalyDetector, AI_FEATURE_COLUMNS


class AIAnomalyDetectorTests(unittest.TestCase):
    def create_detector(self):
        temp_dir = tempfile.TemporaryDirectory()
        base_path = Path(temp_dir.name)
        detector = AIAnomalyDetector(
            model_path=str(base_path / "ai_anomaly_model.joblib"),
            metadata_path=str(base_path / "ai_anomaly_metadata.json"),
            features_path=str(base_path / "behavioral_features.jsonl"),
            output_path=str(base_path / "ai_inference_results.jsonl"),
        )
        return temp_dir, base_path, detector

    def write_feature_records(self, path, records):
        with path.open("w", encoding="utf-8") as file:
            for record in records:
                file.write(json.dumps(record) + "\n")

    def read_jsonl(self, path):
        if not path.exists():
            return []

        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def test_training_creates_model_and_metadata(self):
        temp_dir, base_path, detector = self.create_detector()

        try:
            result = detector.train()

            self.assertTrue(Path(result.model_path).exists())
            self.assertTrue(Path(result.metadata_path).exists())
            self.assertGreaterEqual(result.training_records_count, 8)
            self.assertEqual(result.feature_columns_count, len(AI_FEATURE_COLUMNS))

            metadata = json.loads(Path(result.metadata_path).read_text(encoding="utf-8"))

            self.assertEqual(metadata["model_type"], "IsolationForest")
            self.assertEqual(metadata["feature_columns"], AI_FEATURE_COLUMNS)
        finally:
            temp_dir.cleanup()

    def test_safe_record_inference_returns_low_or_normal_result(self):
        temp_dir, base_path, detector = self.create_detector()

        try:
            detector.train()
            record = detector.template_record(
                "safe-ai-test",
                180,
                178,
                2,
                0,
                24,
                0,
                False,
                False,
                False,
                False,
                0.02,
            )

            result = detector.infer_record(record, persist=True)
            persisted = self.read_jsonl(base_path / "ai_inference_results.jsonl")

            self.assertEqual(result.run_id, "safe-ai-test")
            self.assertGreaterEqual(result.ai_anomaly_score, 0)
            self.assertLessEqual(result.ai_anomaly_score, 100)
            self.assertIn(result.ai_prediction, {"normal", "anomaly"})
            self.assertIn(result.ai_risk_level, {"low", "suspicious", "high"})
            self.assertEqual(len(persisted), 1)
            self.assertEqual(persisted[0]["run_id"], "safe-ai-test")
        finally:
            temp_dir.cleanup()

    def test_sensitive_path_record_increases_ai_risk_signal(self):
        temp_dir, base_path, detector = self.create_detector()

        try:
            detector.train()
            record = detector.template_record(
                "sensitive-ai-test",
                350,
                347,
                2,
                0,
                24,
                1,
                False,
                False,
                False,
                True,
                0.10,
            )

            result = detector.infer_record(record, persist=False)

            self.assertEqual(result.run_id, "sensitive-ai-test")
            self.assertGreaterEqual(result.ai_anomaly_score, 35)
            self.assertIn(result.ai_risk_level, {"suspicious", "high"})
            self.assertIn("sensitive filesystem path access", result.ai_explanation)
        finally:
            temp_dir.cleanup()

    def test_infer_by_run_id_reads_feature_record(self):
        temp_dir, base_path, detector = self.create_detector()

        try:
            features_path = base_path / "behavioral_features.jsonl"
            record = detector.template_record(
                "lookup-ai-test",
                260,
                210,
                2,
                8,
                20,
                0,
                False,
                False,
                True,
                False,
                0.12,
            )

            self.write_feature_records(features_path, [record])
            detector.train(str(features_path))

            result = detector.infer_by_run_id("lookup-ai-test", persist=True)
            persisted = self.read_jsonl(base_path / "ai_inference_results.jsonl")

            self.assertEqual(result.run_id, "lookup-ai-test")
            self.assertGreaterEqual(result.ai_anomaly_score, 15)
            self.assertIn("network syscall activity", result.ai_explanation)
            self.assertEqual(len(persisted), 1)
        finally:
            temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
