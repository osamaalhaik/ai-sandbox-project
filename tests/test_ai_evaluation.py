import json
import tempfile
import unittest
from pathlib import Path

from app.ai.evaluation import build_ai_evaluation_report, build_ai_evaluation_rows
from scripts.export_ai_evaluation import write_csv, write_json


class AIEvaluationTests(unittest.TestCase):
    def test_ai_evaluation_rows_include_core_scenarios(self):
        rows = build_ai_evaluation_rows()
        names = {row["name"] for row in rows}

        self.assertIn("safe_workspace_command", names)
        self.assertIn("outside_workspace_command", names)
        self.assertIn("sensitive_path_access", names)
        self.assertIn("critical_system_path_delete", names)

    def test_ai_evaluation_summary_positions_ai_as_assistant_signal(self):
        report = build_ai_evaluation_report()
        summary = report["summary"]

        self.assertEqual(summary["total_scenarios"], 4)
        self.assertEqual(summary["ai_normal_predictions"], 1)
        self.assertEqual(summary["ai_anomaly_predictions"], 3)
        self.assertIn("assistant signal", summary["positioning"])

    def test_ai_evaluation_report_contains_final_decisions(self):
        report = build_ai_evaluation_report()
        decisions = {row["final_decision"] for row in report["scenarios"]}

        self.assertIn("allow_with_monitoring", decisions)
        self.assertIn("require_confirmation", decisions)
        self.assertIn("review", decisions)
        self.assertIn("block_critical", decisions)

    def test_ai_evaluation_exports_json_and_csv(self):
        report = build_ai_evaluation_report()

        with tempfile.TemporaryDirectory() as temp_dir:
            json_path = Path(temp_dir) / "ai_evaluation_report.json"
            csv_path = Path(temp_dir) / "ai_evaluation_report.csv"

            write_json(report, json_path)
            write_csv(report, csv_path)

            loaded = json.loads(json_path.read_text(encoding="utf-8"))
            csv_text = csv_path.read_text(encoding="utf-8")

        self.assertEqual(loaded["title"], "ProcSentinel AI - AI Evaluation Evidence")
        self.assertIn("critical_system_path_delete", csv_text)
        self.assertIn("ai_prediction", csv_text)


if __name__ == "__main__":
    unittest.main()
