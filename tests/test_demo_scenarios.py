import json
import unittest
from pathlib import Path

from scripts.run_demo_scenarios import DATA_FILES, SCENARIOS, reset_data_files, run_pipeline


ROOT_DIR = Path(__file__).resolve().parents[1]


class DemoScenarioTests(unittest.TestCase):
    def setUp(self):
        reset_data_files()

    def tearDown(self):
        reset_data_files()

    def read_demo_results(self):
        path = ROOT_DIR / "data/processed/demo_results.jsonl"

        if not path.exists():
            return []

        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def test_demo_scenarios_are_defined(self):
        self.assertIn("safe", SCENARIOS)
        self.assertIn("timeout", SCENARIOS)
        self.assertIn("blocked", SCENARIOS)

        for scenario in SCENARIOS.values():
            self.assertIn("title", scenario)
            self.assertIn("command", scenario)
            self.assertIn("timeout_seconds", scenario)
            self.assertIn("monitor_interval_seconds", scenario)

    def test_safe_demo_scenario_returns_low_risk(self):
        result = run_pipeline("safe", SCENARIOS["safe"])
        records = self.read_demo_results()

        self.assertEqual(result["scenario_id"], "safe")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "low")
        self.assertEqual(result["triggered_rules_count"], 0)
        self.assertEqual(result["triggered_rules"], [])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["scenario_id"], "safe")

    def test_timeout_demo_scenario_returns_suspicious_risk(self):
        result = run_pipeline("timeout", SCENARIOS["timeout"])
        records = self.read_demo_results()

        self.assertEqual(result["scenario_id"], "timeout")
        self.assertEqual(result["status"], "timed_out")
        self.assertEqual(result["risk_score"], 35)
        self.assertEqual(result["risk_level"], "suspicious")
        self.assertEqual(result["triggered_rules_count"], 1)
        self.assertEqual(result["triggered_rules"], ["PROCESS_TIMEOUT"])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["scenario_id"], "timeout")

    def test_blocked_demo_scenario_returns_high_risk(self):
        result = run_pipeline("blocked", SCENARIOS["blocked"])
        records = self.read_demo_results()

        self.assertEqual(result["scenario_id"], "blocked")
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["risk_score"], 70)
        self.assertEqual(result["risk_level"], "high")
        self.assertEqual(result["triggered_rules_count"], 1)
        self.assertEqual(result["triggered_rules"], ["POLICY_BLOCKED_COMMAND"])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["scenario_id"], "blocked")


if __name__ == "__main__":
    unittest.main()
