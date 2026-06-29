import unittest

from app.web_platform.reports import build_security_report, risk_bucket

class SecurityReportExportTests(unittest.TestCase):
    def test_risk_bucket(self):
        self.assertEqual(risk_bucket(0), "low")
        self.assertEqual(risk_bucket(35), "suspicious")
        self.assertEqual(risk_bucket(70), "high")
        self.assertEqual(risk_bucket(100), "critical")

    def test_build_security_report(self):
        report = build_security_report(
            stats={
                "total_runs": 3,
                "allowed": 1,
                "reviewed": 1,
                "blocked_or_investigate": 1,
                "alerts": 2,
                "sensitive_path_events": 1,
                "total_gateway_decisions": 2,
                "pending_approvals": 0,
                "critical_blocks": 1,
            },
            runs=[
                {
                    "run_id": "run-1",
                    "command": "rm -rf /tmp/demo",
                    "risk_score": 70,
                    "risk_level": "high",
                    "decision": "block_or_investigate",
                }
            ],
            gateway_decisions=[
                {
                    "gateway_decision_id": "gateway-1",
                    "command_text": "rm -rf /etc",
                    "risk_score": 100,
                    "risk_level": "critical",
                    "security_decision": "block_critical",
                    "final_lifecycle_status": "denied",
                }
            ],
            approval_decisions=[],
            alerts=[],
            generated_at="2026-06-29T00:00:00+00:00",
        )

        self.assertEqual(report["report_name"], "ProcSentinel Security Summary Report")
        self.assertEqual(report["executive_summary"]["total_runs"], 3)
        self.assertEqual(report["highest_risk_items"][0]["risk_score"], 100)
        self.assertTrue(report["recommendations"])

if __name__ == "__main__":
    unittest.main()
