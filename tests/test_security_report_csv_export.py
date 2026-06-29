import csv
import io
import unittest

from fastapi.testclient import TestClient

from app.web_platform.api import app
from app.web_platform.report_exports import security_report_to_csv


class TestSecurityReportCsvExport(unittest.TestCase):
    def test_security_report_to_csv_contains_sections(self):
        report = {
            "executive_summary": {
                "total_runs": 3,
                "alerts": 1,
            },
            "analysis_run_summary": {
                "risk_levels": {
                    "low": 1,
                    "high": 1,
                },
                "decisions": {
                    "allow": 1,
                    "review": 1,
                },
            },
            "gateway_summary": {
                "risk_levels": {
                    "critical": 1,
                },
                "security_decisions": {
                    "block_critical": 1,
                },
            },
            "highest_risk_items": [
                {
                    "source": "gateway_decision",
                    "id": "abc",
                    "command": "rm -rf /etc",
                    "risk_score": 100,
                    "risk_level": "critical",
                    "decision": "block_critical",
                    "lifecycle_status": "denied",
                }
            ],
            "recommendations": [
                "Keep critical blocking enabled.",
            ],
        }

        csv_data = security_report_to_csv(report)
        rows = list(csv.DictReader(io.StringIO(csv_data)))
        sections = {row["section"] for row in rows}

        self.assertIn("executive_summary", sections)
        self.assertIn("analysis_risk_levels", sections)
        self.assertIn("gateway_security_decisions", sections)
        self.assertIn("highest_risk_items", sections)
        self.assertIn("recommendations", sections)
        self.assertIn("rm -rf /etc", csv_data)

    def test_security_report_csv_api(self):
        with TestClient(app) as client:
            response = client.get("/api/reports/security-summary.csv")

        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.headers.get("content-type", ""))
        self.assertIn("executive_summary", response.text)
        self.assertIn("highest_risk_items", response.text)


if __name__ == "__main__":
    unittest.main()
