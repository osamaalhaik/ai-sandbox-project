import unittest

from fastapi.testclient import TestClient

from app.web_platform.api import app
from app.web_platform.report_pdf_exports import security_report_to_pdf_bytes, security_report_to_text_lines


class TestSecurityReportPdfExport(unittest.TestCase):
    def test_security_report_to_text_lines_contains_core_sections(self):
        report = {
            "generated_at": "2026-01-01T00:00:00+00:00",
            "executive_summary": {
                "total_runs": 3,
                "alerts": 1,
            },
            "analysis_run_summary": {
                "risk_levels": {
                    "low": 1,
                },
                "decisions": {
                    "allow": 1,
                },
            },
            "gateway_summary": {
                "risk_levels": {
                    "critical": 1,
                },
                "security_decisions": {
                    "block_critical": 1,
                },
                "lifecycle_statuses": {
                    "denied": 1,
                },
            },
            "approval_summary": {
                "total_records": 0,
                "latest": [],
            },
            "alert_summary": {
                "total_records": 0,
                "latest": [],
            },
            "highest_risk_items": [
                {
                    "source": "gateway_decision",
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

        lines = security_report_to_text_lines(report)
        joined = "\n".join(lines)

        self.assertIn("Executive Summary", joined)
        self.assertIn("Gateway Summary", joined)
        self.assertIn("Highest Risk Items", joined)
        self.assertIn("Recommendations", joined)
        self.assertIn("rm -rf /etc", joined)

    def test_security_report_to_pdf_bytes_starts_with_pdf_header(self):
        report = {
            "executive_summary": {
                "total_runs": 1,
            },
            "analysis_run_summary": {},
            "gateway_summary": {},
            "approval_summary": {},
            "alert_summary": {},
            "highest_risk_items": [],
            "recommendations": [],
        }

        pdf_data = security_report_to_pdf_bytes(report)

        self.assertTrue(pdf_data.startswith(b"%PDF-1.4"))
        self.assertIn(b"ProcSentinel AI", pdf_data)

    def test_security_report_pdf_api(self):
        with TestClient(app) as client:
            response = client.get("/api/reports/security-summary.pdf")

        self.assertEqual(response.status_code, 200)
        self.assertIn("application/pdf", response.headers.get("content-type", ""))
        self.assertTrue(response.content.startswith(b"%PDF-1.4"))


if __name__ == "__main__":
    unittest.main()
