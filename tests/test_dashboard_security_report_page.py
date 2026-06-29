import unittest

from fastapi.testclient import TestClient

from app.web_platform.api import app


class TestDashboardSecurityReportPage(unittest.TestCase):
    def test_security_report_page_returns_html(self):
        with TestClient(app) as client:
            response = client.get("/reports/security-summary")

        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers.get("content-type", ""))
        self.assertIn("Security Summary Report", response.text)
        self.assertIn("Executive Summary", response.text)
        self.assertIn("/api/reports/security-summary", response.text)

    def test_security_report_api_still_returns_json(self):
        with TestClient(app) as client:
            response = client.get("/api/reports/security-summary")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["report_name"], "ProcSentinel Security Summary Report")


if __name__ == "__main__":
    unittest.main()
