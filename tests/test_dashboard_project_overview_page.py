import unittest

from fastapi.testclient import TestClient

from app.web_platform.api import app


class TestDashboardProjectOverviewPage(unittest.TestCase):
    def test_project_overview_page_renders_core_project_information(self):
        with TestClient(app) as client:
            response = client.get("/project-overview")

        self.assertEqual(response.status_code, 200)
        self.assertIn("ProcSentinel AI - Project Overview", response.text)
        self.assertIn("Execution Security Gateway", response.text)
        self.assertIn("Operating Systems Layer", response.text)
        self.assertIn("Cybersecurity Layer", response.text)
        self.assertIn("AI Layer", response.text)
        self.assertIn("Ran 84 tests OK", response.text)


if __name__ == "__main__":
    unittest.main()
