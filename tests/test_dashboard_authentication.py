import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.web_platform.api import app


class TestDashboardAuthentication(unittest.TestCase):
    def test_dashboard_auth_disabled_by_default(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PROCSENTINEL_DASHBOARD_AUTH_ENABLED", None)
            os.environ.pop("PROCSENTINEL_DASHBOARD_TOKEN", None)

            with TestClient(app) as client:
                response = client.get("/project-overview")

        self.assertEqual(response.status_code, 200)
        self.assertIn("ProcSentinel AI - Project Overview", response.text)

    def test_dashboard_auth_blocks_request_when_enabled_without_token(self):
        with patch.dict(
            os.environ,
            {
                "PROCSENTINEL_DASHBOARD_AUTH_ENABLED": "true",
                "PROCSENTINEL_DASHBOARD_TOKEN": "unit-test-token",
            },
            clear=False,
        ):
            with TestClient(app) as client:
                response = client.get("/project-overview")

        self.assertEqual(response.status_code, 401)
        self.assertIn("authentication required", response.text)

    def test_dashboard_auth_allows_request_with_valid_header_token(self):
        with patch.dict(
            os.environ,
            {
                "PROCSENTINEL_DASHBOARD_AUTH_ENABLED": "true",
                "PROCSENTINEL_DASHBOARD_TOKEN": "unit-test-token",
            },
            clear=False,
        ):
            with TestClient(app) as client:
                response = client.get(
                    "/project-overview",
                    headers={"X-ProcSentinel-Token": "unit-test-token"},
                )

        self.assertEqual(response.status_code, 200)
        self.assertIn("ProcSentinel AI - Project Overview", response.text)

    def test_dashboard_auth_allows_request_with_query_token_and_sets_cookie(self):
        with patch.dict(
            os.environ,
            {
                "PROCSENTINEL_DASHBOARD_AUTH_ENABLED": "true",
                "PROCSENTINEL_DASHBOARD_TOKEN": "unit-test-token",
            },
            clear=False,
        ):
            with TestClient(app) as client:
                response = client.get("/project-overview?token=unit-test-token")
                second_response = client.get("/project-overview")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(second_response.status_code, 200)
        self.assertIn("ProcSentinel AI - Project Overview", second_response.text)


if __name__ == "__main__":
    unittest.main()
