import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.web_platform.api import app


class TestDashboardAuthentication(unittest.TestCase):
    def test_dashboard_auth_disabled_by_default(self):
        with patch.dict(
            os.environ,
            {},
            clear=False,
        ):
            os.environ.pop(
                "PROCSENTINEL_DASHBOARD_AUTH_ENABLED",
                None,
            )
            os.environ.pop(
                "PROCSENTINEL_DASHBOARD_TOKEN",
                None,
            )

            with TestClient(app) as client:
                response = client.get(
                    "/project-overview"
                )

        self.assertEqual(
            response.status_code,
            200,
        )

    def test_html_redirects_to_login(self):
        with patch.dict(
            os.environ,
            {
                "PROCSENTINEL_DASHBOARD_AUTH_ENABLED": "true",
                "PROCSENTINEL_DASHBOARD_TOKEN": (
                    "unit-test-token"
                ),
            },
            clear=False,
        ):
            with TestClient(app) as client:
                response = client.get(
                    "/project-overview",
                    follow_redirects=False,
                )

        self.assertEqual(
            response.status_code,
            303,
        )
        self.assertEqual(
            response.headers["location"],
            "/login?next=/project-overview",
        )

    def test_api_returns_401_without_auth(self):
        with patch.dict(
            os.environ,
            {
                "PROCSENTINEL_DASHBOARD_AUTH_ENABLED": "true",
                "PROCSENTINEL_DASHBOARD_TOKEN": (
                    "unit-test-token"
                ),
            },
            clear=False,
        ):
            with TestClient(app) as client:
                response = client.get(
                    "/api/stats"
                )

        self.assertEqual(
            response.status_code,
            401,
        )

    def test_openapi_returns_401_without_auth(self):
        with patch.dict(
            os.environ,
            {
                "PROCSENTINEL_DASHBOARD_AUTH_ENABLED": "true",
                "PROCSENTINEL_DASHBOARD_TOKEN": (
                    "unit-test-token"
                ),
            },
            clear=False,
        ):
            with TestClient(app) as client:
                response = client.get(
                    "/openapi.json"
                )

        self.assertEqual(
            response.status_code,
            401,
        )

    def test_valid_header_token_allows_request(self):
        with patch.dict(
            os.environ,
            {
                "PROCSENTINEL_DASHBOARD_AUTH_ENABLED": "true",
                "PROCSENTINEL_DASHBOARD_TOKEN": (
                    "unit-test-token"
                ),
            },
            clear=False,
        ):
            with TestClient(app) as client:
                response = client.get(
                    "/project-overview",
                    headers={
                        "X-ProcSentinel-Token": (
                            "unit-test-token"
                        )
                    },
                )

        self.assertEqual(
            response.status_code,
            200,
        )
        self.assertEqual(
            response.headers["X-Frame-Options"],
            "DENY",
        )

    def test_valid_login_sets_cookie(self):
        with patch.dict(
            os.environ,
            {
                "PROCSENTINEL_DASHBOARD_AUTH_ENABLED": "true",
                "PROCSENTINEL_DASHBOARD_TOKEN": (
                    "unit-test-token"
                ),
                "PROCSENTINEL_DASHBOARD_COOKIE_SECURE": (
                    "false"
                ),
            },
            clear=False,
        ):
            with TestClient(app) as client:
                response = client.post(
                    "/login",
                    data={
                        "token": "unit-test-token",
                        "next": "/project-overview",
                    },
                    follow_redirects=False,
                )

                protected = client.get(
                    "/project-overview"
                )

        self.assertEqual(
            response.status_code,
            303,
        )
        self.assertIn(
            "HttpOnly",
            response.headers["set-cookie"],
        )
        self.assertIn(
            "SameSite=strict",
            response.headers["set-cookie"],
        )
        self.assertEqual(
            protected.status_code,
            200,
        )

    def test_invalid_login_is_rejected(self):
        with patch.dict(
            os.environ,
            {
                "PROCSENTINEL_DASHBOARD_AUTH_ENABLED": "true",
                "PROCSENTINEL_DASHBOARD_TOKEN": (
                    "unit-test-token"
                ),
            },
            clear=False,
        ):
            with TestClient(app) as client:
                response = client.post(
                    "/login",
                    data={
                        "token": "wrong-token",
                        "next": "/",
                    },
                )

        self.assertEqual(
            response.status_code,
            401,
        )

    def test_missing_token_fails_closed(self):
        with patch.dict(
            os.environ,
            {
                "PROCSENTINEL_DASHBOARD_AUTH_ENABLED": "true",
                "PROCSENTINEL_DASHBOARD_TOKEN": "",
            },
            clear=False,
        ):
            with TestClient(app) as client:
                response = client.get(
                    "/api/stats"
                )

        self.assertEqual(
            response.status_code,
            503,
        )


if __name__ == "__main__":
    unittest.main()
