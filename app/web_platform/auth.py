import os
from starlette.requests import Request
from starlette.responses import PlainTextResponse


AUTH_ENABLED_ENV = "PROCSENTINEL_DASHBOARD_AUTH_ENABLED"
AUTH_TOKEN_ENV = "PROCSENTINEL_DASHBOARD_TOKEN"
DEFAULT_TOKEN = "procsentinel-demo-token"
AUTH_COOKIE_NAME = "procsentinel_dashboard_token"


PUBLIC_PREFIXES = (
    "/static/",
    "/favicon.ico",
)


PROTECTED_PREFIXES = (
    "/",
    "/runs",
    "/alerts",
    "/approvals",
    "/reports",
    "/project-overview",
    "/api",
)


def is_dashboard_auth_enabled() -> bool:
    value = os.getenv(AUTH_ENABLED_ENV, "false").strip().lower()
    return value in {"1", "true", "yes", "on"}


def configured_dashboard_token() -> str:
    return os.getenv(AUTH_TOKEN_ENV, DEFAULT_TOKEN)


def path_requires_dashboard_auth(path: str) -> bool:
    if not is_dashboard_auth_enabled():
        return False

    if any(path.startswith(prefix) for prefix in PUBLIC_PREFIXES):
        return False

    if path == "/":
        return True

    return any(path.startswith(prefix + "/") or path == prefix for prefix in PROTECTED_PREFIXES if prefix != "/")


def request_token(request: Request) -> str:
    header_token = request.headers.get("X-ProcSentinel-Token", "")
    query_token = request.query_params.get("token", "")
    cookie_token = request.cookies.get(AUTH_COOKIE_NAME, "")

    return header_token or query_token or cookie_token


def is_authenticated_request(request: Request) -> bool:
    expected = configured_dashboard_token()
    provided = request_token(request)

    return bool(expected) and provided == expected


def should_set_auth_cookie(request: Request) -> bool:
    header_token = request.headers.get("X-ProcSentinel-Token", "")
    query_token = request.query_params.get("token", "")
    provided = header_token or query_token

    return bool(provided) and provided == configured_dashboard_token()


def install_dashboard_auth(app):
    @app.middleware("http")
    async def dashboard_auth_middleware(request: Request, call_next):
        if path_requires_dashboard_auth(request.url.path) and not is_authenticated_request(request):
            return PlainTextResponse(
                "ProcSentinel dashboard authentication required.",
                status_code=401,
            )

        response = await call_next(request)

        if should_set_auth_cookie(request):
            response.set_cookie(
                AUTH_COOKIE_NAME,
                configured_dashboard_token(),
                httponly=True,
                samesite="lax",
            )

        return response

    return app
