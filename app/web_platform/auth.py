import os
import secrets
from pathlib import Path
from urllib.parse import parse_qs, quote

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates


AUTH_ENABLED_ENV = "PROCSENTINEL_DASHBOARD_AUTH_ENABLED"
AUTH_TOKEN_ENV = "PROCSENTINEL_DASHBOARD_TOKEN"
COOKIE_SECURE_ENV = "PROCSENTINEL_DASHBOARD_COOKIE_SECURE"
SESSION_SECONDS_ENV = "PROCSENTINEL_DASHBOARD_SESSION_SECONDS"
AUTH_COOKIE_NAME = "procsentinel_dashboard_session"

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

PUBLIC_PATHS = {
    "/login",
    "/logout",
    "/favicon.ico",
}

PUBLIC_PREFIXES = (
    "/static/",
)

PROTECTED_PREFIXES = (
    "/runs",
    "/alerts",
    "/approvals",
    "/reports",
    "/project-overview",
    "/api",
    "/docs",
    "/redoc",
)

UNSAFE_METHODS = {
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
}


def env_flag(name: str, default: str = "false") -> bool:
    value = os.getenv(name, default).strip().lower()
    return value in {"1", "true", "yes", "on"}


def is_dashboard_auth_enabled() -> bool:
    return env_flag(AUTH_ENABLED_ENV)


def configured_dashboard_token() -> str:
    return os.getenv(AUTH_TOKEN_ENV, "").strip()


def configured_session_seconds() -> int:
    raw_value = os.getenv(SESSION_SECONDS_ENV, "28800").strip()

    try:
        value = int(raw_value)
    except ValueError:
        return 28800

    return max(300, min(value, 86400))


def cookie_secure_enabled() -> bool:
    return env_flag(COOKIE_SECURE_ENV)


def path_requires_dashboard_auth(path: str) -> bool:
    if not is_dashboard_auth_enabled():
        return False

    if path in PUBLIC_PATHS:
        return False

    if any(path.startswith(prefix) for prefix in PUBLIC_PREFIXES):
        return False

    if path in {"/", "/openapi.json"}:
        return True

    return any(
        path == prefix or path.startswith(prefix + "/")
        for prefix in PROTECTED_PREFIXES
    )


def token_matches(provided: str) -> bool:
    expected = configured_dashboard_token()

    if not expected or not provided:
        return False

    return secrets.compare_digest(provided, expected)


def header_token(request: Request) -> str:
    return request.headers.get("X-ProcSentinel-Token", "").strip()


def cookie_token(request: Request) -> str:
    return request.cookies.get(AUTH_COOKIE_NAME, "").strip()


def is_authenticated_request(request: Request) -> bool:
    return (
        token_matches(header_token(request))
        or token_matches(cookie_token(request))
    )


def safe_next_path(value: str | None) -> str:
    candidate = (value or "/").strip()

    if not candidate.startswith("/"):
        return "/"

    if candidate.startswith("//"):
        return "/"

    if candidate.startswith("/login"):
        return "/"

    if candidate.startswith("/logout"):
        return "/"

    return candidate


def same_origin_request(request: Request) -> bool:
    origin = request.headers.get("origin", "").rstrip("/")
    referer = request.headers.get("referer", "")
    expected_origin = str(request.base_url).rstrip("/")

    if origin:
        return secrets.compare_digest(origin, expected_origin)

    if referer:
        return referer.startswith(expected_origin + "/")

    return False


def api_request(path: str) -> bool:
    return (
        path == "/openapi.json"
        or path.startswith("/api/")
        or path == "/docs"
        or path.startswith("/docs/")
        or path == "/redoc"
        or path.startswith("/redoc/")
    )


def authentication_failure(request: Request):
    if api_request(request.url.path):
        return JSONResponse(
            {
                "detail": (
                    "ProcSentinel dashboard authentication required."
                )
            },
            status_code=401,
            headers={"Cache-Control": "no-store"},
        )

    next_path = quote(
        safe_next_path(request.url.path),
        safe="/",
    )

    return RedirectResponse(
        url=f"/login?next={next_path}",
        status_code=303,
        headers={"Cache-Control": "no-store"},
    )


def set_auth_cookie(response, token: str) -> None:
    response.set_cookie(
        AUTH_COOKIE_NAME,
        token,
        max_age=configured_session_seconds(),
        httponly=True,
        secure=cookie_secure_enabled(),
        samesite="strict",
        path="/",
    )


def login_template_response(
    request: Request,
    next_path: str,
    error: str | None,
    configuration_error: bool,
    status_code: int = 200,
):
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "request": request,
            "next_path": safe_next_path(next_path),
            "error": error,
            "configuration_error": configuration_error,
        },
        status_code=status_code,
        headers={"Cache-Control": "no-store"},
    )


def install_dashboard_auth(app):
    @app.get("/login", response_class=HTMLResponse)
    async def dashboard_login_page(
        request: Request,
        next: str = "/",
    ):
        if not is_dashboard_auth_enabled():
            return RedirectResponse(
                url="/",
                status_code=303,
            )

        if is_authenticated_request(request):
            return RedirectResponse(
                url=safe_next_path(next),
                status_code=303,
            )

        return login_template_response(
            request=request,
            next_path=next,
            error=None,
            configuration_error=not bool(
                configured_dashboard_token()
            ),
        )

    @app.post("/login", response_class=HTMLResponse)
    async def dashboard_login_submit(request: Request):
        body = (
            await request.body()
        ).decode(
            "utf-8",
            errors="replace",
        )

        form = parse_qs(
            body,
            keep_blank_values=True,
        )

        token = form.get(
            "token",
            [""],
        )[0].strip()

        next_path = safe_next_path(
            form.get(
                "next",
                ["/"],
            )[0]
        )

        if not configured_dashboard_token():
            return login_template_response(
                request=request,
                next_path=next_path,
                error=(
                    "Dashboard authentication is not configured."
                ),
                configuration_error=True,
                status_code=503,
            )

        if not token_matches(token):
            return login_template_response(
                request=request,
                next_path=next_path,
                error="Invalid dashboard access token.",
                configuration_error=False,
                status_code=401,
            )

        response = RedirectResponse(
            url=next_path,
            status_code=303,
            headers={"Cache-Control": "no-store"},
        )

        set_auth_cookie(
            response,
            token,
        )

        return response

    @app.post("/logout")
    async def dashboard_logout(request: Request):
        if not same_origin_request(request):
            return JSONResponse(
                {
                    "detail": (
                        "Cross-origin request rejected."
                    )
                },
                status_code=403,
                headers={"Cache-Control": "no-store"},
            )

        response = RedirectResponse(
            url="/login",
            status_code=303,
            headers={"Cache-Control": "no-store"},
        )

        response.delete_cookie(
            AUTH_COOKIE_NAME,
            path="/",
            secure=cookie_secure_enabled(),
            httponly=True,
            samesite="strict",
        )

        return response

    @app.middleware("http")
    async def dashboard_auth_middleware(
        request: Request,
        call_next,
    ):
        path = request.url.path

        if (
            is_dashboard_auth_enabled()
            and not configured_dashboard_token()
            and path not in PUBLIC_PATHS
            and not any(
                path.startswith(prefix)
                for prefix in PUBLIC_PREFIXES
            )
        ):
            return JSONResponse(
                {
                    "detail": (
                        "Dashboard authentication "
                        "configuration is invalid."
                    )
                },
                status_code=503,
                headers={"Cache-Control": "no-store"},
            )

        if (
            path_requires_dashboard_auth(path)
            and not is_authenticated_request(request)
        ):
            return authentication_failure(request)

        if (
            path_requires_dashboard_auth(path)
            and request.method.upper() in UNSAFE_METHODS
            and not token_matches(header_token(request))
            and not same_origin_request(request)
        ):
            return JSONResponse(
                {
                    "detail": (
                        "Cross-origin request rejected."
                    )
                },
                status_code=403,
                headers={"Cache-Control": "no-store"},
            )

        response = await call_next(request)

        if path_requires_dashboard_auth(path):
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = (
                "nosniff"
            )
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = (
                "no-referrer"
            )
            response.headers["Permissions-Policy"] = (
                "camera=(), microphone=(), geolocation=()"
            )

        return response

    return app
