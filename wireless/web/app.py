"""
FastAPI application factory for the WireLess web UI.

The UI binds to loopback by default and runs as root (it drives WireGuard and
iptables), so every response carries a strict CSP and cross-origin mutating
requests are rejected before they reach a route.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from wireless.services import ConflictError, GatewayService, NotFoundError, ServiceError
from wireless.web.auth import LoginRateLimiter, WebAuth
from wireless.web.routes import api, pages

WEB_ROOT = Path(__file__).resolve().parent
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'self'"
)


def create_app(
    service: Optional[GatewayService] = None,
    auth: Optional[WebAuth] = None,
    auth_enabled: bool = True,
    limiter: Optional[LoginRateLimiter] = None,
) -> FastAPI:
    """Build the web application.

    Args:
        service: Gateway service used by the routes (injectable for tests).
        auth: Password/session store.
        auth_enabled: When False, no login is required (loopback only).
        limiter: Login rate limiter (injectable for tests).
    """
    app = FastAPI(
        title="WireLess",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.service = service or GatewayService()
    app.state.auth = auth or WebAuth()
    app.state.auth_enabled = auth_enabled
    app.state.limiter = limiter or LoginRateLimiter()
    app.state.templates = Jinja2Templates(directory=str(WEB_ROOT / "templates"))

    app.mount(
        "/static",
        StaticFiles(directory=str(WEB_ROOT / "static")),
        name="static",
    )

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        if request.method in MUTATING_METHODS:
            origin = request.headers.get("origin")
            if origin:
                expected = (
                    f"{request.url.scheme}://"
                    f"{request.headers.get('host', request.url.netloc)}"
                )
                if origin.rstrip("/") != expected.rstrip("/"):
                    return JSONResponse(
                        {"detail": "Cross-origin request rejected."},
                        status_code=403,
                    )

        response = await call_next(request)
        response.headers.setdefault(
            "Content-Security-Policy", CONTENT_SECURITY_POLICY
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    app.include_router(api.router, prefix="/api")
    app.include_router(pages.router)

    @app.exception_handler(ServiceError)
    async def service_error_handler(request: Request, exc: ServiceError):
        if isinstance(exc, NotFoundError):
            status_code = 404
        elif isinstance(exc, ConflictError):
            status_code = 409
        else:
            status_code = 400
        return JSONResponse({"detail": str(exc)}, status_code=status_code)

    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError):
        return JSONResponse({"detail": str(exc)}, status_code=400)

    @app.exception_handler(RuntimeError)
    async def runtime_error_handler(request: Request, exc: RuntimeError):
        return JSONResponse({"detail": str(exc)}, status_code=500)

    return app
