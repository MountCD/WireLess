"""JSON API of the web UI."""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from wireless.web.deps import SESSION_COOKIE, require_csrf, require_session

router = APIRouter()


class LoginRequest(BaseModel):
    password: str = ""


@router.get("/health")
async def health() -> dict:
    """Liveness probe; intentionally unauthenticated and secret-free."""
    return {"status": "ok"}


@router.post("/login")
async def login(payload: LoginRequest, request: Request):
    app = request.app
    client = request.client.host if request.client else "unknown"
    limiter = app.state.limiter

    if not limiter.allow(client):
        raise HTTPException(status_code=429, detail="Too many attempts, try again later.")

    if not app.state.auth_enabled:
        return JSONResponse({"ok": True, "csrf": ""})

    if not app.state.auth.check_password(payload.password):
        limiter.failure(client)
        raise HTTPException(status_code=401, detail="Invalid password.")

    limiter.success(client)
    token, session = app.state.auth.issue_session()
    response = JSONResponse({"ok": True, "csrf": session.csrf})
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=app.state.auth.session_ttl,
        httponly=True,
        samesite="strict",
        path="/",
    )
    return response


@router.post("/logout", dependencies=[Depends(require_csrf)])
async def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@router.get("/status")
async def status(request: Request, _=Depends(require_session)) -> dict:
    return request.app.state.service.status()
