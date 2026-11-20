"""JSON API of the web UI."""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from wireless.services import public_config
from wireless.web.deps import SESSION_COOKIE, require_csrf, require_session

router = APIRouter()


class LoginRequest(BaseModel):
    password: str = ""


class ProxyRequest(BaseModel):
    url: str
    name: str = ""


class UrlRequest(BaseModel):
    url: str


class NameRequest(BaseModel):
    name: str


class GatewayRequest(BaseModel):
    server_ip: str = ""


# ── Health / auth ────────────────────────────────────────────────────────────

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


# ── Status ───────────────────────────────────────────────────────────────────

@router.get("/status")
async def status(request: Request, _=Depends(require_session)) -> dict:
    return request.app.state.service.status()


# ── Proxies ──────────────────────────────────────────────────────────────────

@router.get("/proxies")
async def list_proxies(request: Request, _=Depends(require_session)) -> dict:
    service = request.app.state.service
    active = service.store.load_state().get("active") or None
    return {
        "active": active,
        "configs": [public_config(config) for config in service.list_proxies()],
    }


@router.post("/proxies", dependencies=[Depends(require_csrf)])
async def add_proxy(payload: ProxyRequest, request: Request) -> dict:
    created = request.app.state.service.add_proxy(payload.url, payload.name)
    return public_config(created)


@router.post("/proxies/parse", dependencies=[Depends(require_csrf)])
async def parse_proxy(payload: UrlRequest, request: Request) -> dict:
    return request.app.state.service.preview_proxy(payload.url)


@router.post("/proxies/activate", dependencies=[Depends(require_csrf)])
async def activate_proxy(payload: NameRequest, request: Request) -> dict:
    return {"active": request.app.state.service.activate(payload.name)}


@router.delete("/proxies", dependencies=[Depends(require_csrf)])
async def delete_proxy(request: Request, name: str) -> dict:
    # The name travels as a query parameter: config names may contain "/" and
    # would not survive a path parameter.
    request.app.state.service.remove_proxy(name)
    return {"ok": True}


# ── Gateway lifecycle ────────────────────────────────────────────────────────

@router.post("/gateway/{action}", dependencies=[Depends(require_csrf)])
async def gateway(action: str, payload: GatewayRequest, request: Request) -> dict:
    service = request.app.state.service
    if action == "start":
        result = service.start(payload.server_ip)
    elif action == "stop":
        result = service.stop()
    elif action == "restart":
        result = service.restart(payload.server_ip)
    else:
        raise HTTPException(status_code=404, detail="Unknown gateway action.")
    return {"result": result, "status": service.status()}
