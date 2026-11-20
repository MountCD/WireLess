"""Server-rendered pages of the web UI."""
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from wireless.web.deps import current_session

router = APIRouter()


def _page(request: Request, template: str):
    session = current_session(request)
    if request.app.state.auth_enabled and session is None:
        return RedirectResponse("/login", status_code=303)
    return request.app.state.templates.TemplateResponse(
        request,
        template,
        {"csrf": session.csrf if session else ""},
    )


@router.get("/")
async def dashboard(request: Request):
    return _page(request, "dashboard.html")


@router.get("/proxies")
async def proxies(request: Request):
    return _page(request, "proxies.html")


@router.get("/login")
async def login_page(request: Request):
    if not request.app.state.auth_enabled or current_session(request) is not None:
        return RedirectResponse("/", status_code=303)
    return request.app.state.templates.TemplateResponse(request, "login.html", {})
