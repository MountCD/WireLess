"""Server-rendered pages of the web UI."""
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from wireless.web.deps import current_session

router = APIRouter()


@router.get("/")
async def dashboard(request: Request):
    session = current_session(request)
    if request.app.state.auth_enabled and session is None:
        return RedirectResponse("/login", status_code=303)
    return request.app.state.templates.TemplateResponse(
        request,
        "dashboard.html",
        {"csrf": session.csrf if session else ""},
    )


@router.get("/login")
async def login_page(request: Request):
    if not request.app.state.auth_enabled or current_session(request) is not None:
        return RedirectResponse("/", status_code=303)
    return request.app.state.templates.TemplateResponse(request, "login.html", {})
