"""FastAPI dependencies: session authentication and CSRF validation."""
from __future__ import annotations

import hmac
from typing import Optional

from fastapi import Depends, HTTPException, Request

from wireless.web.auth import Session

SESSION_COOKIE = "wireless_session"


def current_session(request: Request) -> Optional[Session]:
    """Return the session from the request cookie, or ``None``."""
    if not request.app.state.auth_enabled:
        return None
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    return request.app.state.auth.verify_session(token)


async def require_session(request: Request) -> Optional[Session]:
    """Reject unauthenticated API requests with 401."""
    session = current_session(request)
    if request.app.state.auth_enabled and session is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return session


async def require_csrf(
    request: Request,
    session: Optional[Session] = Depends(require_session),
) -> Optional[Session]:
    """Reject state-changing requests without a matching CSRF header."""
    if not request.app.state.auth_enabled:
        return session
    token = request.headers.get("X-CSRF-Token", "")
    if session is None or not token or not hmac.compare_digest(token, session.csrf):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    return session
