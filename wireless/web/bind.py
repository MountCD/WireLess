"""Bind-address policy for the web UI (kept free of web-framework imports)."""
from typing import Optional

from wireless.web import is_loopback


def check_bind(host: str, no_auth: bool, configured: bool) -> Optional[str]:
    """Validate the bind address and return an error message, or ``None``.

    A non-loopback bind exposes a root-owned control panel to the network, so
    it is only allowed together with a configured password.
    """
    if is_loopback(host):
        return None
    if no_auth:
        return "❌ --no-auth is only allowed when binding to loopback."
    if not configured:
        return (
            "❌ Binding to a non-loopback address requires a password. "
            "Run 'wireless web --set-password' first."
        )
    return None
