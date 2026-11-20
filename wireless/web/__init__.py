"""WireLess web UI (FastAPI). Import :mod:`wireless.web.app` to serve it."""

import ipaddress


def is_loopback(host: str) -> bool:
    """Return True when *host* only accepts connections from this machine."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
