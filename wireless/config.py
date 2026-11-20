"""
Application-wide configuration constants for WireLess.
"""
import os
import shutil
import subprocess
from functools import lru_cache

# ── sing-box ────────────────────────────────────────────────────────────────
# Generated configs use the sing-box >= 1.12 DNS/rule format.
MIN_SINGBOX_VERSION = "1.12.0"

# Historical install locations, checked after PATH / whereis.  The AUR package
# installs to /usr/bin, manual installers to /usr/local/bin.
_LEGACY_SINGBOX_PATHS = (
    "/usr/local/bin/sing-box",
    "/usr/bin/sing-box",
    os.path.expanduser("~/go/bin/sing-box"),
)


def _is_executable(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.X_OK)


def _whereis_singbox_paths() -> list[str]:
    """Return binary paths reported by ``whereis -b sing-box`` (may be empty)."""
    try:
        result = subprocess.run(
            ["whereis", "-b", "sing-box"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    # whereis output looks like:
    #   sing-box: /usr/bin/sing-box /usr/local/bin/sing-box
    output = result.stdout.strip()
    if ":" not in output:
        return []
    return output.partition(":")[2].split()


@lru_cache(maxsize=1)
def find_singbox_binary() -> str:
    """Locate the sing-box binary.

    Priority:
        1. ``SINGBOX_BINARY`` environment variable (used as-is, even if broken:
           the caller reports a clear error for an explicit override).
        2. The first executable found in ``PATH``.
        3. The first executable reported by ``whereis -b sing-box`` (catches
           locations outside PATH, e.g. ``/usr/bin`` for AUR installs).
        4. Historical default locations.

    Returns:
        Path to the first executable found, or the historical default so the
        caller can produce a helpful "not found" error.
    """
    explicit = os.environ.get("SINGBOX_BINARY", "").strip()
    if explicit:
        return explicit

    candidates: list[str] = []

    which_path = shutil.which("sing-box")
    if which_path:
        candidates.append(which_path)

    candidates.extend(_whereis_singbox_paths())
    candidates.extend(_LEGACY_SINGBOX_PATHS)

    for path in candidates:
        if _is_executable(path):
            return path

    return "/usr/local/bin/sing-box"


SINGBOX_BINARY = find_singbox_binary()

SINGBOX_CONFIG_PATH = "/etc/wireless/singbox/config.json"
SINGBOX_PID_FILE    = "/etc/wireless/singbox/singbox.pid"
SINGBOX_LOG_FILE    = "/etc/wireless/singbox/singbox.log"
SINGBOX_SOCKS_PORT  = 2080
SINGBOX_HTTP_PORT   = 2081
SINGBOX_TPROXY_PORT = 2082

# ── WireGuard ───────────────────────────────────────────────────────────────
WG_INTERFACE      = "wg0"
WG_LISTEN_PORT    = 51820
WG_SERVER_ADDRESS = "10.100.0.1/24"
WG_CLIENT_ADDRESS = "10.100.0.2/32"
WG_CONFIG_DIR     = "/etc/wireless/wireguard/"
WG_SERVER_CONF    = "/etc/wireless/wireguard/wg0.conf"

# ── State / data ────────────────────────────────────────────────────────────
STATE_FILE         = "/etc/wireless/state.json"
CONFIGS_FILE       = "/etc/wireless/configs.json"
SUBSCRIPTIONS_FILE = "/etc/wireless/subscriptions.json"
LOCK_FILE          = "/etc/wireless/.lock"
WEB_FILE           = "/etc/wireless/web.json"

# ── Routing / networking ─────────────────────────────────────────────────────
ROUTE_TABLE    = 100
FWMARK         = 1
PRIVATE_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
