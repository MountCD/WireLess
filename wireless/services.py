"""
High-level WireLess operations shared by the CLI and the web UI.

The service layer owns all state transitions: it reads and writes the JSON
state through :class:`wireless.store.Store`, drives the WireGuard / sing-box /
routing managers and raises typed exceptions that front ends can translate
into exit codes or HTTP statuses.
"""
from __future__ import annotations

import dataclasses
import logging
import socket
import threading
from typing import Optional

from wireless import config as cfg
from wireless.generators.singbox import generate_singbox_config
from wireless.managers.routing import RoutingManager
from wireless.managers.singbox import SingBoxManager
from wireless.managers.wireguard import WireGuardManager
from wireless.models import (
    Hysteria2Config,
    ProxyConfig,
    TrojanConfig,
    VlessConfig,
    VmessConfig,
)
from wireless.parsers.auto import parse_proxy_url
from wireless.store import Store

logger = logging.getLogger(__name__)

_PROXY_TYPES = {
    "vless": VlessConfig,
    "vmess": VmessConfig,
    "trojan": TrojanConfig,
    "hysteria2": Hysteria2Config,
}


class ServiceError(RuntimeError):
    """Base class for service-layer failures."""


class NotFoundError(ServiceError):
    """The requested config, client or subscription does not exist."""


class ConflictError(ServiceError):
    """The operation conflicts with the current state."""


# ── Proxy (de)serialisation ──────────────────────────────────────────────────

def proxy_to_dict(proxy: ProxyConfig) -> dict:
    """Convert a ProxyConfig dataclass to a serialisable dict."""
    data = dataclasses.asdict(proxy)
    data["_type"] = proxy.type
    return data


def dict_to_proxy_config(data: dict) -> ProxyConfig:
    """Reconstruct a ProxyConfig subclass from a saved dict.

    Raises:
        ValueError: If the stored type is unknown.
    """
    proxy_type = data.get("_type") or data.get("type", "")
    cls = _PROXY_TYPES.get(proxy_type)
    if cls is None:
        raise ValueError(f"Unknown proxy type: {proxy_type!r}")
    # Only pass fields known to the dataclass; service keys such as ``_type``,
    # ``_url`` and ``_source`` are intentionally dropped.
    known = {field.name for field in dataclasses.fields(cls)}
    filtered = {key: value for key, value in data.items() if key in known}
    return cls(**filtered)


def config_name(config: dict) -> str:
    """Return the display name of a saved config (new and legacy keys)."""
    return config.get("name") or config.get("_name") or ""


# ── Service ──────────────────────────────────────────────────────────────────

class GatewayService:
    """Stateful facade over the store and the three runtime managers.

    Managers are created lazily so that read-only operations (list, status of
    the state files) never touch subprocesses, and can be injected in tests.
    """

    def __init__(
        self,
        store: Optional[Store] = None,
        singbox: Optional[SingBoxManager] = None,
        wireguard: Optional[WireGuardManager] = None,
        routing: Optional[RoutingManager] = None,
    ):
        self.store = store or Store()
        self._singbox = singbox
        self._wireguard = wireguard
        self._routing = routing
        # Re-entrant so restart() can call stop()/start() while holding it.
        self._op_lock = threading.RLock()

    # ── Managers ─────────────────────────────────────────────────────────────

    @property
    def singbox(self) -> SingBoxManager:
        if self._singbox is None:
            self._singbox = SingBoxManager()
        return self._singbox

    @property
    def wireguard(self) -> WireGuardManager:
        if self._wireguard is None:
            self._wireguard = WireGuardManager()
        return self._wireguard

    @property
    def routing(self) -> RoutingManager:
        if self._routing is None:
            self._routing = RoutingManager()
        return self._routing

    # ── Proxy configs ────────────────────────────────────────────────────────

    def list_proxies(self) -> list[dict]:
        """Return all saved proxy configs."""
        return self.store.load_configs()

    def get_active_config(self) -> Optional[dict]:
        """Return the config selected in the state file, if it still exists."""
        active = self.store.load_state().get("active")
        if not active:
            return None
        for config in self.store.load_configs():
            if config_name(config) == active:
                return config
        return None

    def add_proxy(self, url: str, name: str = "") -> dict:
        """Parse *url*, save the config and return it.

        Raises:
            ValueError: If the URL cannot be parsed.
            ConflictError: If a config with the same name already exists.
        """
        proxy = parse_proxy_url(url)
        resolved = name or proxy.name or f"{proxy.type}_{proxy.server}_{proxy.port}"
        proxy.name = resolved

        with self.store.lock():
            configs = self.store.load_configs()
            if any(config_name(config) == resolved for config in configs):
                raise ConflictError(
                    f"Config named {resolved!r} already exists. "
                    "Use 'remove' first."
                )
            data = proxy_to_dict(proxy)
            data["name"] = resolved
            data["_url"] = url.strip()
            configs.append(data)
            self.store.save_configs(configs)
        return data

    def activate(self, name_or_index: str) -> str:
        """Set the active config by name or 0-based index and return its name.

        Raises:
            NotFoundError: If no configs exist or the target is unknown.
        """
        configs = self.store.load_configs()
        if not configs:
            raise NotFoundError("No configs saved.")

        target: Optional[dict] = None
        try:
            index = int(name_or_index)
        except (TypeError, ValueError):
            index = -1
        if 0 <= index < len(configs):
            target = configs[index]
        else:
            target = next(
                (c for c in configs if config_name(c) == name_or_index), None
            )

        if target is None:
            raise NotFoundError(f"Config {name_or_index!r} not found.")

        name = config_name(target)
        self.store.update_state(active=name)
        return name

    def remove_proxy(self, name: str) -> None:
        """Delete a saved config and clear it from the state if it was active.

        Raises:
            NotFoundError: If the config does not exist.
        """
        with self.store.lock():
            configs = self.store.load_configs()
            remaining = [c for c in configs if config_name(c) != name]
            if len(remaining) == len(configs):
                raise NotFoundError(f"Config {name!r} not found.")
            self.store.save_configs(remaining)
            state = self.store.load_state()
            if state.get("active") == name:
                state.pop("active", None)
                self.store.save_state(state)

    # ── Runtime status ───────────────────────────────────────────────────────

    def status(self) -> dict:
        """Return a structured snapshot of the gateway state and processes."""
        state = self.store.load_state()
        return {
            "active": state.get("active") or None,
            "server_ip": state.get("server_ip", "unknown"),
            "running": bool(state.get("running")),
            "configs_count": len(self.store.load_configs()),
            "wireguard": self.wireguard.status(),
            "singbox": self.singbox.status(),
            "routing": self.routing.is_active(),
        }

    @staticmethod
    def detect_server_ip() -> str:
        """Best-effort local address of the default route (not the public IP)."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80))
                return sock.getsockname()[0]
        except OSError:
            return "0.0.0.0"

    # ── Gateway lifecycle ────────────────────────────────────────────────────

    def start(self, server_ip: str = "") -> dict:
        """Start sing-box, WireGuard and TPROXY routing.

        Returns:
            Dict describing what was started, what was already running and the
            server IP written to the state.

        Raises:
            ConflictError: If no active config is selected.
            ValueError: If the active config cannot be reconstructed.
            RuntimeError: If sing-box or WireGuard fails to start.
        """
        with self._op_lock:
            config = self.get_active_config()
            if config is None:
                raise ConflictError(
                    "No active proxy config. Use 'wireless use <name>' first."
                )
            proxy = dict_to_proxy_config(config)
            singbox_config = generate_singbox_config(proxy)

            ip = server_ip or self.detect_server_ip()
            result = {
                "server_ip": ip,
                "singbox": "already running",
                "wireguard": "already running",
                "routing": "active",
            }

            if not self.singbox.is_running():
                self.singbox.start(singbox_config)
                result["singbox"] = "started"

            if not self.wireguard.is_running():
                try:
                    self.wireguard.setup()
                    if not self.wireguard.list_clients():
                        self.wireguard.add_client(server_public_ip=ip)
                except RuntimeError:
                    self.singbox.stop()
                    raise
                result["wireguard"] = "started"

            if not self.routing.is_active():
                try:
                    self.routing.setup()
                except Exception as exc:  # noqa: BLE001 - routing is best effort
                    logger.warning("Routing setup warning: %s", exc)
                    result["routing"] = "failed"

            self.store.update_state(running=True, server_ip=ip)
            return result

    def stop(self) -> dict:
        """Stop routing, sing-box and WireGuard.

        Returns:
            Dict describing which components were actually stopped.
        """
        with self._op_lock:
            stopped = {"routing": False, "singbox": False, "wireguard": False}
            if self.routing.is_active():
                self.routing.teardown()
                stopped["routing"] = True
            if self.singbox.is_running():
                self.singbox.stop()
                stopped["singbox"] = True
            if self.wireguard.is_running():
                self.wireguard.teardown()
                stopped["wireguard"] = True
            self.store.update_state(running=False)
            return stopped

    def restart(self, server_ip: str = "") -> dict:
        """Stop and start the gateway, keeping the previous server IP."""
        with self._op_lock:
            previous_ip = self.store.load_state().get("server_ip", "")
            self.stop()
            return self.start(server_ip or previous_ip)

    # ── WireGuard clients ────────────────────────────────────────────────────

    def list_clients(self) -> list:
        """Return all registered WireGuard clients."""
        return self.wireguard.list_clients()

    def client_config(self, index: int = 0) -> str:
        """Return the ``.conf`` text for the client at *index*.

        Raises:
            NotFoundError: If there are no clients or the index is out of range.
        """
        clients = self.list_clients()
        if not clients:
            raise NotFoundError(
                "No client configs found. Run 'wireless start' first."
            )
        if not 0 <= index < len(clients):
            raise NotFoundError(
                f"Client index {index} out of range (0–{len(clients) - 1})."
            )
        server_ip = self.store.load_state().get("server_ip", "0.0.0.0")
        return self.wireguard.get_client_config_text(clients[index], server_ip)
