"""
WireGuard interface manager.

Handles: key generation, config writing, interface up/down, peer management.
Requires root privileges and wireguard-tools.
"""
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Optional

from wireless import config as cfg
from wireless.models import WireGuardServerConfig, WireGuardClientConfig
from wireless.generators.wireguard import generate_keypair, generate_server_config, generate_client_config

logger = logging.getLogger(__name__)


class WireGuardManager:
    """Manages the WireGuard server interface (wg0)."""

    def __init__(
        self,
        interface: str = cfg.WG_INTERFACE,
        listen_port: int = cfg.WG_LISTEN_PORT,
        server_address: str = cfg.WG_SERVER_ADDRESS,
        config_dir: str = cfg.WG_CONFIG_DIR,
    ):
        self.interface    = interface
        self.listen_port  = listen_port
        self.server_address = server_address
        self.config_dir   = Path(config_dir)
        self.conf_path    = self.config_dir / f"{interface}.conf"
        self._keys_file   = self.config_dir / "server_keys.json"
        self._clients_file = self.config_dir / "clients.json"

        self._server_cfg: Optional[WireGuardServerConfig] = None
        self._clients: list[WireGuardClientConfig] = []

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _ensure_dirs(self) -> None:
        self.config_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.config_dir, 0o700)

    def _save_keys(self, priv: str, pub: str) -> None:
        self._keys_file.write_text(json.dumps({"private": priv, "public": pub}))
        os.chmod(self._keys_file, 0o600)

    def _load_keys(self) -> tuple[str, str]:
        data = json.loads(self._keys_file.read_text())
        return data["private"], data["public"]

    def _load_clients(self) -> list[WireGuardClientConfig]:
        if not self._clients_file.exists():
            return []
        raw = json.loads(self._clients_file.read_text())
        clients = []
        for d in raw:
            clients.append(WireGuardClientConfig(**d))
        return clients

    def _save_clients(self, clients: list[WireGuardClientConfig]) -> None:
        import dataclasses
        self._clients_file.write_text(
            json.dumps([dataclasses.asdict(c) for c in clients], indent=2)
        )

    def _write_server_conf(self) -> None:
        conf_text = generate_server_config(self._server_cfg, self._clients)
        self.conf_path.write_text(conf_text)
        os.chmod(self.conf_path, 0o600)
        logger.debug("Wrote server config to %s", self.conf_path)

    def _run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        logger.debug("Running: %s", " ".join(args))
        return subprocess.run(list(args), capture_output=True, text=True, check=check)

    # ── Public API ────────────────────────────────────────────────────────────

    def setup(self) -> WireGuardServerConfig:
        """Create keys, write config and bring up the WireGuard interface.

        Returns:
            The WireGuardServerConfig for the running server.

        Raises:
            RuntimeError: On wg/ip command failure.
        """
        self._ensure_dirs()

        # Reuse existing keys if present
        if self._keys_file.exists():
            logger.info("Reusing existing server keys")
            priv, pub = self._load_keys()
        else:
            logger.info("Generating new server keypair")
            priv, pub = generate_keypair()
            self._save_keys(priv, pub)

        self._clients = self._load_clients()

        self._server_cfg = WireGuardServerConfig(
            interface=self.interface,
            private_key=priv,
            public_key=pub,
            address=self.server_address,
            listen_port=self.listen_port,
        )

        self._write_server_conf()

        # Bring up interface
        try:
            self._run("wg-quick", "up", str(self.conf_path))
            logger.info("WireGuard interface %s is up", self.interface)
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"Failed to bring up {self.interface}: {exc.stderr}"
            ) from exc

        return self._server_cfg

    def add_client(
        self,
        client_address: str = cfg.WG_CLIENT_ADDRESS,
        dns: str = "1.1.1.1",
        server_public_ip: str = "",
    ) -> WireGuardClientConfig:
        """Generate a new client keypair and add it as a peer.

        Args:
            client_address:   IP/CIDR for the client inside WG tunnel.
            dns:              DNS server for the client config.
            server_public_ip: Public IP/hostname of this server (for Endpoint).

        Returns:
            WireGuardClientConfig ready to be written to a .conf file.

        Raises:
            RuntimeError: If WireGuard server is not set up yet.
        """
        if self._server_cfg is None:
            if self._keys_file.exists():
                priv, pub = self._load_keys()
                self._server_cfg = WireGuardServerConfig(
                    interface=self.interface,
                    private_key=priv,
                    public_key=pub,
                    address=self.server_address,
                    listen_port=self.listen_port,
                )
                self._clients = self._load_clients()
            else:
                raise RuntimeError("WireGuard not set up. Run setup() first.")

        client_priv, client_pub = generate_keypair()
        endpoint = f"{server_public_ip or '0.0.0.0'}:{self.listen_port}"

        client = WireGuardClientConfig(
            private_key=client_priv,
            public_key=client_pub,
            server_public_key=self._server_cfg.public_key,
            server_endpoint=endpoint,
            address=client_address,
            dns=dns,
        )

        self._clients.append(client)
        self._save_clients(self._clients)
        self._write_server_conf()

        # Hot-add peer if interface is up
        if self.is_running():
            try:
                self._run(
                    "wg", "set", self.interface,
                    "peer", client_pub,
                    "allowed-ips", client_address,
                )
                logger.info("Hot-added peer %s... to %s", client_pub[:10], self.interface)
            except subprocess.CalledProcessError as exc:
                logger.warning("Hot-add peer failed: %s", exc.stderr)

        return client

    def teardown(self) -> None:
        """Bring down the WireGuard interface."""
        if not self.is_running():
            logger.info("WireGuard interface %s is not running", self.interface)
            return
        try:
            self._run("wg-quick", "down", str(self.conf_path))
            logger.info("WireGuard interface %s is down", self.interface)
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"Failed to bring down {self.interface}: {exc.stderr}"
            ) from exc

    def is_running(self) -> bool:
        """Check if the WireGuard interface is currently active."""
        result = self._run("wg", "show", self.interface, check=False)
        return result.returncode == 0

    def status(self) -> dict:
        """Return a status dict for the WireGuard interface."""
        running = self.is_running()
        info: dict = {"interface": self.interface, "running": running}
        if running:
            result = self._run("wg", "show", self.interface, check=False)
            info["details"] = result.stdout.strip()
        return info

    def get_client_config_text(
        self,
        client: WireGuardClientConfig,
        server_public_ip: str = "",
    ) -> str:
        """Return the .conf text for a client."""
        if self._server_cfg is None:
            if self._keys_file.exists():
                _, pub = self._load_keys()
            else:
                raise RuntimeError("Server not set up")
        else:
            pub = self._server_cfg.public_key

        endpoint = f"{server_public_ip or '0.0.0.0'}:{self.listen_port}"
        return generate_client_config(client, pub, endpoint)

    def list_clients(self) -> list[WireGuardClientConfig]:
        """Return all registered client configs."""
        return self._load_clients()
