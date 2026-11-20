"""
WireGuard configuration generator.

Generates server wg0.conf and client .conf files.
Requires the `wg` binary (wireguard-tools) to be installed for key generation.
"""
import logging
import subprocess
from typing import List

from wireless.models import WireGuardServerConfig, WireGuardClientConfig
from wireless import config as cfg

logger = logging.getLogger(__name__)


# ── Key generation ───────────────────────────────────────────────────────────

def generate_keypair() -> tuple[str, str]:
    """Generate a WireGuard private/public key pair.

    Returns:
        (private_key, public_key) — both base64 strings.

    Raises:
        RuntimeError: If wg binary is not found or returns an error.
    """
    try:
        priv_result = subprocess.run(
            ["wg", "genkey"],
            capture_output=True,
            text=True,
            check=True,
        )
        private_key = priv_result.stdout.strip()

        pub_result = subprocess.run(
            ["wg", "pubkey"],
            input=private_key,
            capture_output=True,
            text=True,
            check=True,
        )
        public_key = pub_result.stdout.strip()

    except FileNotFoundError:
        raise RuntimeError(
            "wireguard-tools not found. Install with: apt install wireguard-tools"
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Key generation failed: {exc.stderr}") from exc

    logger.debug("Generated WireGuard keypair (pub: %s...)", public_key[:10])
    return private_key, public_key


# ── Server config ────────────────────────────────────────────────────────────

def _build_postup_rules(wg_iface: str, tproxy_port: int) -> str:
    """Build PostUp iptables commands for TPROXY routing."""
    cmds = [
        # Enable IP forwarding
        f"sysctl -w net.ipv4.ip_forward=1",
        # Policy routing: fwmark → table 100
        f"ip rule add fwmark {cfg.FWMARK} table {cfg.ROUTE_TABLE} 2>/dev/null || true",
        f"ip route add local 0.0.0.0/0 dev lo table {cfg.ROUTE_TABLE} 2>/dev/null || true",
        # Create custom mangle chain
        f"iptables -t mangle -N WIRELESS_PROXY 2>/dev/null || true",
        # Bypass private/local addresses
        *[
            f"iptables -t mangle -A WIRELESS_PROXY -d {cidr} -j RETURN"
            for cidr in cfg.PRIVATE_RANGES
        ],
        # TPROXY TCP + UDP from wg interface
        f"iptables -t mangle -A WIRELESS_PROXY -p tcp -j TPROXY"
        f" --on-port {tproxy_port} --tproxy-mark {cfg.FWMARK}",
        f"iptables -t mangle -A WIRELESS_PROXY -p udp -j TPROXY"
        f" --on-port {tproxy_port} --tproxy-mark {cfg.FWMARK}",
        f"iptables -t mangle -A PREROUTING -i {wg_iface} -j WIRELESS_PROXY",
    ]
    return "; ".join(cmds)


def _build_postdown_rules(wg_iface: str) -> str:
    """Build PostDown iptables cleanup commands."""
    cmds = [
        f"iptables -t mangle -D PREROUTING -i {wg_iface} -j WIRELESS_PROXY 2>/dev/null || true",
        f"iptables -t mangle -F WIRELESS_PROXY 2>/dev/null || true",
        f"iptables -t mangle -X WIRELESS_PROXY 2>/dev/null || true",
        f"ip rule del fwmark {cfg.FWMARK} table {cfg.ROUTE_TABLE} 2>/dev/null || true",
        f"ip route del local 0.0.0.0/0 dev lo table {cfg.ROUTE_TABLE} 2>/dev/null || true",
    ]
    return "; ".join(cmds)


def generate_server_config(
    server_cfg: WireGuardServerConfig,
    clients: List[WireGuardClientConfig],
    tproxy_port: int = None,
) -> str:
    """Render a wg0.conf server config string.

    Args:
        server_cfg: Server keys, address, port.
        clients:    List of WireGuardClientConfig peers to include.
        tproxy_port: sing-box tproxy port for PostUp rules.

    Returns:
        Multi-line wg0.conf string.
    """
    tproxy_port = tproxy_port or cfg.SINGBOX_TPROXY_PORT
    post_up   = _build_postup_rules(server_cfg.interface, tproxy_port)
    post_down = _build_postdown_rules(server_cfg.interface)

    lines = [
        "[Interface]",
        f"Address = {server_cfg.address}",
        f"ListenPort = {server_cfg.listen_port}",
        f"PrivateKey = {server_cfg.private_key}",
        f"DNS = {server_cfg.dns}",
        f"PostUp = {post_up}",
        f"PostDown = {post_down}",
    ]

    for client in clients:
        lines += [
            "",
            "[Peer]",
            f"# Client: {client.address}",
            f"PublicKey = {client.public_key}",
            f"AllowedIPs = {client.address}",
        ]

    return "\n".join(lines) + "\n"


# ── Client config ────────────────────────────────────────────────────────────

def generate_client_config(
    client_cfg: WireGuardClientConfig,
    server_public_key: str,
    server_endpoint: str,
) -> str:
    """Render a WireGuard client .conf string.

    Args:
        client_cfg:       Client keys and address.
        server_public_key: Server's public key.
        server_endpoint:  "host:port" of the WG server.

    Returns:
        Multi-line WireGuard client config string.
    """
    lines = [
        "[Interface]",
        f"Address = {client_cfg.address}",
        f"PrivateKey = {client_cfg.private_key}",
        f"DNS = {client_cfg.dns}",
        "",
        "[Peer]",
        f"PublicKey = {server_public_key}",
        f"Endpoint = {server_endpoint}",
        f"AllowedIPs = {client_cfg.allowed_ips}",
        f"PersistentKeepalive = {client_cfg.persistent_keepalive}",
    ]
    return "\n".join(lines) + "\n"
