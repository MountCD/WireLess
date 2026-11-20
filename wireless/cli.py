#!/usr/bin/env python3
"""
WireLess CLI — WireGuard gateway for proxy protocols.

Usage examples:
    wireless add "vless://uuid@host:443?security=reality&...#MyProxy"
    wireless list
    wireless use MyProxy
    wireless start
    wireless status
    wireless client
    wireless client --qr
    wireless stop
    wireless remove MyProxy
"""
import dataclasses
import json
import logging
import os
import socket
import sys
from pathlib import Path
from typing import Optional

import click

from wireless import config as cfg
from wireless.parsers.auto import parse_proxy_url
from wireless.generators.singbox import generate_singbox_config
from wireless.managers.wireguard import WireGuardManager
from wireless.managers.singbox import SingBoxManager
from wireless.managers.routing import RoutingManager

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("wireless.cli")


# ── State helpers ─────────────────────────────────────────────────────────────

def _ensure_state_dirs() -> None:
    Path(cfg.STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(cfg.CONFIGS_FILE).parent.mkdir(parents=True, exist_ok=True)


def _load_configs() -> list[dict]:
    """Load saved proxy configs from disk."""
    p = Path(cfg.CONFIGS_FILE)
    if not p.exists():
        return []
    return json.loads(p.read_text())


def _save_configs(configs: list[dict]) -> None:
    _ensure_state_dirs()
    Path(cfg.CONFIGS_FILE).write_text(json.dumps(configs, indent=2, ensure_ascii=False))


def _load_state() -> dict:
    p = Path(cfg.STATE_FILE)
    if not p.exists():
        return {}
    return json.loads(p.read_text())


def _save_state(state: dict) -> None:
    _ensure_state_dirs()
    Path(cfg.STATE_FILE).write_text(json.dumps(state, indent=2, ensure_ascii=False))


def _get_active_config(state: dict, configs: list[dict]) -> Optional[dict]:
    active_name = state.get("active")
    if not active_name:
        return None
    for c in configs:
        if c.get("name") == active_name or c.get("_name") == active_name:
            return c
    return None


def _proxy_config_to_dict(proxy_cfg) -> dict:
    """Convert a ProxyConfig dataclass to a serialisable dict."""
    d = dataclasses.asdict(proxy_cfg)
    d["_type"] = proxy_cfg.type
    return d


def _dict_to_proxy_config(d: dict):
    """Reconstruct a ProxyConfig subclass from a dict."""
    from wireless.models import VlessConfig, VmessConfig, TrojanConfig, Hysteria2Config
    type_map = {
        "vless":     VlessConfig,
        "vmess":     VmessConfig,
        "trojan":    TrojanConfig,
        "hysteria2": Hysteria2Config,
    }
    t = d.get("_type") or d.get("type", "")
    cls = type_map.get(t)
    if cls is None:
        raise ValueError(f"Unknown proxy type: {t!r}")
    # Only pass fields known to the dataclass
    known = {f.name for f in dataclasses.fields(cls)}
    filtered = {k: v for k, v in d.items() if k in known}
    return cls(**filtered)


# ── CLI group ─────────────────────────────────────────────────────────────────

@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose logging.")
def cli(verbose: bool):
    """WireLess — WireGuard gateway for proxy protocols."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)


# ── add ───────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("proxy_url")
def add(proxy_url: str):
    """Parse and save a proxy URL.

    PROXY_URL: vless://, vmess://, trojan://, hysteria2:// link
    """
    try:
        proxy = parse_proxy_url(proxy_url)
    except ValueError as exc:
        click.echo(f"❌ Parse error: {exc}", err=True)
        sys.exit(1)

    name = proxy.name or f"{proxy.type}_{proxy.server}_{proxy.port}"
    proxy.name = name

    configs = _load_configs()
    # Check for duplicate name
    for existing in configs:
        if existing.get("name") == name or existing.get("_name") == name:
            click.echo(f"⚠️  Config named {name!r} already exists. Use 'remove' first.")
            sys.exit(1)

    d = _proxy_config_to_dict(proxy)
    d["name"] = name
    configs.append(d)
    _save_configs(configs)

    click.echo(f"✅ Added proxy: {name}")
    click.echo(f"   Type:   {proxy.type}")
    click.echo(f"   Server: {proxy.server}:{proxy.port}")


# ── list ──────────────────────────────────────────────────────────────────────

@cli.command(name="list")
def list_configs():
    """List all saved proxy configurations."""
    configs = _load_configs()
    state   = _load_state()
    active  = state.get("active", "")

    if not configs:
        click.echo("No proxy configs saved. Use 'wireless add <url>' to add one.")
        return

    click.echo(f"{'#':<4} {'NAME':<30} {'TYPE':<12} {'SERVER':<40}")
    click.echo("-" * 90)
    for i, c in enumerate(configs):
        name   = c.get("name", c.get("_name", "?"))
        ptype  = c.get("_type", c.get("type", "?"))
        server = f"{c.get('server', '?')}:{c.get('port', '?')}"
        marker = " ◀ active" if name == active else ""
        click.echo(f"{i:<4} {name:<30} {ptype:<12} {server:<40}{marker}")


# ── use ───────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("name_or_index")
def use(name_or_index: str):
    """Set the active proxy configuration.

    NAME_OR_INDEX: config name or list index (0-based)
    """
    configs = _load_configs()
    if not configs:
        click.echo("No configs saved.", err=True)
        sys.exit(1)

    # Try index first
    target = None
    try:
        idx = int(name_or_index)
        if 0 <= idx < len(configs):
            target = configs[idx]
    except ValueError:
        pass

    if target is None:
        for c in configs:
            if c.get("name") == name_or_index or c.get("_name") == name_or_index:
                target = c
                break

    if target is None:
        click.echo(f"❌ Config {name_or_index!r} not found.", err=True)
        sys.exit(1)

    state = _load_state()
    state["active"] = target.get("name", target.get("_name"))
    _save_state(state)
    click.echo(f"✅ Active config set to: {state['active']}")


# ── remove ────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("name")
def remove(name: str):
    """Remove a saved proxy configuration."""
    configs = _load_configs()
    new_configs = [
        c for c in configs
        if c.get("name") != name and c.get("_name") != name
    ]
    if len(new_configs) == len(configs):
        click.echo(f"❌ Config {name!r} not found.", err=True)
        sys.exit(1)
    _save_configs(new_configs)

    # Clear active if removed
    state = _load_state()
    if state.get("active") == name:
        state.pop("active", None)
        _save_state(state)

    click.echo(f"✅ Removed config: {name}")


# ── start ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--server-ip", default="", help="Public IP of this server (for client config Endpoint).")
def start(server_ip: str):
    """Start WireGuard + sing-box + routing."""
    state   = _load_state()
    configs = _load_configs()
    cfg_dict = _get_active_config(state, configs)

    if cfg_dict is None:
        click.echo(
            "❌ No active proxy config. Use 'wireless use <name>' first.", err=True
        )
        sys.exit(1)

    try:
        proxy = _dict_to_proxy_config(cfg_dict)
    except Exception as exc:
        click.echo(f"❌ Failed to load proxy config: {exc}", err=True)
        sys.exit(1)

    singbox_cfg = generate_singbox_config(proxy)

    # Detect public IP if not provided
    if not server_ip:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            server_ip = s.getsockname()[0]
            s.close()
        except Exception:
            server_ip = "0.0.0.0"

    click.echo("🚀 Starting WireLess...")

    # 1. sing-box
    sb = SingBoxManager()
    if not sb.is_running():
        try:
            click.echo("  Starting sing-box...")
            sb.start(singbox_cfg)
        except RuntimeError as exc:
            click.echo(f"❌ sing-box: {exc}", err=True)
            sys.exit(1)
    else:
        click.echo("  sing-box already running")

    # 2. WireGuard
    wg = WireGuardManager()
    if not wg.is_running():
        try:
            click.echo("  Starting WireGuard...")
            wg.setup()
            # Add a default client if none exist
            if not wg.list_clients():
                click.echo("  Generating client keypair...")
                wg.add_client(server_public_ip=server_ip)
        except RuntimeError as exc:
            sb.stop()
            click.echo(f"❌ WireGuard: {exc}", err=True)
            sys.exit(1)
    else:
        click.echo("  WireGuard already running")

    # 3. Routing
    routing = RoutingManager()
    if not routing.is_active():
        try:
            click.echo("  Setting up iptables TPROXY routing...")
            routing.setup()
        except Exception as exc:
            click.echo(f"⚠️  Routing setup warning: {exc}", err=True)

    state["running"] = True
    state["server_ip"] = server_ip
    _save_state(state)

    click.echo()
    click.echo(f"✅ WireLess is running!")
    click.echo(f"   WireGuard:  {cfg.WG_INTERFACE}  port={cfg.WG_LISTEN_PORT}")
    click.echo(f"   SOCKS5:     0.0.0.0:{cfg.SINGBOX_SOCKS_PORT}")
    click.echo(f"   HTTP proxy: 0.0.0.0:{cfg.SINGBOX_HTTP_PORT}")
    click.echo(f"   Server IP:  {server_ip}")
    click.echo()
    click.echo("Run 'wireless client' to get the WireGuard client config.")


# ── stop ──────────────────────────────────────────────────────────────────────

@cli.command()
def stop():
    """Stop sing-box, routing and WireGuard."""
    click.echo("🛑 Stopping WireLess...")

    routing = RoutingManager()
    if routing.is_active():
        click.echo("  Removing iptables rules...")
        routing.teardown()

    sb = SingBoxManager()
    if sb.is_running():
        click.echo("  Stopping sing-box...")
        sb.stop()

    wg = WireGuardManager()
    if wg.is_running():
        click.echo("  Bringing down WireGuard...")
        wg.teardown()

    state = _load_state()
    state["running"] = False
    _save_state(state)

    click.echo("✅ WireLess stopped.")


# ── status ────────────────────────────────────────────────────────────────────

@cli.command()
def status():
    """Show current status of all components."""
    state   = _load_state()
    configs = _load_configs()
    active  = state.get("active", "(none)")

    click.echo(f"Active config: {active}")
    click.echo(f"Server IP:     {state.get('server_ip', 'unknown')}")
    click.echo()

    # WireGuard
    wg = WireGuardManager()
    wg_status = wg.status()
    wg_icon = "🟢" if wg_status["running"] else "🔴"
    click.echo(f"{wg_icon} WireGuard ({cfg.WG_INTERFACE}): {'running' if wg_status['running'] else 'stopped'}")
    if wg_status.get("details"):
        for line in wg_status["details"].splitlines():
            click.echo(f"   {line}")

    # sing-box
    sb = SingBoxManager()
    sb_status = sb.status()
    sb_icon = "🟢" if sb_status["running"] else "🔴"
    click.echo(
        f"{sb_icon} sing-box: {'running' if sb_status['running'] else 'stopped'}"
        + (f" (pid={sb_status['pid']})" if sb_status.get('pid') else "")
    )
    binary_note = "" if Path(sb_status["binary"]).is_file() else " (not found)"
    click.echo(f"   binary: {sb_status['binary']}{binary_note}")

    # Routing
    routing = RoutingManager()
    r_active = routing.is_active()
    r_icon = "🟢" if r_active else "🔴"
    click.echo(f"{r_icon} iptables TPROXY routing: {'active' if r_active else 'inactive'}")

    click.echo()
    click.echo(f"Proxy configs saved: {len(configs)}")


# ── client ────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--qr", is_flag=True, help="Display QR code of the client config.")
@click.option("--save", type=click.Path(), default=None, help="Save config to file.")
@click.option("--index", default=0, show_default=True, help="Client index (0-based).")
def client(qr: bool, save: Optional[str], index: int):
    """Display (or save) the WireGuard client configuration."""
    state = _load_state()
    server_ip = state.get("server_ip", "0.0.0.0")

    wg = WireGuardManager()
    clients = wg.list_clients()

    if not clients:
        click.echo(
            "❌ No client configs found. Run 'wireless start' first.", err=True
        )
        sys.exit(1)

    if index >= len(clients):
        click.echo(
            f"❌ Client index {index} out of range (0–{len(clients)-1}).", err=True
        )
        sys.exit(1)

    client_cfg = clients[index]
    conf_text  = wg.get_client_config_text(client_cfg, server_ip)

    click.echo("── WireGuard Client Config ─────────────────────")
    click.echo(conf_text)

    if save:
        Path(save).write_text(conf_text)
        click.echo(f"✅ Saved to {save}")

    if qr:
        try:
            import qrcode  # type: ignore
            qr_obj = qrcode.QRCode()
            qr_obj.add_data(conf_text)
            qr_obj.make(fit=True)
            qr_obj.print_ascii(invert=True)
        except ImportError:
            click.echo("❌ qrcode not installed. Run: pip install qrcode[pil]", err=True)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    cli()


if __name__ == "__main__":
    main()
