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
    wireless restart
    wireless remove MyProxy
"""
import logging
import sys
from pathlib import Path
from typing import Optional

import click

from wireless import config as cfg
from wireless.services import (
    ConflictError,
    GatewayService,
    NotFoundError,
    ServiceError,
)

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("wireless.cli")


def _fail(message: str) -> None:
    click.echo(message, err=True)
    sys.exit(1)


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
    service = GatewayService()
    try:
        proxy = service.add_proxy(proxy_url)
    except ValueError as exc:
        _fail(f"❌ Parse error: {exc}")
    except ConflictError as exc:
        _fail(f"⚠️  {exc}")

    click.echo(f"✅ Added proxy: {proxy['name']}")
    click.echo(f"   Type:   {proxy['type']}")
    click.echo(f"   Server: {proxy['server']}:{proxy['port']}")


# ── list ──────────────────────────────────────────────────────────────────────

@cli.command(name="list")
def list_configs():
    """List all saved proxy configurations."""
    service = GatewayService()
    configs = service.list_proxies()
    active = service.store.load_state().get("active", "")

    if not configs:
        click.echo("No proxy configs saved. Use 'wireless add <url>' to add one.")
        return

    click.echo(f"{'#':<4} {'NAME':<30} {'TYPE':<12} {'SERVER':<40}")
    click.echo("-" * 90)
    for i, config in enumerate(configs):
        name = config.get("name", config.get("_name", "?"))
        ptype = config.get("_type", config.get("type", "?"))
        server = f"{config.get('server', '?')}:{config.get('port', '?')}"
        marker = " ◀ active" if name == active else ""
        click.echo(f"{i:<4} {name:<30} {ptype:<12} {server:<40}{marker}")


# ── use ───────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("name_or_index")
def use(name_or_index: str):
    """Set the active proxy configuration.

    NAME_OR_INDEX: config name or list index (0-based)
    """
    service = GatewayService()
    try:
        active = service.activate(name_or_index)
    except NotFoundError as exc:
        _fail(f"❌ {exc}")
    click.echo(f"✅ Active config set to: {active}")


# ── remove ────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("name")
def remove(name: str):
    """Remove a saved proxy configuration."""
    service = GatewayService()
    try:
        service.remove_proxy(name)
    except NotFoundError as exc:
        _fail(f"❌ {exc}")
    click.echo(f"✅ Removed config: {name}")


# ── start ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--server-ip", default="", help="Public IP of this server (for client config Endpoint).")
def start(server_ip: str):
    """Start WireGuard + sing-box + routing."""
    service = GatewayService()
    click.echo("🚀 Starting WireLess...")
    try:
        result = service.start(server_ip)
    except ValueError as exc:
        _fail(f"❌ Failed to load proxy config: {exc}")
    except ServiceError as exc:
        _fail(f"❌ {exc}")
    except RuntimeError as exc:
        _fail(f"❌ {exc}")

    click.echo(f"  sing-box: {result['singbox']}")
    click.echo(f"  WireGuard: {result['wireguard']}")
    if result["routing"] == "failed":
        click.echo("  routing: failed (see logs)")
    else:
        click.echo(f"  routing: {result['routing']}")

    click.echo()
    click.echo("✅ WireLess is running!")
    click.echo(f"   WireGuard:  {cfg.WG_INTERFACE}  port={cfg.WG_LISTEN_PORT}")
    click.echo(f"   SOCKS5:     0.0.0.0:{cfg.SINGBOX_SOCKS_PORT}")
    click.echo(f"   HTTP proxy: 0.0.0.0:{cfg.SINGBOX_HTTP_PORT}")
    click.echo(f"   Server IP:  {result['server_ip']}")
    click.echo()
    click.echo("Run 'wireless client' to get the WireGuard client config.")


# ── stop ──────────────────────────────────────────────────────────────────────

@cli.command()
def stop():
    """Stop sing-box, routing and WireGuard."""
    service = GatewayService()
    click.echo("🛑 Stopping WireLess...")
    stopped = service.stop()
    if stopped["routing"]:
        click.echo("  routing: stopped")
    if stopped["singbox"]:
        click.echo("  sing-box: stopped")
    if stopped["wireguard"]:
        click.echo("  WireGuard: stopped")
    click.echo("✅ WireLess stopped.")


# ── restart ───────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--server-ip", default="", help="Public IP of this server (for client config Endpoint).")
def restart(server_ip: str):
    """Restart WireGuard + sing-box + routing."""
    service = GatewayService()
    click.echo("🔄 Restarting WireLess...")
    try:
        result = service.restart(server_ip)
    except ValueError as exc:
        _fail(f"❌ Failed to load proxy config: {exc}")
    except ServiceError as exc:
        _fail(f"❌ {exc}")
    except RuntimeError as exc:
        _fail(f"❌ {exc}")

    click.echo(f"  sing-box: {result['singbox']}")
    click.echo(f"  WireGuard: {result['wireguard']}")
    if result["routing"] == "failed":
        click.echo("  routing: failed (see logs)")
    else:
        click.echo(f"  routing: {result['routing']}")
    click.echo()
    click.echo(f"✅ WireLess restarted! (server IP: {result['server_ip']})")


# ── status ────────────────────────────────────────────────────────────────────

@cli.command()
def status():
    """Show current status of all components."""
    snapshot = GatewayService().status()

    click.echo(f"Active config: {snapshot['active'] or '(none)'}")
    click.echo(f"Server IP:     {snapshot['server_ip']}")
    click.echo()

    wg_status = snapshot["wireguard"]
    wg_icon = "🟢" if wg_status["running"] else "🔴"
    click.echo(
        f"{wg_icon} WireGuard ({cfg.WG_INTERFACE}): "
        f"{'running' if wg_status['running'] else 'stopped'}"
    )
    if wg_status.get("details"):
        for line in wg_status["details"].splitlines():
            click.echo(f"   {line}")

    sb_status = snapshot["singbox"]
    sb_icon = "🟢" if sb_status["running"] else "🔴"
    click.echo(
        f"{sb_icon} sing-box: {'running' if sb_status['running'] else 'stopped'}"
        + (f" (pid={sb_status['pid']})" if sb_status.get("pid") else "")
    )
    binary_note = "" if Path(sb_status["binary"]).is_file() else " (not found)"
    click.echo(f"   binary: {sb_status['binary']}{binary_note}")

    r_icon = "🟢" if snapshot["routing"] else "🔴"
    click.echo(
        f"{r_icon} iptables TPROXY routing: "
        f"{'active' if snapshot['routing'] else 'inactive'}"
    )

    click.echo()
    click.echo(f"Proxy configs saved: {snapshot['configs_count']}")


# ── client ────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--qr", is_flag=True, help="Display QR code of the client config.")
@click.option("--save", type=click.Path(), default=None, help="Save config to file.")
@click.option("--index", default=0, show_default=True, help="Client index (0-based).")
def client(qr: bool, save: Optional[str], index: int):
    """Display (or save) the WireGuard client configuration."""
    service = GatewayService()
    try:
        conf_text = service.client_config(index)
    except NotFoundError as exc:
        _fail(f"❌ {exc}")

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


# ── web ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind address.")
@click.option("--port", default=8787, show_default=True, type=int, help="Bind port.")
@click.option(
    "--set-password",
    "set_password_flag",
    is_flag=True,
    help="Set the admin password interactively and exit.",
)
@click.option(
    "--no-auth",
    is_flag=True,
    help="Disable authentication (loopback bind only).",
)
def web(host: str, port: int, set_password_flag: bool, no_auth: bool):
    """Run the local web UI (http://127.0.0.1:8787 by default)."""
    try:
        from wireless.web.auth import WebAuth
        from wireless.web.bind import check_bind
    except ImportError as exc:
        _fail(
            f"❌ Web UI dependencies are missing: {exc}\n"
            "   Install them with: pip install 'wireless[web]'"
        )

    auth = WebAuth()

    if set_password_flag:
        password = click.prompt(
            "New admin password", hide_input=True, confirmation_prompt=True
        )
        try:
            auth.set_password(password)
        except ValueError as exc:
            _fail(f"❌ {exc}")
        except PermissionError:
            _fail("❌ Cannot write /etc/wireless/web.json — run this command as root.")
        click.echo("✅ Password updated.")
        return

    try:
        configured = auth.is_configured()
    except PermissionError:
        _fail("❌ Cannot read /etc/wireless/web.json — run the web UI as root.")

    problem = check_bind(host, no_auth=no_auth, configured=configured)
    if problem:
        _fail(problem)

    if no_auth:
        click.echo(f"🔓 Web UI: http://{host}:{port} (authentication disabled)")
    elif configured:
        click.echo(f"🔐 Web UI: http://{host}:{port}")
    else:
        try:
            generated = auth.ensure_configured()
        except PermissionError:
            _fail("❌ Cannot write /etc/wireless/web.json — run the web UI as root.")
        click.echo("🔐 Generated admin password (shown only once):")
        click.echo(f"   {generated}")
        click.echo("   Change it with: wireless web --set-password")

    try:
        import uvicorn

        from wireless.web.app import create_app
    except ImportError as exc:
        _fail(
            f"❌ Web UI dependencies are missing: {exc}\n"
            "   Install them with: pip install 'wireless[web]'"
        )

    uvicorn.run(create_app(auth=auth, auth_enabled=not no_auth), host=host, port=port)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    cli()


if __name__ == "__main__":
    main()
