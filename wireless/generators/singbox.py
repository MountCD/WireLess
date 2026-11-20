"""
sing-box JSON configuration generator.

Generates a full sing-box config from a ProxyConfig, including:
  - inbounds: socks (2080), http (2081), tproxy (2082)
  - outbounds: proxy (type-specific), direct, block
  - dns: remote via proxy + local fallback
  - route: private IPs → direct, DNS hijacking, rest → proxy

Requires sing-box >= 1.12 (new DNS server format and rule actions).
"""
import json
import logging
from typing import Union

from wireless.models import (
    ProxyConfig, VlessConfig, VmessConfig,
    TrojanConfig, Hysteria2Config,
)
from wireless import config as cfg

logger = logging.getLogger(__name__)


# ── Outbound builders ────────────────────────────────────────────────────────

def _build_vless_outbound(c: VlessConfig) -> dict:
    out: dict = {
        "type":        "vless",
        "tag":         "proxy",
        "server":      c.server,
        "server_port": c.port,
        "uuid":        c.uuid,
    }
    if c.flow:
        out["flow"] = c.flow

    tls_block: dict = {}

    if c.security in ("tls", "reality"):
        tls_block["enabled"] = True
        if c.sni:
            tls_block["server_name"] = c.sni
        if c.fp:
            tls_block["utls"] = {"enabled": True, "fingerprint": c.fp}
        if c.security == "reality":
            tls_block["reality"] = {
                "enabled":    True,
                "public_key": c.pbk,
                "short_id":   c.sid,
            }

    if tls_block:
        out["tls"] = tls_block

    # Transport
    if c.network == "ws":
        transport: dict = {"type": "ws"}
        if c.path:
            transport["path"] = c.path
        if c.host:
            transport["headers"] = {"Host": c.host}
        out["transport"] = transport
    elif c.network == "grpc":
        transport = {"type": "grpc"}
        if c.path:
            transport["service_name"] = c.path
        out["transport"] = transport

    return out


def _build_vmess_outbound(c: VmessConfig) -> dict:
    out: dict = {
        "type":        "vmess",
        "tag":         "proxy",
        "server":      c.server,
        "server_port": c.port,
        "uuid":        c.uuid,
        "alter_id":    c.alter_id,
        "security":    c.cipher,
    }

    if c.tls:
        tls_block: dict = {"enabled": True}
        if c.sni:
            tls_block["server_name"] = c.sni
        out["tls"] = tls_block

    if c.network == "ws":
        transport: dict = {"type": "ws"}
        if c.path:
            transport["path"] = c.path
        if c.host:
            transport["headers"] = {"Host": c.host}
        out["transport"] = transport
    elif c.network in ("h2", "http"):
        transport = {"type": "http"}
        if c.path:
            transport["path"] = c.path
        if c.host:
            transport["host"] = [c.host]
        out["transport"] = transport
    elif c.network == "grpc":
        transport = {"type": "grpc"}
        if c.path:
            transport["service_name"] = c.path
        out["transport"] = transport

    return out


def _build_trojan_outbound(c: TrojanConfig) -> dict:
    out: dict = {
        "type":        "trojan",
        "tag":         "proxy",
        "server":      c.server,
        "server_port": c.port,
        "password":    c.password,
    }

    tls_block: dict = {"enabled": True}
    if c.sni:
        tls_block["server_name"] = c.sni
    out["tls"] = tls_block

    if c.network == "ws":
        transport: dict = {"type": "ws"}
        if c.path:
            transport["path"] = c.path
        if c.host:
            transport["headers"] = {"Host": c.host}
        out["transport"] = transport

    return out


def _build_hysteria2_outbound(c: Hysteria2Config) -> dict:
    out: dict = {
        "type":        "hysteria2",
        "tag":         "proxy",
        "server":      c.server,
        "server_port": c.port,
    }

    if c.auth:
        out["password"] = c.auth

    if c.obfs:
        out["obfs"] = {
            "type":     c.obfs,
            "password": c.obfs_password,
        }

    tls_block: dict = {"enabled": True}
    if c.sni:
        tls_block["server_name"] = c.sni
    if c.insecure:
        tls_block["insecure"] = True
    out["tls"] = tls_block

    return out


_OUTBOUND_BUILDERS = {
    "vless":     _build_vless_outbound,
    "vmess":     _build_vmess_outbound,
    "trojan":    _build_trojan_outbound,
    "hysteria2": _build_hysteria2_outbound,
}


# ── Main generator ───────────────────────────────────────────────────────────

def generate_singbox_config(proxy: ProxyConfig) -> dict:
    """Generate a complete sing-box configuration dict for the given proxy.

    Args:
        proxy: A parsed ProxyConfig subclass instance.

    Returns:
        dict suitable for json.dumps as sing-box config.json.

    Raises:
        ValueError: If the proxy type is unsupported.
    """
    builder = _OUTBOUND_BUILDERS.get(proxy.type)
    if builder is None:
        raise ValueError(f"Unsupported proxy type for sing-box: {proxy.type!r}")

    proxy_outbound = builder(proxy)  # type: ignore[arg-type]

    singbox_config = {
        "log": {
            "level":     "info",
            "timestamp": True,
        },
        # sing-box >= 1.12 DNS server format.
        "dns": {
            "servers": [
                {
                    "type":   "tls",
                    "tag":    "remote",
                    "server": "1.1.1.1",
                    "detour": "proxy",
                },
                # No detour: in sing-box >= 1.12 DNS transports use their own
                # dialer, and detouring to an empty "direct" outbound is
                # rejected at startup.  Without detour this server dials
                # directly, which is exactly what "local" means here.
                {
                    "type":   "udp",
                    "tag":    "local",
                    "server": "223.5.5.5",
                },
                # TODO(удалить/переосмыслить): старый DNS-сервер "block"
                # (address "rcode://success") удалён из формата sing-box 1.12.
                # Если понадобится блокировка, используйте DNS rule action
                # "predefined" с rcode.
            ],
            "rules": [
                {
                    "clash_mode": "Direct",
                    "server":     "local",
                },
            ],
            "final":    "remote",
            "strategy": "prefer_ipv4",
        },
        "inbounds": [
            {
                "type":          "tproxy",
                "tag":           "tproxy-in",
                "listen":        "0.0.0.0",
                "listen_port":   cfg.SINGBOX_TPROXY_PORT,
                "tcp_fast_open": True,
            },
            {
                "type":        "socks",
                "tag":         "socks-in",
                "listen":      "0.0.0.0",
                "listen_port": cfg.SINGBOX_SOCKS_PORT,
            },
            {
                "type":        "http",
                "tag":         "http-in",
                "listen":      "0.0.0.0",
                "listen_port": cfg.SINGBOX_HTTP_PORT,
            },
        ],
        "outbounds": [
            proxy_outbound,
            {"type": "direct", "tag": "direct"},
            # TODO(удалить/переосмыслить): не используется, оставлен на случай
            # будущих правил блокировки (legacy special outbound).
            {"type": "block", "tag": "block"},
        ],
        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_is_private": True, "outbound": "direct"},
                {"clash_mode": "Direct", "outbound": "direct"},
                {"clash_mode": "Global", "outbound": "proxy"},
            ],
            "final": "proxy",
            "auto_detect_interface": True,
            # Resolve outbound server domains locally, otherwise resolving the
            # proxy server itself would loop through the proxy.
            "default_domain_resolver": "local",
        },
    }

    logger.debug(
        "Generated sing-box config for proxy type=%s server=%s port=%d",
        proxy.type, proxy.server, proxy.port,
    )
    return singbox_config


def config_to_json(proxy: ProxyConfig, indent: int = 2) -> str:
    """Return sing-box config as a formatted JSON string."""
    return json.dumps(generate_singbox_config(proxy), indent=indent, ensure_ascii=False)
