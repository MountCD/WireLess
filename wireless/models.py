"""
Data models for WireLess proxy configurations.
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ProxyConfig:
    """Base proxy configuration."""
    type: str
    server: str
    port: int
    name: str = ""
    uuid: str = ""
    password: str = ""


@dataclass
class VlessConfig(ProxyConfig):
    """VLESS proxy configuration."""
    flow: str = ""
    security: str = "none"          # none | tls | reality
    sni: str = ""
    fp: str = ""                    # uTLS fingerprint
    pbk: str = ""                   # reality public key
    sid: str = ""                   # reality short id
    path: str = ""                  # WS path
    host: str = ""                  # WS host header
    network: str = "tcp"            # tcp | ws | grpc
    encryption: str = "none"

    def __post_init__(self):
        self.type = "vless"


@dataclass
class VmessConfig(ProxyConfig):
    """VMess proxy configuration."""
    alter_id: int = 0
    cipher: str = "auto"
    network: str = "tcp"            # tcp | ws | grpc | h2
    path: str = ""
    host: str = ""
    tls: bool = False
    sni: str = ""

    def __post_init__(self):
        self.type = "vmess"


@dataclass
class TrojanConfig(ProxyConfig):
    """Trojan proxy configuration."""
    sni: str = ""
    path: str = ""
    host: str = ""
    security: str = "tls"
    network: str = "tcp"            # tcp | ws

    def __post_init__(self):
        self.type = "trojan"


@dataclass
class Hysteria2Config(ProxyConfig):
    """Hysteria2 proxy configuration."""
    auth: str = ""
    obfs: str = ""                  # salamander | (empty)
    obfs_password: str = ""
    sni: str = ""
    insecure: bool = False

    def __post_init__(self):
        self.type = "hysteria2"


@dataclass
class WireGuardServerConfig:
    """WireGuard server interface configuration."""
    interface: str
    private_key: str
    public_key: str
    address: str
    listen_port: int
    dns: str = "1.1.1.1"
    peers: list = field(default_factory=list)   # list of WireGuardClientConfig


@dataclass
class WireGuardClientConfig:
    """WireGuard client peer configuration."""
    private_key: str
    public_key: str
    server_public_key: str
    server_endpoint: str            # host:port
    allowed_ips: str = "0.0.0.0/0, ::/0"
    address: str = "10.100.0.2/32"
    dns: str = "1.1.1.1"
    persistent_keepalive: int = 25
