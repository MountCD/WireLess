"""Config generators for WireLess."""
from wireless.generators.singbox import generate_singbox_config, config_to_json
from wireless.generators.wireguard import generate_keypair, generate_server_config, generate_client_config

__all__ = [
    "generate_singbox_config",
    "config_to_json",
    "generate_keypair",
    "generate_server_config",
    "generate_client_config",
]
