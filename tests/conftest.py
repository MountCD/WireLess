"""Shared pytest fixtures: isolated state directory and fake runtime managers."""
from types import SimpleNamespace

import pytest

from wireless import config as cfg
from wireless.services import GatewayService
from wireless.store import Store


class FakeSingBox:
    def __init__(self):
        self.running = False
        self.started_with: list[dict] = []
        self.stop_calls = 0
        self.fail_on_start = ""

    def is_running(self) -> bool:
        return self.running

    def start(self, config: dict) -> None:
        if self.fail_on_start:
            raise RuntimeError(self.fail_on_start)
        self.running = True
        self.started_with.append(config)

    def stop(self) -> None:
        self.stop_calls += 1
        self.running = False

    def status(self) -> dict:
        return {
            "running": self.running,
            "pid": 42 if self.running else None,
            "binary": "/usr/bin/sing-box",
            "config": "/tmp/singbox/config.json",
            "log": "/tmp/singbox/singbox.log",
        }


class FakeWireGuard:
    def __init__(self):
        self.running = False
        self.clients: list = []
        self.fail_on_setup = ""

    def is_running(self) -> bool:
        return self.running

    def setup(self) -> None:
        if self.fail_on_setup:
            raise RuntimeError(self.fail_on_setup)
        self.running = True

    def teardown(self) -> None:
        self.running = False

    def list_clients(self) -> list:
        return list(self.clients)

    def add_client(self, server_public_ip: str = "", **kwargs):
        client = SimpleNamespace(
            public_key=f"pub{len(self.clients)}",
            server_public_ip=server_public_ip,
        )
        self.clients.append(client)
        return client

    def status(self) -> dict:
        return {"interface": "wg0", "running": self.running}

    def get_client_config_text(self, client, server_ip: str = "") -> str:
        return f"[Interface]\n# {server_ip}\n"


class FakeRouting:
    def __init__(self):
        self.active = False
        self.fail_on_setup = ""

    def is_active(self) -> bool:
        return self.active

    def setup(self) -> None:
        if self.fail_on_setup:
            raise RuntimeError(self.fail_on_setup)
        self.active = True

    def teardown(self) -> None:
        self.active = False


@pytest.fixture
def store(tmp_path, monkeypatch):
    """A Store pointed at a temporary directory instead of /etc/wireless."""
    base = tmp_path / "wireless"
    monkeypatch.setattr(cfg, "CONFIGS_FILE", str(base / "configs.json"))
    monkeypatch.setattr(cfg, "STATE_FILE", str(base / "state.json"))
    monkeypatch.setattr(cfg, "SUBSCRIPTIONS_FILE", str(base / "subscriptions.json"))
    monkeypatch.setattr(cfg, "LOCK_FILE", str(base / ".lock"))
    return Store()


@pytest.fixture
def fakes():
    return SimpleNamespace(
        singbox=FakeSingBox(),
        wireguard=FakeWireGuard(),
        routing=FakeRouting(),
    )


@pytest.fixture
def service(store, fakes):
    return GatewayService(
        store=store,
        singbox=fakes.singbox,
        wireguard=fakes.wireguard,
        routing=fakes.routing,
    )


VLESS_URL = (
    "vless://11111111-1111-1111-1111-111111111111@example.com:443"
    "?security=tls&sni=example.com&type=ws&path=%2Fws#TestNode"
)
