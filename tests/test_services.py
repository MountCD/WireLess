"""Tests for the shared service layer (no root, no network, no subprocesses)."""
import threading

import pytest

from conftest import VLESS_URL
from wireless.services import (
    MASK,
    ConflictError,
    GatewayService,
    NotFoundError,
    config_name,
    dict_to_proxy_config,
    proxy_to_dict,
    public_config,
)


# ── Serialisation helpers ────────────────────────────────────────────────────

def test_proxy_dict_roundtrip_keeps_type_and_fields(service):
    saved = service.add_proxy(VLESS_URL)

    restored = dict_to_proxy_config(saved)

    assert restored.type == "vless"
    assert restored.server == "example.com"
    assert restored.port == 443
    assert restored.sni == "example.com"
    assert restored.network == "ws"


def test_dict_to_proxy_config_rejects_unknown_type():
    with pytest.raises(ValueError, match="Unknown proxy type"):
        dict_to_proxy_config({"_type": "shadowsocks"})


def test_dict_to_proxy_config_drops_service_keys(service):
    saved = service.add_proxy(VLESS_URL)

    restored = dict_to_proxy_config(saved)

    assert not hasattr(restored, "_source")


# ── add ──────────────────────────────────────────────────────────────────────

def test_add_uses_url_fragment_as_name(service):
    saved = service.add_proxy(VLESS_URL)

    assert saved["name"] == "TestNode"
    assert service.list_proxies()[0]["name"] == "TestNode"


def test_add_generates_name_without_fragment(service):
    saved = service.add_proxy(
        "vless://11111111-1111-1111-1111-111111111111@host.example:8443"
        "?security=tls&sni=host.example"
    )

    assert saved["name"] == "vless_host.example_8443"


def test_add_stores_raw_url_for_later_editing(service):
    service.add_proxy(VLESS_URL)

    assert service.list_proxies()[0]["_url"] == VLESS_URL


def test_add_rejects_duplicate_name(service):
    service.add_proxy(VLESS_URL)

    with pytest.raises(ConflictError, match="already exists"):
        service.add_proxy(VLESS_URL)


def test_add_rejects_broken_url(service):
    with pytest.raises(ValueError):
        service.add_proxy("http://example.com")


# ── activate ─────────────────────────────────────────────────────────────────

def test_activate_by_name_and_index(service):
    service.add_proxy(VLESS_URL)
    service.add_proxy(
        "vless://22222222-2222-2222-2222-222222222222@second.example:443"
        "?security=tls&sni=second.example#Second"
    )

    assert service.activate("Second") == "Second"
    assert service.store.load_state()["active"] == "Second"

    assert service.activate("0") == "TestNode"
    assert service.get_active_config()["name"] == "TestNode"


def test_activate_unknown_config(service):
    service.add_proxy(VLESS_URL)

    with pytest.raises(NotFoundError):
        service.activate("nope")


def test_activate_without_configs(service):
    with pytest.raises(NotFoundError):
        service.activate("anything")


# ── remove ───────────────────────────────────────────────────────────────────

def test_remove_config(service):
    service.add_proxy(VLESS_URL)

    service.remove_proxy("TestNode")

    assert service.list_proxies() == []


def test_remove_clears_active(service):
    service.add_proxy(VLESS_URL)
    service.activate("TestNode")

    service.remove_proxy("TestNode")

    assert "active" not in service.store.load_state()


def test_remove_unknown_config(service):
    with pytest.raises(NotFoundError):
        service.remove_proxy("ghost")


# ── status ───────────────────────────────────────────────────────────────────

def test_status_snapshot(service, fakes):
    service.add_proxy(VLESS_URL)
    service.activate("TestNode")
    service.store.update_state(server_ip="1.2.3.4")

    snapshot = service.status()

    assert snapshot["active"] == "TestNode"
    assert snapshot["server_ip"] == "1.2.3.4"
    assert snapshot["configs_count"] == 1
    assert snapshot["running"] is False
    assert snapshot["wireguard"] == {"interface": "wg0", "running": False}
    assert snapshot["singbox"]["running"] is False
    assert snapshot["routing"] is False


# ── start / stop / restart ───────────────────────────────────────────────────

def test_start_requires_active_config(service):
    with pytest.raises(ConflictError, match="No active proxy config"):
        service.start("1.2.3.4")


def test_start_brings_everything_up(service, fakes):
    service.add_proxy(VLESS_URL)
    service.activate("TestNode")

    result = service.start("1.2.3.4")

    assert result == {
        "server_ip": "1.2.3.4",
        "singbox": "started",
        "wireguard": "started",
        "routing": "active",
    }
    assert fakes.singbox.running
    assert fakes.wireguard.running
    assert fakes.routing.active
    assert fakes.singbox.started_with[0]["outbounds"][0]["type"] == "vless"
    # No clients existed, so start() generated one for the endpoint.
    assert len(fakes.wireguard.clients) == 1
    assert fakes.wireguard.clients[0].server_public_ip == "1.2.3.4"
    assert service.store.load_state()["running"] is True
    assert service.store.load_state()["server_ip"] == "1.2.3.4"


def test_start_is_idempotent_for_running_components(service, fakes):
    service.add_proxy(VLESS_URL)
    service.activate("TestNode")
    service.start("1.2.3.4")

    result = service.start("1.2.3.4")

    assert result["singbox"] == "already running"
    assert result["wireguard"] == "already running"
    assert result["routing"] == "active"
    assert len(fakes.singbox.started_with) == 1


def test_start_survives_routing_failure(service, fakes):
    service.add_proxy(VLESS_URL)
    service.activate("TestNode")
    fakes.routing.fail_on_setup = "iptables unavailable"

    result = service.start("1.2.3.4")

    assert result["routing"] == "failed"
    assert fakes.singbox.running
    assert service.store.load_state()["running"] is True


def test_start_rolls_back_singbox_when_wireguard_fails(service, fakes):
    service.add_proxy(VLESS_URL)
    service.activate("TestNode")
    fakes.wireguard.fail_on_setup = "wg-quick failed"

    with pytest.raises(RuntimeError, match="wg-quick failed"):
        service.start("1.2.3.4")

    assert fakes.singbox.running is False
    assert service.store.load_state().get("running") is not True


def test_stop_tears_down_running_components(service, fakes):
    service.add_proxy(VLESS_URL)
    service.activate("TestNode")
    service.start("1.2.3.4")

    stopped = service.stop()

    assert stopped == {"routing": True, "singbox": True, "wireguard": True}
    assert fakes.singbox.running is False
    assert fakes.wireguard.running is False
    assert fakes.routing.active is False
    assert service.store.load_state()["running"] is False


def test_stop_is_safe_when_nothing_runs(service):
    stopped = service.stop()

    assert stopped == {"routing": False, "singbox": False, "wireguard": False}


def test_restart_keeps_server_ip(service, fakes):
    service.add_proxy(VLESS_URL)
    service.activate("TestNode")
    service.start("5.6.7.8")

    result = service.restart()

    assert result["server_ip"] == "5.6.7.8"
    assert service.store.load_state()["server_ip"] == "5.6.7.8"
    assert fakes.singbox.running
    assert fakes.wireguard.running


# ── clients ──────────────────────────────────────────────────────────────────

def test_client_config_requires_clients(service):
    with pytest.raises(NotFoundError, match="No client configs"):
        service.client_config(0)


def test_client_config_returns_text(service, fakes):
    service.add_proxy(VLESS_URL)
    service.activate("TestNode")
    service.start("1.2.3.4")

    text = service.client_config(0)

    assert "1.2.3.4" in text


def test_client_config_index_out_of_range(service, fakes):
    service.add_proxy(VLESS_URL)
    service.activate("TestNode")
    service.start("1.2.3.4")

    with pytest.raises(NotFoundError, match="out of range"):
        service.client_config(5)


# ── helpers ──────────────────────────────────────────────────────────────────

def test_config_name_supports_legacy_key():
    assert config_name({"name": "A"}) == "A"
    assert config_name({"_name": "B"}) == "B"
    assert config_name({}) == ""


def test_proxy_to_dict_marks_type(service):
    saved = service.add_proxy(VLESS_URL)

    assert saved["_type"] == "vless"
    assert saved["type"] == "vless"
    assert proxy_to_dict(dict_to_proxy_config(saved))["_type"] == "vless"


# ── public representation ────────────────────────────────────────────────────

def test_public_config_masks_secrets_and_drops_url(service):
    saved = service.add_proxy(VLESS_URL)

    public = public_config(saved)

    assert public["uuid"] == MASK
    assert public["name"] == "TestNode"
    assert public["_type"] == "vless"
    assert "_url" not in public
    assert "_source" not in public


def test_public_config_masks_trojan_password(service):
    saved = service.add_proxy(
        "trojan://secret-password@example.com:443?sni=example.com#Trojan"
    )

    assert public_config(saved)["password"] == MASK


def test_public_config_can_reveal(service):
    saved = service.add_proxy(VLESS_URL)

    public = public_config(saved, reveal=True)

    assert public["uuid"].startswith("11111111")


def test_preview_proxy_does_not_save(service):
    preview = service.preview_proxy(VLESS_URL)

    assert preview["server"] == "example.com"
    assert preview["port"] == 443
    assert preview["_type"] == "vless"
    assert service.list_proxies() == []


def test_preview_proxy_rejects_broken_url(service):
    with pytest.raises(ValueError):
        service.preview_proxy("not-a-proxy")


# ── concurrency ──────────────────────────────────────────────────────────────

def test_concurrent_gateway_operation_conflicts(service):
    service.add_proxy(VLESS_URL)
    service.activate("TestNode")

    started = threading.Event()
    release = threading.Event()

    def hold():
        with service._operation():
            started.set()
            release.wait(5)

    thread = threading.Thread(target=hold)
    thread.start()
    assert started.wait(2)

    try:
        with pytest.raises(ConflictError, match="in progress"):
            service.start("1.2.3.4")
    finally:
        release.set()
        thread.join()
