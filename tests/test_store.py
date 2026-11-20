"""Tests for the JSON state store: round-trips, permissions, locking."""
import json
import stat
import threading

import pytest

from wireless.store import DIR_MODE, FILE_MODE, StoreError


def test_missing_files_return_defaults(store):
    assert store.load_configs() == []
    assert store.load_state() == {}
    assert store.load_subscriptions() == []


def test_configs_roundtrip(store):
    configs = [{"_type": "vless", "name": "A", "server": "a.example", "port": 443}]
    store.save_configs(configs)
    assert store.load_configs() == configs


def test_state_roundtrip_and_unicode(store):
    state = {"active": "Узел", "running": True, "server_ip": "1.2.3.4"}
    store.save_state(state)
    assert store.load_state() == state
    assert "Узел" in store.state_path.read_text(encoding="utf-8")


def test_subscriptions_roundtrip(store):
    subs = [{"id": "sub_1", "url": "https://example.com/sub", "enabled": True}]
    store.save_subscriptions(subs)
    assert store.load_subscriptions() == subs


def test_files_are_private_and_dir_is_restricted(store):
    store.save_configs([])
    store.save_state({})
    store.save_subscriptions([])

    for path in (store.configs_path, store.state_path, store.subscriptions_path):
        assert stat.S_IMODE(path.stat().st_mode) == FILE_MODE
    assert stat.S_IMODE(store.configs_path.parent.stat().st_mode) == DIR_MODE


def test_write_is_atomic_and_leaves_no_temp_files(store):
    store.save_configs([{"name": "A"}])
    store.save_configs([{"name": "B"}])

    assert store.load_configs() == [{"name": "B"}]
    assert list(store.configs_path.parent.glob(".*.tmp")) == []


def test_update_state_merges_and_removes_none(store):
    store.save_state({"active": "A", "server_ip": "1.1.1.1"})

    result = store.update_state(active="B", running=True)

    assert result == {"active": "B", "server_ip": "1.1.1.1", "running": True}
    assert store.load_state() == result

    store.update_state(server_ip=None)
    assert "server_ip" not in store.load_state()


def test_lock_is_reentrant(store):
    with store.lock():
        with store.lock():
            store.save_state({"inside": True})
    assert store.load_state() == {"inside": True}


def test_concurrent_updates_do_not_lose_data(store):
    errors: list[BaseException] = []

    def worker(worker_id: int) -> None:
        try:
            for i in range(20):
                store.update_state(**{f"w{worker_id}_{i}": i})
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    state = store.load_state()
    assert len(state) == 60
    assert state["w2_19"] == 19


def test_corrupted_file_raises_store_error(store):
    store.configs_path.parent.mkdir(parents=True, exist_ok=True)
    store.configs_path.write_text("{not json")

    with pytest.raises(StoreError):
        store.load_configs()


def test_wrong_root_type_raises_store_error(store):
    store.configs_path.parent.mkdir(parents=True, exist_ok=True)
    store.configs_path.write_text(json.dumps({"not": "a list"}))

    with pytest.raises(StoreError):
        store.load_configs()
