"""Tests for the web UI: authentication, pages, status API and bind policy."""
import pytest
from fastapi.testclient import TestClient

from wireless.web.app import create_app
from wireless.web.auth import LoginRateLimiter, WebAuth
from wireless.web.bind import check_bind

PASSWORD = "correct-horse"


@pytest.fixture
def auth(tmp_path):
    auth = WebAuth(path=str(tmp_path / "web.json"))
    auth.set_password(PASSWORD)
    return auth


@pytest.fixture
def client(service, auth):
    app = create_app(
        service=service,
        auth=auth,
        auth_enabled=True,
        limiter=LoginRateLimiter(max_attempts=5, window=60),
    )
    return TestClient(app)


@pytest.fixture
def open_client(service, auth):
    app = create_app(service=service, auth=auth, auth_enabled=False)
    return TestClient(app)


def login(client, password=PASSWORD):
    return client.post("/api/login", json={"password": password})


# ── Public endpoints ─────────────────────────────────────────────────────────

def test_health_is_public_and_secret_free(client):
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_status_requires_authentication(client):
    assert client.get("/api/status").status_code == 401


def test_login_page_is_public(client):
    response = client.get("/login")

    assert response.status_code == 200
    assert "WireLess" in response.text


def test_dashboard_redirects_to_login(client):
    response = client.get("/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


# ── Login / logout ───────────────────────────────────────────────────────────

def test_login_sets_secure_cookie_and_returns_csrf(client):
    response = login(client)

    assert response.status_code == 200
    assert response.json()["csrf"]
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "wireless_session=" in cookie


def test_login_with_wrong_password(client):
    response = login(client, "wrong-horse")

    assert response.status_code == 401
    assert "set-cookie" not in response.headers


def test_login_is_rate_limited(client):
    for _ in range(5):
        assert login(client, "wrong-horse").status_code == 401

    response = login(client, PASSWORD)

    assert response.status_code == 429


def test_status_after_login(client, service):
    service.add_proxy(
        "vless://11111111-1111-1111-1111-111111111111@example.com:443"
        "?security=tls&sni=example.com#TestNode"
    )
    service.activate("TestNode")

    assert login(client).status_code == 200
    response = client.get("/api/status")

    assert response.status_code == 200
    body = response.json()
    assert body["active"] == "TestNode"
    assert body["configs_count"] == 1
    assert body["running"] is False


def test_dashboard_after_login(client):
    assert login(client).status_code == 200

    response = client.get("/")

    assert response.status_code == 200
    assert "csrf-token" in response.text


def test_logout_requires_csrf(client):
    csrf = login(client).json()["csrf"]

    assert client.post("/api/logout").status_code == 403

    response = client.post("/api/logout", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    assert client.get("/api/status").status_code == 401


def test_cross_origin_login_is_rejected(client):
    response = client.post(
        "/api/login",
        json={"password": PASSWORD},
        headers={"Origin": "http://evil.example"},
    )

    assert response.status_code == 403


def test_same_origin_login_is_allowed(client):
    response = client.post(
        "/api/login",
        json={"password": PASSWORD},
        headers={"Origin": "http://testserver"},
    )

    assert response.status_code == 200


# ── Security headers ────────────────────────────────────────────────────────

def test_security_headers_are_set(client):
    response = client.get("/login")

    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"


def test_static_assets_are_served(client):
    for path in ("/static/app.css", "/static/app.js"):
        response = client.get(path)
        assert response.status_code == 200


# ── --no-auth mode ──────────────────────────────────────────────────────────

def test_no_auth_mode_opens_dashboard(open_client):
    assert open_client.get("/api/status").status_code == 200
    assert open_client.get("/").status_code == 200
    assert open_client.get("/login", follow_redirects=False).status_code == 303


# ── Bind policy ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_loopback_binds_need_no_password(host):
    assert check_bind(host, no_auth=True, configured=False) is None


def test_non_loopback_bind_requires_password():
    assert check_bind("0.0.0.0", no_auth=False, configured=False)
    assert check_bind("0.0.0.0", no_auth=True, configured=True)
    assert check_bind("0.0.0.0", no_auth=False, configured=True) is None


def test_unknown_host_is_not_loopback():
    assert check_bind("example.com", no_auth=False, configured=False)


# ── Proxies ──────────────────────────────────────────────────────────────────

from conftest import VLESS_URL
from wireless.services import MASK


def csrf_headers(client):
    return {"X-CSRF-Token": login(client).json()["csrf"]}


def add_proxy(client, url=VLESS_URL, name=""):
    return client.post(
        "/api/proxies",
        json={"url": url, "name": name},
        headers=csrf_headers(client),
    )


def test_proxies_requires_authentication(client):
    assert client.get("/api/proxies").status_code == 401


def test_add_and_list_proxies(client):
    response = add_proxy(client)

    assert response.status_code == 200
    assert response.json()["name"] == "TestNode"

    listing = client.get("/api/proxies").json()
    assert listing["active"] is None
    assert len(listing["configs"]) == 1
    assert listing["configs"][0]["uuid"] == MASK
    assert listing["configs"][0]["_type"] == "vless"
    assert "_url" not in listing["configs"][0]
    assert "11111111" not in str(listing)


def test_add_proxy_with_custom_name(client):
    response = add_proxy(client, name="Custom")

    assert response.json()["name"] == "Custom"


def test_add_duplicate_proxy_returns_409(client):
    add_proxy(client)

    assert add_proxy(client).status_code == 409


def test_add_broken_proxy_returns_400(client):
    assert add_proxy(client, url="http://example.com").status_code == 400


def test_parse_proxy_preview(client):
    response = client.post(
        "/api/proxies/parse",
        json={"url": VLESS_URL},
        headers=csrf_headers(client),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["server"] == "example.com"
    assert body["port"] == 443
    assert body["uuid"].startswith("11111111")
    assert client.get("/api/proxies").json()["configs"] == []


def test_activate_and_delete_proxy(client):
    add_proxy(client)

    activated = client.post(
        "/api/proxies/activate",
        json={"name": "TestNode"},
        headers=csrf_headers(client),
    )
    assert activated.status_code == 200
    assert activated.json()["active"] == "TestNode"
    assert client.get("/api/proxies").json()["active"] == "TestNode"

    deleted = client.delete(
        "/api/proxies",
        params={"name": "TestNode"},
        headers=csrf_headers(client),
    )
    assert deleted.status_code == 200
    assert client.get("/api/proxies").json()["configs"] == []


def test_activate_unknown_proxy_returns_404(client):
    response = client.post(
        "/api/proxies/activate",
        json={"name": "ghost"},
        headers=csrf_headers(client),
    )

    assert response.status_code == 404


def test_delete_unknown_proxy_returns_404(client):
    response = client.delete(
        "/api/proxies",
        params={"name": "ghost"},
        headers=csrf_headers(client),
    )

    assert response.status_code == 404


def test_proxy_mutations_require_csrf(client):
    login(client)

    assert client.post("/api/proxies", json={"url": VLESS_URL}).status_code == 403
    assert client.post("/api/proxies/activate", json={"name": "x"}).status_code == 403
    assert client.delete("/api/proxies", params={"name": "x"}).status_code == 403


def test_proxies_page(client):
    assert client.get("/proxies", follow_redirects=False).status_code == 303

    login(client)
    response = client.get("/proxies")

    assert response.status_code == 200
    assert "add-form" in response.text


# ── Gateway ──────────────────────────────────────────────────────────────────

def test_gateway_start_requires_active_config(client):
    response = client.post(
        "/api/gateway/start",
        json={},
        headers=csrf_headers(client),
    )

    assert response.status_code == 409


def test_gateway_start_and_stop(client, fakes):
    add_proxy(client)
    client.post(
        "/api/proxies/activate",
        json={"name": "TestNode"},
        headers=csrf_headers(client),
    )

    started = client.post(
        "/api/gateway/start",
        json={"server_ip": "1.2.3.4"},
        headers=csrf_headers(client),
    )

    assert started.status_code == 200
    body = started.json()
    assert body["result"]["singbox"] == "started"
    assert body["status"]["running"] is True
    assert body["status"]["server_ip"] == "1.2.3.4"
    assert fakes.singbox.running and fakes.wireguard.running and fakes.routing.active

    stopped = client.post(
        "/api/gateway/stop",
        json={},
        headers=csrf_headers(client),
    )

    assert stopped.status_code == 200
    assert stopped.json()["status"]["running"] is False
    assert not fakes.singbox.running


def test_gateway_restart_keeps_server_ip(client, fakes):
    add_proxy(client)
    client.post(
        "/api/proxies/activate",
        json={"name": "TestNode"},
        headers=csrf_headers(client),
    )
    client.post(
        "/api/gateway/start",
        json={"server_ip": "5.6.7.8"},
        headers=csrf_headers(client),
    )

    response = client.post(
        "/api/gateway/restart",
        json={},
        headers=csrf_headers(client),
    )

    assert response.status_code == 200
    assert response.json()["status"]["server_ip"] == "5.6.7.8"
    assert fakes.singbox.running


def test_gateway_unknown_action_returns_404(client):
    response = client.post(
        "/api/gateway/bogus",
        json={},
        headers=csrf_headers(client),
    )

    assert response.status_code == 404


def test_gateway_environment_error_returns_500(client, fakes):
    add_proxy(client)
    client.post(
        "/api/proxies/activate",
        json={"name": "TestNode"},
        headers=csrf_headers(client),
    )
    fakes.singbox.fail_on_start = "sing-box exploded"

    response = client.post(
        "/api/gateway/start",
        json={"server_ip": "1.2.3.4"},
        headers=csrf_headers(client),
    )

    assert response.status_code == 500
    assert "sing-box exploded" in response.json()["detail"]
