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
