"""Tests for password hashing, session cookies and login throttling."""
import json
import stat

import pytest

from wireless.store import FILE_MODE
from wireless.web.auth import (
    LoginRateLimiter,
    WebAuth,
    hash_password,
    verify_password,
)


# ── Passwords ────────────────────────────────────────────────────────────────

def test_password_hash_roundtrip():
    encoded = hash_password("correct-horse")

    assert encoded.startswith("scrypt$")
    assert verify_password("correct-horse", encoded) is True
    assert verify_password("wrong-horse", encoded) is False


def test_password_hashes_are_salted():
    assert hash_password("same-password") != hash_password("same-password")


@pytest.mark.parametrize("broken", ["", "plain", "scrypt$1$2$3", "bcrypt$1$2$3$4$5"])
def test_verify_rejects_malformed_hash(broken):
    assert verify_password("anything", broken) is False


# ── WebAuth ──────────────────────────────────────────────────────────────────

@pytest.fixture
def auth(tmp_path):
    return WebAuth(path=str(tmp_path / "web.json"))


def test_password_is_persisted_with_private_permissions(auth):
    auth.set_password("correct-horse")

    assert auth.is_configured() is True
    assert auth.check_password("correct-horse") is True
    assert auth.check_password("nope") is False
    assert stat.S_IMODE(auth.path.stat().st_mode) == FILE_MODE
    assert "correct-horse" not in auth.path.read_text(encoding="utf-8")


def test_set_password_rejects_short_passwords(auth):
    with pytest.raises(ValueError, match="at least 8"):
        auth.set_password("short")


def test_ensure_configured_generates_password_once(auth):
    generated = auth.ensure_configured()

    assert generated
    assert auth.check_password(generated) is True
    assert auth.ensure_configured() is None


def test_ensure_configured_keeps_existing_password(auth):
    auth.set_password("correct-horse")

    assert auth.ensure_configured() is None
    assert auth.check_password("correct-horse") is True


def test_session_roundtrip(auth):
    auth.set_password("correct-horse")

    token, session = auth.issue_session(now=1000)

    restored = auth.verify_session(token, now=1001)
    assert restored == session
    assert restored.csrf


def test_session_rejects_tampering(auth):
    auth.set_password("correct-horse")
    token, _ = auth.issue_session(now=1000)
    body, signature = token.rsplit(".", 1)

    assert auth.verify_session(f"{body}.{signature[:-2]}AA", now=1001) is None
    assert auth.verify_session("not-a-token", now=1001) is None
    assert auth.verify_session(None, now=1001) is None


def test_session_expires(auth):
    auth.set_password("correct-horse")
    token, _ = auth.issue_session(now=1000)

    assert auth.verify_session(token, now=1000 + auth.session_ttl) is not None
    assert auth.verify_session(token, now=1000 + auth.session_ttl + 1) is None


def test_session_from_the_future_is_rejected(auth):
    auth.set_password("correct-horse")
    token, _ = auth.issue_session(now=2000)

    assert auth.verify_session(token, now=1000) is None


def test_secret_is_generated_and_stable(auth):
    auth.set_password("correct-horse")

    first = auth.secret
    assert first == auth.secret
    data = json.loads(auth.path.read_text(encoding="utf-8"))
    assert data["secret"] == first


# ── Rate limiter ─────────────────────────────────────────────────────────────

def test_rate_limiter_blocks_after_max_attempts():
    limiter = LoginRateLimiter(max_attempts=3, window=60)

    for _ in range(3):
        assert limiter.allow("1.2.3.4", now=100) is True
        limiter.failure("1.2.3.4", now=100)

    assert limiter.allow("1.2.3.4", now=101) is False
    assert limiter.allow("5.6.7.8", now=101) is True


def test_rate_limiter_window_slides():
    limiter = LoginRateLimiter(max_attempts=2, window=60)

    limiter.failure("ip", now=0)
    limiter.failure("ip", now=10)

    assert limiter.allow("ip", now=30) is False
    assert limiter.allow("ip", now=61) is True


def test_rate_limiter_resets_after_success():
    limiter = LoginRateLimiter(max_attempts=1, window=60)

    limiter.failure("ip", now=0)
    limiter.success("ip")

    assert limiter.allow("ip", now=1) is True
