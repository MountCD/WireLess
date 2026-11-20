"""
Password authentication and signed session cookies for the web UI.

Only the standard library is used: scrypt for password hashing and
HMAC-SHA256 for session tokens, so authentication adds no dependencies.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from wireless import config as cfg
from wireless.store import FILE_MODE, atomic_write_json

SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SESSION_TTL = 12 * 60 * 60


# ── Encoding helpers ─────────────────────────────────────────────────────────

def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ── Passwords ────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Return a self-describing scrypt hash: ``scrypt$n$r$p$salt$hash``."""
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64e(salt)}${_b64e(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    """Check *password* against a hash produced by :func:`hash_password`."""
    try:
        scheme, n, r, p, salt_b64, hash_b64 = encoded.split("$")
        if scheme != "scrypt":
            return False
        expected = _b64d(hash_b64)
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=_b64d(salt_b64),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, expected)


# ── Sessions ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Session:
    issued_at: int
    csrf: str


class WebAuth:
    """Stores the admin password hash and signs session cookies.

    The JSON file is created on demand with ``0600`` permissions and also
    holds the HMAC secret used to sign cookies.
    """

    def __init__(self, path: Optional[str] = None, session_ttl: int = SESSION_TTL):
        self.path = Path(path or cfg.WEB_FILE)
        self.session_ttl = session_ttl
        self._lock = threading.RLock()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load(self) -> dict:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        if not raw.strip():
            return {}
        return json.loads(raw)

    def _save(self, data: dict) -> None:
        atomic_write_json(self.path, data, mode=FILE_MODE)

    # ── Password management ──────────────────────────────────────────────────

    def is_configured(self) -> bool:
        """Return True when an admin password has been set."""
        return bool(self._load().get("password_hash"))

    def set_password(self, password: str) -> None:
        """Hash and store a new admin password.

        Raises:
            ValueError: If the password is shorter than 8 characters.
        """
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        with self._lock:
            data = self._load()
            data["password_hash"] = hash_password(password)
            data.setdefault("secret", secrets.token_hex(32))
            self._save(data)

    def ensure_configured(self) -> Optional[str]:
        """Create a random password on first run and return it once.

        Returns:
            The generated password, or ``None`` if one was already configured.
        """
        with self._lock:
            if self.is_configured():
                return None
            password = secrets.token_urlsafe(12)
            data = self._load()
            data["password_hash"] = hash_password(password)
            data.setdefault("secret", secrets.token_hex(32))
            self._save(data)
            return password

    def check_password(self, password: str) -> bool:
        """Verify *password* against the stored hash."""
        encoded = self._load().get("password_hash", "")
        return bool(encoded) and verify_password(password, encoded)

    # ── Cookie signing ───────────────────────────────────────────────────────

    @property
    def secret(self) -> str:
        data = self._load()
        secret = data.get("secret")
        if not secret:
            secret = secrets.token_hex(32)
            data["secret"] = secret
            self._save(data)
        return secret

    def _sign(self, body: str) -> str:
        digest = hmac.new(
            self.secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256
        ).digest()
        return _b64e(digest)

    def issue_session(self, now: Optional[float] = None) -> tuple[str, Session]:
        """Create a signed session token and the session it represents."""
        issued = int(now if now is not None else time.time())
        session = Session(issued_at=issued, csrf=secrets.token_urlsafe(24))
        payload = json.dumps(
            {"iat": session.issued_at, "csrf": session.csrf},
            separators=(",", ":"),
        ).encode("utf-8")
        body = _b64e(payload)
        return f"{body}.{self._sign(body)}", session

    def verify_session(
        self, token: Optional[str], now: Optional[float] = None
    ) -> Optional[Session]:
        """Return the session for a valid, unexpired token, else ``None``."""
        if not token or "." not in token:
            return None
        body, signature = token.rsplit(".", 1)
        if not hmac.compare_digest(signature, self._sign(body)):
            return None
        try:
            data = json.loads(_b64d(body))
        except (ValueError, TypeError, json.JSONDecodeError):
            return None

        issued_at = int(data.get("iat", 0))
        csrf = str(data.get("csrf", ""))
        current = int(now if now is not None else time.time())
        if not csrf or issued_at > current or current - issued_at > self.session_ttl:
            return None
        return Session(issued_at=issued_at, csrf=csrf)


# ── Login throttling ─────────────────────────────────────────────────────────

class LoginRateLimiter:
    """In-memory fixed-window limiter for login attempts, keyed by client IP."""

    def __init__(self, max_attempts: int = 5, window: float = 60.0):
        self.max_attempts = max_attempts
        self.window = window
        self._attempts: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> list[float]:
        attempts = [t for t in self._attempts.get(key, []) if now - t < self.window]
        self._attempts[key] = attempts
        return attempts

    def allow(self, key: str, now: Optional[float] = None) -> bool:
        """Return True when another attempt is permitted for *key*."""
        current = now if now is not None else time.time()
        with self._lock:
            return len(self._prune(key, current)) < self.max_attempts

    def failure(self, key: str, now: Optional[float] = None) -> None:
        """Record a failed attempt."""
        current = now if now is not None else time.time()
        with self._lock:
            self._prune(key, current).append(current)

    def success(self, key: str) -> None:
        """Clear the failure history after a successful login."""
        with self._lock:
            self._attempts.pop(key, None)
