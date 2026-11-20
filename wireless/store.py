"""
Persistent state storage for WireLess.

All state lives under ``/etc/wireless`` (root, ``0700``).  Writes are atomic
(temp file + ``os.replace``) and guarded by an advisory ``flock`` so the CLI
and the web UI can run at the same time without corrupting each other's data.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any, Iterator, Optional

from wireless import config as cfg

FILE_MODE = 0o600
DIR_MODE = 0o700


class StoreError(RuntimeError):
    """Raised when a state file exists but cannot be read or parsed."""


# ── Low-level helpers ────────────────────────────────────────────────────────

def _ensure_dir(path: Path) -> None:
    """Create *path* (and parents) with ``0700`` when it does not exist yet."""
    if path.is_dir():
        return
    path.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(path, DIR_MODE)


def _read_json(path: Path, default: Any) -> Any:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return default
    if not raw.strip():
        return default
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise StoreError(f"Corrupted state file {path}: {exc}") from exc


def _atomic_write_json(path: Path, data: Any, mode: int = FILE_MODE) -> None:
    """Write *data* as JSON to *path* atomically with the given file mode."""
    _ensure_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise
    # Persist the rename itself.  Not every filesystem supports fsync on a
    # directory, so failures here are harmless.
    with contextlib.suppress(OSError):
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


# ── Store ────────────────────────────────────────────────────────────────────

class Store:
    """Reads and writes the JSON state files used by WireLess.

    Paths default to the values from :mod:`wireless.config` at construction
    time, which keeps tests free to point the store at a temporary directory.
    """

    def __init__(
        self,
        configs_path: Optional[str] = None,
        state_path: Optional[str] = None,
        subscriptions_path: Optional[str] = None,
        lock_path: Optional[str] = None,
    ):
        self.configs_path = Path(configs_path or cfg.CONFIGS_FILE)
        self.state_path = Path(state_path or cfg.STATE_FILE)
        self.subscriptions_path = Path(subscriptions_path or cfg.SUBSCRIPTIONS_FILE)
        self.lock_path = Path(lock_path or cfg.LOCK_FILE)

        self._thread_lock = threading.RLock()
        self._lock_fd: Optional[int] = None
        self._lock_depth = 0

    # ── Locking ──────────────────────────────────────────────────────────────

    def ensure_dirs(self) -> None:
        """Create the directories that hold the state files."""
        for path in (self.configs_path, self.state_path, self.subscriptions_path):
            _ensure_dir(path.parent)

    @contextlib.contextmanager
    def lock(self) -> Iterator[None]:
        """Hold the exclusive state lock (re-entrant within one thread)."""
        with self._thread_lock:
            if self._lock_depth == 0:
                _ensure_dir(self.lock_path.parent)
                fd = os.open(
                    str(self.lock_path), os.O_CREAT | os.O_RDWR, FILE_MODE
                )
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                except BaseException:
                    os.close(fd)
                    raise
                self._lock_fd = fd
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
                if self._lock_depth == 0 and self._lock_fd is not None:
                    fd, self._lock_fd = self._lock_fd, None
                    with contextlib.suppress(OSError):
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    with contextlib.suppress(OSError):
                        os.close(fd)

    # ── Proxy configs ────────────────────────────────────────────────────────

    def load_configs(self) -> list[dict]:
        """Return the saved proxy configs (empty list when the file is absent)."""
        data = _read_json(self.configs_path, [])
        if not isinstance(data, list):
            raise StoreError(
                f"Corrupted state file {self.configs_path}: expected a list"
            )
        return data

    def save_configs(self, configs: list[dict]) -> None:
        """Atomically replace the saved proxy configs."""
        _atomic_write_json(self.configs_path, configs)

    # ── State ────────────────────────────────────────────────────────────────

    def load_state(self) -> dict:
        """Return the gateway state (empty dict when the file is absent)."""
        data = _read_json(self.state_path, {})
        if not isinstance(data, dict):
            raise StoreError(
                f"Corrupted state file {self.state_path}: expected an object"
            )
        return data

    def save_state(self, state: dict) -> None:
        """Atomically replace the gateway state."""
        _atomic_write_json(self.state_path, state)

    def update_state(self, **changes: Any) -> dict:
        """Merge *changes* into the state under the lock and return the result.

        Keys whose value is ``None`` are removed from the state.
        """
        with self.lock():
            state = self.load_state()
            for key, value in changes.items():
                if value is None:
                    state.pop(key, None)
                else:
                    state[key] = value
            self.save_state(state)
            return state

    # ── Subscriptions ────────────────────────────────────────────────────────

    def load_subscriptions(self) -> list[dict]:
        """Return saved subscriptions (empty list when the file is absent)."""
        data = _read_json(self.subscriptions_path, [])
        if not isinstance(data, list):
            raise StoreError(
                f"Corrupted state file {self.subscriptions_path}: expected a list"
            )
        return data

    def save_subscriptions(self, subscriptions: list[dict]) -> None:
        """Atomically replace the saved subscriptions."""
        _atomic_write_json(self.subscriptions_path, subscriptions)
