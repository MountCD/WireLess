"""
sing-box process manager.

Writes config, starts/stops sing-box as a subprocess, tracks PID.
"""
import json
import logging
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Optional

from wireless import config as cfg

logger = logging.getLogger(__name__)


class SingBoxManager:
    """Manages the sing-box proxy process."""

    def __init__(
        self,
        binary:      str = cfg.SINGBOX_BINARY,
        config_path: str = cfg.SINGBOX_CONFIG_PATH,
        pid_file:    str = cfg.SINGBOX_PID_FILE,
        log_file:    str = cfg.SINGBOX_LOG_FILE,
    ):
        self.binary      = binary
        self.config_path = Path(config_path)
        self.pid_file    = Path(pid_file)
        self.log_file    = Path(log_file)
        self._process: Optional[subprocess.Popen] = None

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _ensure_dirs(self) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.pid_file.parent.mkdir(parents=True, exist_ok=True)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def _write_config(self, config: dict) -> None:
        self.config_path.write_text(
            json.dumps(config, indent=2, ensure_ascii=False)
        )
        logger.debug("Wrote sing-box config to %s", self.config_path)

    def _read_pid(self) -> Optional[int]:
        if not self.pid_file.exists():
            return None
        try:
            return int(self.pid_file.read_text().strip())
        except (ValueError, OSError):
            return None

    def _write_pid(self, pid: int) -> None:
        self.pid_file.write_text(str(pid))

    def _remove_pid(self) -> None:
        try:
            self.pid_file.unlink()
        except FileNotFoundError:
            pass

    def _pid_alive(self, pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            return False

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self, config: dict) -> None:
        """Write config and start sing-box in the background.

        Args:
            config: sing-box config dict (from generators.singbox).

        Raises:
            RuntimeError: If sing-box binary not found or already running.
        """
        if self.is_running():
            raise RuntimeError("sing-box is already running")

        if not (os.path.isfile(self.binary) and os.access(self.binary, os.X_OK)):
            raise RuntimeError(
                f"sing-box binary not found or not executable at {self.binary!r}. "
                f"Install sing-box >= {cfg.MIN_SINGBOX_VERSION} or set "
                "SINGBOX_BINARY=/path/to/sing-box."
            )

        self._ensure_dirs()
        self._write_config(config)

        log_fd = open(self.log_file, "a")
        proc = subprocess.Popen(
            [self.binary, "run", "-c", str(self.config_path)],
            stdout=log_fd,
            stderr=log_fd,
            close_fds=True,
        )
        self._process = proc
        self._write_pid(proc.pid)
        logger.info("sing-box started (pid=%d)", proc.pid)

        # Brief pause to detect immediate crash
        time.sleep(0.5)
        if proc.poll() is not None:
            self._remove_pid()
            raise RuntimeError(
                f"sing-box exited immediately (rc={proc.returncode}). "
                f"Check {self.log_file}"
            )

    def stop(self) -> None:
        """Stop the running sing-box process."""
        pid = self._read_pid()
        if pid is None:
            if self._process is not None and self._process.poll() is None:
                pid = self._process.pid
            else:
                logger.info("sing-box is not running")
                return

        if not self._pid_alive(pid):
            logger.info("sing-box pid %d no longer alive", pid)
            self._remove_pid()
            return

        logger.info("Stopping sing-box (pid=%d)", pid)
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

        # Wait up to 5 s for graceful shutdown
        for _ in range(50):
            if not self._pid_alive(pid):
                break
            time.sleep(0.1)
        else:
            logger.warning("sing-box did not exit, sending SIGKILL")
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        self._remove_pid()
        self._process = None
        logger.info("sing-box stopped")

    def restart(self, config: dict) -> None:
        """Stop and restart sing-box with a new config.

        Args:
            config: New sing-box config dict.
        """
        self.stop()
        self.start(config)

    def is_running(self) -> bool:
        """Return True if sing-box process is alive."""
        # Check tracked Popen object first
        if self._process is not None and self._process.poll() is None:
            return True
        # Fall back to PID file
        pid = self._read_pid()
        if pid is not None and self._pid_alive(pid):
            return True
        return False

    def status(self) -> dict:
        """Return a status dict for sing-box."""
        pid = self._read_pid()
        running = self.is_running()
        return {
            "running": running,
            "pid":     pid if running else None,
            "binary":  self.binary,
            "config":  str(self.config_path),
            "log":     str(self.log_file),
        }
