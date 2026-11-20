"""
Routing manager — sets up/tears down iptables TPROXY rules
so that traffic arriving on the WireGuard interface is transparently
forwarded through the sing-box tproxy inbound.
"""
import logging
import subprocess
from typing import List

from wireless import config as cfg

logger = logging.getLogger(__name__)


def _run(args: List[str], check: bool = True) -> subprocess.CompletedProcess:
    logger.debug("routing: %s", " ".join(args))
    return subprocess.run(args, capture_output=True, text=True, check=check)


class RoutingManager:
    """Manages iptables TPROXY routing rules for WireLess."""

    def __init__(
        self,
        wg_interface: str = cfg.WG_INTERFACE,
        tproxy_port: int = cfg.SINGBOX_TPROXY_PORT,
        fwmark: int = cfg.FWMARK,
        route_table: int = cfg.ROUTE_TABLE,
        private_ranges: List[str] = None,
    ):
        self.wg_interface   = wg_interface
        self.tproxy_port    = tproxy_port
        self.fwmark         = fwmark
        self.route_table    = route_table
        self.private_ranges = private_ranges or cfg.PRIVATE_RANGES

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _ip_rule_exists(self) -> bool:
        result = _run(["ip", "rule", "show"], check=False)
        return f"fwmark 0x{self.fwmark:x}" in result.stdout or \
               f"fwmark {self.fwmark}" in result.stdout

    def _chain_exists(self) -> bool:
        result = _run(
            ["iptables", "-t", "mangle", "-L", "WIRELESS_PROXY", "-n"],
            check=False,
        )
        return result.returncode == 0

    # ── Public API ────────────────────────────────────────────────────────────

    def setup(
        self,
        wg_interface: str = None,
        tproxy_port: int = None,
    ) -> None:
        """Configure TPROXY routing for traffic arriving on the WG interface.

        Steps:
            1. Enable IP forwarding
            2. Add policy route: fwmark → table 100 → lo
            3. Create WIRELESS_PROXY mangle chain
            4. Bypass RFC-1918 / loopback ranges
            5. TPROXY TCP + UDP → sing-box tproxy inbound
            6. Jump PREROUTING → WIRELESS_PROXY for wg interface

        Args:
            wg_interface: Override WireGuard interface name.
            tproxy_port:  Override tproxy listen port.

        Raises:
            RuntimeError: On iptables / ip command failure.
        """
        iface = wg_interface or self.wg_interface
        port  = tproxy_port  or self.tproxy_port

        logger.info(
            "Setting up routing: %s → tproxy port %d", iface, port
        )

        # 1. IP forwarding
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as fh:
                fh.write("1")
        except OSError as exc:
            logger.warning("Could not set ip_forward: %s", exc)

        # 2. Policy routing
        if not self._ip_rule_exists():
            _run(["ip", "rule", "add",
                  "fwmark", str(self.fwmark),
                  "table", str(self.route_table)])
        _run(["ip", "route", "add",
              "local", "0.0.0.0/0",
              "dev", "lo",
              "table", str(self.route_table)],
             check=False)  # may already exist

        # 3. Create chain (idempotent)
        if not self._chain_exists():
            _run(["iptables", "-t", "mangle", "-N", "WIRELESS_PROXY"])

        # 4. Bypass private ranges
        for cidr in self.private_ranges:
            _run([
                "iptables", "-t", "mangle",
                "-C", "WIRELESS_PROXY",
                "-d", cidr, "-j", "RETURN",
            ], check=False)
            result = _run([
                "iptables", "-t", "mangle",
                "-C", "WIRELESS_PROXY",
                "-d", cidr, "-j", "RETURN",
            ], check=False)
            if result.returncode != 0:
                _run([
                    "iptables", "-t", "mangle",
                    "-A", "WIRELESS_PROXY",
                    "-d", cidr, "-j", "RETURN",
                ])

        # 5. TPROXY rules
        for proto in ("tcp", "udp"):
            check_result = _run([
                "iptables", "-t", "mangle",
                "-C", "WIRELESS_PROXY",
                "-p", proto,
                "-j", "TPROXY",
                "--on-port", str(port),
                "--tproxy-mark", str(self.fwmark),
            ], check=False)
            if check_result.returncode != 0:
                _run([
                    "iptables", "-t", "mangle",
                    "-A", "WIRELESS_PROXY",
                    "-p", proto,
                    "-j", "TPROXY",
                    "--on-port", str(port),
                    "--tproxy-mark", str(self.fwmark),
                ])

        # 6. PREROUTING jump
        check_prerouting = _run([
            "iptables", "-t", "mangle",
            "-C", "PREROUTING",
            "-i", iface,
            "-j", "WIRELESS_PROXY",
        ], check=False)
        if check_prerouting.returncode != 0:
            _run([
                "iptables", "-t", "mangle",
                "-A", "PREROUTING",
                "-i", iface,
                "-j", "WIRELESS_PROXY",
            ])

        logger.info("Routing setup complete")

    def teardown(self, wg_interface: str = None) -> None:
        """Remove TPROXY routing rules.

        Args:
            wg_interface: Override WireGuard interface name.
        """
        iface = wg_interface or self.wg_interface
        logger.info("Tearing down routing for %s", iface)

        _run([
            "iptables", "-t", "mangle",
            "-D", "PREROUTING",
            "-i", iface,
            "-j", "WIRELESS_PROXY",
        ], check=False)

        _run(["iptables", "-t", "mangle", "-F", "WIRELESS_PROXY"], check=False)
        _run(["iptables", "-t", "mangle", "-X", "WIRELESS_PROXY"], check=False)

        _run([
            "ip", "route", "del",
            "local", "0.0.0.0/0",
            "dev", "lo",
            "table", str(self.route_table),
        ], check=False)

        _run([
            "ip", "rule", "del",
            "fwmark", str(self.fwmark),
            "table", str(self.route_table),
        ], check=False)

        logger.info("Routing teardown complete")

    def is_active(self) -> bool:
        """Return True if WIRELESS_PROXY chain exists and is linked to PREROUTING."""
        if not self._chain_exists():
            return False
        result = _run([
            "iptables", "-t", "mangle",
            "-C", "PREROUTING",
            "-i", self.wg_interface,
            "-j", "WIRELESS_PROXY",
        ], check=False)
        return result.returncode == 0
