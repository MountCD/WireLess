"""
Trojan proxy URL parser.

Format:
  trojan://<password>@<host>:<port>?sni=...&type=ws&path=...#name
"""
import logging
from urllib.parse import urlparse, parse_qs, unquote

from wireless.parsers.base import BaseParser
from wireless.models import TrojanConfig

logger = logging.getLogger(__name__)


class TrojanParser(BaseParser):
    """Parser for trojan:// proxy URLs."""

    def parse(self, url: str) -> TrojanConfig:
        """Parse a trojan:// URL into a TrojanConfig.

        Args:
            url: Raw trojan:// URL string.

        Returns:
            Populated TrojanConfig instance.

        Raises:
            ValueError: On malformed or incomplete URL.
        """
        url = url.strip()
        if not url.startswith("trojan://"):
            raise ValueError(f"Not a Trojan URL: {url[:30]!r}")

        parsed = urlparse(url)

        password = unquote(parsed.username or "")
        self._require(password, "password")

        host = parsed.hostname or ""
        self._require(host, "server host")

        port = parsed.port
        if port is None:
            raise ValueError("Missing port in Trojan URL")

        name = unquote(parsed.fragment or "")

        qs = parse_qs(parsed.query, keep_blank_values=True)

        def _q(key: str, default: str = "") -> str:
            vals = qs.get(key)
            return unquote(vals[0]) if vals else default

        sni      = _q("sni")
        network  = _q("type", "tcp")
        path     = _q("path")
        host_hdr = _q("host")
        security = _q("security", "tls")

        logger.debug(
            "Parsed Trojan: host=%s port=%d network=%s sni=%s",
            host, port, network, sni,
        )

        return TrojanConfig(
            type="trojan",
            server=host,
            port=port,
            password=password,
            name=name,
            sni=sni,
            path=path,
            host=host_hdr,
            security=security,
            network=network,
        )
