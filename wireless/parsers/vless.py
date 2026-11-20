"""
VLESS proxy URL parser.

Supported formats:
  vless://<uuid>@<host>:<port>?encryption=none&flow=xtls-rprx-vision
         &security=reality&sni=...&fp=...&pbk=...&sid=...&type=tcp#name
  vless://<uuid>@<host>:<port>?security=tls&sni=...&type=ws&path=/ws&host=...#name
"""
import logging
from urllib.parse import urlparse, parse_qs, unquote

from wireless.parsers.base import BaseParser
from wireless.models import VlessConfig

logger = logging.getLogger(__name__)


class VlessParser(BaseParser):
    """Parser for vless:// proxy URLs."""

    def parse(self, url: str) -> VlessConfig:
        """Parse a vless:// URL into a VlessConfig.

        Args:
            url: Raw vless:// URL string.

        Returns:
            Populated VlessConfig instance.

        Raises:
            ValueError: On malformed or incomplete URL.
        """
        url = url.strip()
        if not url.startswith("vless://"):
            raise ValueError(f"Not a VLESS URL: {url[:30]!r}")

        parsed = urlparse(url)

        # UUID is in the username field
        uuid = unquote(parsed.username or "")
        self._require(uuid, "uuid")

        host = parsed.hostname or ""
        self._require(host, "server host")

        port = parsed.port
        if port is None:
            raise ValueError("Missing port in VLESS URL")

        # Fragment is the display name (URL-decoded)
        name = unquote(parsed.fragment or "")

        # Query parameters
        qs = parse_qs(parsed.query, keep_blank_values=True)

        def _q(key: str, default: str = "") -> str:
            vals = qs.get(key)
            return unquote(vals[0]) if vals else default

        security  = _q("security", "none")
        flow      = _q("flow")
        network   = _q("type", "tcp")
        sni       = _q("sni")
        fp        = _q("fp")
        pbk       = _q("pbk")
        sid       = _q("sid")
        path      = _q("path")
        host_hdr  = _q("host")
        encryption = _q("encryption", "none")

        logger.debug(
            "Parsed VLESS: host=%s port=%d security=%s network=%s",
            host, port, security, network,
        )

        return VlessConfig(
            type="vless",
            server=host,
            port=port,
            uuid=uuid,
            name=name,
            flow=flow,
            security=security,
            sni=sni,
            fp=fp,
            pbk=pbk,
            sid=sid,
            path=path,
            host=host_hdr,
            network=network,
            encryption=encryption,
        )
