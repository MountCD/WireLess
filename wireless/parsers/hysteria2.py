"""
Hysteria2 proxy URL parser.

Formats:
  hysteria2://<auth>@<host>:<port>?obfs=salamander&obfs-password=...&sni=...&insecure=1#name
  hy2://<auth>@<host>:<port>?...#name   (alias)
"""
import logging
from urllib.parse import urlparse, parse_qs, unquote

from wireless.parsers.base import BaseParser
from wireless.models import Hysteria2Config

logger = logging.getLogger(__name__)


class Hysteria2Parser(BaseParser):
    """Parser for hysteria2:// (and hy2://) proxy URLs."""

    def parse(self, url: str) -> Hysteria2Config:
        """Parse a hysteria2:// URL into a Hysteria2Config.

        Args:
            url: Raw hysteria2:// or hy2:// URL string.

        Returns:
            Populated Hysteria2Config instance.

        Raises:
            ValueError: On malformed or incomplete URL.
        """
        url = url.strip()
        if not (url.startswith("hysteria2://") or url.startswith("hy2://")):
            raise ValueError(f"Not a Hysteria2 URL: {url[:30]!r}")

        parsed = urlparse(url)

        auth = unquote(parsed.username or "")
        # auth may also be in the password field for some clients
        if not auth:
            auth = unquote(parsed.password or "")

        host = parsed.hostname or ""
        self._require(host, "server host")

        port = parsed.port
        if port is None:
            raise ValueError("Missing port in Hysteria2 URL")

        name = unquote(parsed.fragment or "")

        qs = parse_qs(parsed.query, keep_blank_values=True)

        def _q(key: str, default: str = "") -> str:
            vals = qs.get(key)
            return unquote(vals[0]) if vals else default

        obfs          = _q("obfs")
        obfs_password = _q("obfs-password")
        sni           = _q("sni")
        insecure_raw  = _q("insecure", "0")
        insecure      = insecure_raw.strip() in ("1", "true", "yes")

        logger.debug(
            "Parsed Hysteria2: host=%s port=%d obfs=%s sni=%s insecure=%s",
            host, port, obfs, sni, insecure,
        )

        return Hysteria2Config(
            type="hysteria2",
            server=host,
            port=port,
            auth=auth,
            name=name,
            obfs=obfs,
            obfs_password=obfs_password,
            sni=sni,
            insecure=insecure,
        )
