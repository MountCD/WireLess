"""
VMess proxy URL parser.

Format:
  vmess://<base64(JSON)>

The JSON object contains fields like:
  v, ps, add, port, id, aid, scy, net, type, host, path, tls, sni, ...
"""
import base64
import json
import logging
from urllib.parse import urlparse

from wireless.parsers.base import BaseParser
from wireless.models import VmessConfig

logger = logging.getLogger(__name__)


class VmessParser(BaseParser):
    """Parser for vmess:// proxy URLs."""

    def parse(self, url: str) -> VmessConfig:
        """Parse a vmess:// URL into a VmessConfig.

        Args:
            url: Raw vmess:// URL string (base64-encoded JSON payload).

        Returns:
            Populated VmessConfig instance.

        Raises:
            ValueError: On malformed or incomplete URL.
        """
        url = url.strip()
        if not url.startswith("vmess://"):
            raise ValueError(f"Not a VMess URL: {url[:30]!r}")

        b64_payload = url[len("vmess://"):]

        # VMess base64 may be missing padding
        padding = 4 - len(b64_payload) % 4
        if padding != 4:
            b64_payload += "=" * padding

        try:
            decoded = base64.b64decode(b64_payload).decode("utf-8")
        except Exception as exc:
            raise ValueError(f"Failed to decode VMess base64 payload: {exc}") from exc

        try:
            data = json.loads(decoded)
        except json.JSONDecodeError as exc:
            raise ValueError(f"VMess JSON parse error: {exc}") from exc

        host = data.get("add") or data.get("host") or ""
        self._require(host, "server host (add)")

        try:
            port = int(data.get("port", 0))
        except (TypeError, ValueError):
            port = 0
        if not port:
            raise ValueError("Missing or invalid port in VMess config")

        uuid = data.get("id") or ""
        self._require(uuid, "uuid (id)")

        name    = data.get("ps") or data.get("remarks") or ""
        alter_id = int(data.get("aid", 0))
        cipher  = data.get("scy") or data.get("security") or "auto"
        network = data.get("net") or data.get("type") or "tcp"
        path    = data.get("path") or ""
        ws_host = data.get("host") or ""
        tls     = str(data.get("tls", "")).lower() in ("tls", "true", "1")
        sni     = data.get("sni") or data.get("servername") or ""

        logger.debug(
            "Parsed VMess: host=%s port=%d network=%s tls=%s",
            host, port, network, tls,
        )

        return VmessConfig(
            type="vmess",
            server=host,
            port=port,
            uuid=uuid,
            name=name,
            alter_id=alter_id,
            cipher=cipher,
            network=network,
            path=path,
            host=ws_host,
            tls=tls,
            sni=sni,
        )
