"""
Auto proxy URL parser — determines type by scheme and delegates to the
appropriate concrete parser.
"""
import logging
from urllib.parse import urlparse

from wireless.models import ProxyConfig
from wireless.parsers.vless    import VlessParser
from wireless.parsers.vmess    import VmessParser
from wireless.parsers.trojan   import TrojanParser
from wireless.parsers.hysteria2 import Hysteria2Parser

logger = logging.getLogger(__name__)

# Map URL scheme → parser class
_PARSERS = {
    "vless":     VlessParser,
    "vmess":     VmessParser,
    "trojan":    TrojanParser,
    "hysteria2": Hysteria2Parser,
    "hy2":       Hysteria2Parser,
}


def parse_proxy_url(url: str) -> ProxyConfig:
    """Parse any supported proxy URL and return the appropriate ProxyConfig.

    Supported schemes: vless, vmess, trojan, hysteria2, hy2

    Args:
        url: Raw proxy URL string.

    Returns:
        A ProxyConfig subclass instance.

    Raises:
        ValueError: If the scheme is unsupported or the URL is malformed.
    """
    url = url.strip()
    if not url:
        raise ValueError("Empty proxy URL")

    scheme = urlparse(url).scheme.lower()
    if scheme not in _PARSERS:
        raise ValueError(
            f"Unsupported proxy scheme: {scheme!r}. "
            f"Supported: {', '.join(sorted(_PARSERS))}"
        )

    parser_cls = _PARSERS[scheme]
    logger.debug("Dispatching %r URL to %s", scheme, parser_cls.__name__)
    return parser_cls().parse(url)


def supported_schemes() -> list:
    """Return the list of supported proxy URL schemes."""
    return sorted(set(_PARSERS.keys()))
