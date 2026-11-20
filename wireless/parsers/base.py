"""
Base parser class for proxy URL parsers.
"""
from abc import ABC, abstractmethod
from wireless.models import ProxyConfig


class BaseParser(ABC):
    """Abstract base class for proxy URL parsers."""

    @abstractmethod
    def parse(self, url: str) -> ProxyConfig:
        """Parse a proxy URL and return a ProxyConfig instance.

        Args:
            url: The raw proxy URL string.

        Returns:
            A ProxyConfig subclass instance with parsed fields.

        Raises:
            ValueError: If the URL is malformed or missing required fields.
        """
        ...

    @classmethod
    def _require(cls, value: str, field_name: str) -> str:
        """Assert that a required field is non-empty."""
        if not value:
            raise ValueError(f"Missing required field: {field_name}")
        return value
