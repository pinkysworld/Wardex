"""wardex — Python SDK for the Wardex XDR / SIEM platform."""

from wardex.client import WardexClient
from wardex.exceptions import (
    WardexError,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ServerError,
)

__version__ = "0.53.1"
__all__ = [
    "WardexClient",
    "WardexError",
    "AuthenticationError",
    "NotFoundError",
    "RateLimitError",
    "ServerError",
]
