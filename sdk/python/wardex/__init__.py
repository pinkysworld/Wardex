"""wardex — Python SDK for the Wardex XDR / SIEM platform."""

from wardex.client import (
    CommandCenterLaneResponse,
    CommandCenterSummaryResponse,
    WardexClient,
)
from wardex.exceptions import (
    WardexError,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ServerError,
)

__version__ = "0.55.1"
__all__ = [
    "CommandCenterLaneResponse",
    "CommandCenterSummaryResponse",
    "WardexClient",
    "WardexError",
    "AuthenticationError",
    "NotFoundError",
    "RateLimitError",
    "ServerError",
]
