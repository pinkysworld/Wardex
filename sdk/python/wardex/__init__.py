"""wardex — Python SDK for the Wardex XDR / SIEM platform."""

from wardex.client import (
    CommandCenterLaneResponse,
    CommandCenterSummaryResponse,
    WardexClient,
)
from wardex.exceptions import (
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    WardexError,
)

__version__ = "1.0.30"
__all__ = [
    "AuthenticationError",
    "CommandCenterLaneResponse",
    "CommandCenterSummaryResponse",
    "NotFoundError",
    "RateLimitError",
    "ServerError",
    "WardexClient",
    "WardexError",
]
