"""Custom exception hierarchy for the Wardex SDK."""


class WardexError(Exception):
    """Base exception for all Wardex SDK errors."""

    def __init__(self, message: str, status_code: int | None = None, body: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class AuthenticationError(WardexError):
    """Raised on 401 / 403 responses."""


class NotFoundError(WardexError):
    """Raised on 404 responses."""


class RateLimitError(WardexError):
    """Raised on 429 responses."""


class ServerError(WardexError):
    """Raised on 5xx responses."""
