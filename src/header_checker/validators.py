"""URL validation. Only well-formed http/https URLs without credentials pass."""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https"}


class InvalidURLError(ValueError):
    """Raised when a URL does not meet the tool's input requirements."""


def validate_url(raw: str) -> str:
    """Return the stripped URL if valid, otherwise raise InvalidURLError."""
    if not isinstance(raw, str) or not raw.strip():
        raise InvalidURLError("URL is empty.")
    url = raw.strip()
    if len(url) > MAX_URL_LENGTH:
        raise InvalidURLError(f"URL is longer than {MAX_URL_LENGTH} characters.")
    if any(ch.isspace() or ord(ch) < 32 for ch in url):
        raise InvalidURLError("URL contains whitespace or control characters.")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise InvalidURLError(f"URL could not be parsed: {exc}") from exc
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise InvalidURLError(
            "Only http:// and https:// URLs are accepted (include the scheme)."
        )
    if not parts.hostname:
        raise InvalidURLError("URL has no hostname.")
    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidURLError("URL has an invalid port.") from exc
    if port == 0:
        raise InvalidURLError("URL has an invalid port.")
    if parts.username is not None or parts.password is not None:
        raise InvalidURLError("URLs with embedded credentials are not accepted.")
    return url


def is_loopback_host(hostname: str) -> bool:
    """True for localhost and loopback IP addresses (safe local testing)."""
    host = hostname.strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
