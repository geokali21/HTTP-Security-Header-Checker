"""Guards against redirects that lead to internal/private network targets (SSRF-style).

A host is treated as *internal* when it is a local-only name, or when any address
it resolves to is not globally routable (loopback, RFC 1918 private, link-local,
CGNAT 100.64/10, unspecified, reserved, multicast, ...). IPv4-mapped IPv6
addresses are unwrapped before checking. Resolution failures are reported to the
caller, which blocks redirect targets it cannot classify (fail closed).
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Callable, List

INTERNAL_SUFFIXES = (".localhost", ".local", ".internal", ".localdomain", ".home.arpa")

Resolver = Callable[[str], List[str]]


class ResolutionError(Exception):
    """The hostname could not be resolved to any address."""


def is_blocked_address(address: str) -> bool:
    """True if `address` is not a globally routable unicast address."""
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (not ip.is_global) or ip.is_multicast


def resolve_host(hostname: str) -> List[str]:
    """Resolve a hostname with the system resolver (also handles 2130706433-style forms)."""
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError) as exc:
        raise ResolutionError(f"Could not resolve {hostname!r}") from exc
    return sorted({info[4][0] for info in infos})


def host_is_internal(hostname: str, resolver: Resolver = resolve_host) -> bool:
    """Classify a hostname as internal (True) or public (False).

    Raises ResolutionError if the name cannot be resolved.
    """
    host = hostname.strip("[]").rstrip(".").lower()
    if not host:
        raise ResolutionError("Empty hostname")
    if host == "localhost" or host.endswith(INTERNAL_SUFFIXES):
        return True
    try:
        return is_blocked_address(host)  # literal IP address
    except ValueError:
        pass
    addresses = resolver(host)
    if not addresses:
        raise ResolutionError(f"No addresses for {host!r}")
    return any(is_blocked_address(a) for a in addresses)
