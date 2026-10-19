"""HTTP fetching with a bounded, manual redirect loop (single GET per hop).

Redirect safety: if the starting target is a public host, a redirect to an
internal/private destination is blocked *before* any request is sent to it.
If the starting target is itself internal (e.g. a local lab or the demo
server), internal redirects are allowed because the user chose that scope.
"""
from __future__ import annotations

import time
from typing import List, Optional
from urllib.parse import urljoin, urlsplit

import requests

from .models import FetchResult
from .netguard import Resolver, ResolutionError, host_is_internal, resolve_host
from .validators import InvalidURLError, validate_url

USER_AGENT = "header-checker/1.0 (+passive security header review)"
REDIRECT_CODES = {301, 302, 303, 307, 308}


class FetchError(Exception):
    """Failure with a short category: timeout, tls, connection, request, redirect, blocked."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def fetch(url: str, timeout: float = 10.0, max_redirects: int = 5,
          session: Optional[requests.Session] = None,
          resolver: Resolver = resolve_host) -> FetchResult:
    """GET `url`, following at most `max_redirects` http(s) redirects."""
    url = validate_url(url)
    sess = session or requests.Session()
    chain: List[str] = [url]
    notes: List[str] = []
    current = url
    start = time.monotonic()

    try:
        initial_internal = host_is_internal(urlsplit(url).hostname or "", resolver)
    except ResolutionError:
        initial_internal = False  # the request itself will report the failure

    for _ in range(max_redirects + 1):
        try:
            resp = sess.get(current, timeout=timeout, allow_redirects=False,
                            stream=True, headers={"User-Agent": USER_AGENT})
        except requests.exceptions.Timeout as exc:
            raise FetchError("timeout", f"Request timed out after {timeout}s.") from exc
        except requests.exceptions.SSLError as exc:
            raise FetchError("tls", "TLS/certificate error while connecting.") from exc
        except requests.exceptions.ConnectionError as exc:
            raise FetchError("connection", "Could not connect to the host.") from exc
        except requests.exceptions.RequestException as exc:
            raise FetchError("request", f"Request failed: {type(exc).__name__}.") from exc

        try:
            code = resp.status_code
            headers = dict(resp.headers)
            location = resp.headers.get("Location")
        finally:
            resp.close()  # body is never downloaded

        if code in REDIRECT_CODES and location:
            nxt = urljoin(current, location)
            try:
                nxt = validate_url(nxt)
            except InvalidURLError as exc:
                raise FetchError("redirect", f"Redirect to an unsupported target: {exc}") from exc
            host = urlsplit(nxt).hostname or ""
            if not initial_internal:
                try:
                    internal = host_is_internal(host, resolver)
                except ResolutionError as exc:
                    raise FetchError(
                        "blocked",
                        f"Redirect target '{host}' could not be resolved; blocked as a precaution.",
                    ) from exc
                if internal:
                    raise FetchError(
                        "blocked",
                        f"Redirect to an internal/private address was blocked (host '{host}'). "
                        "No request was sent to it.",
                    )
            if urlsplit(current).scheme == "https" and urlsplit(nxt).scheme == "http":
                notes.append("Redirect chain downgrades from HTTPS to HTTP.")
            chain.append(nxt)
            current = nxt
            continue

        if code in REDIRECT_CODES:
            notes.append(f"HTTP {code} redirect without a Location header; treated as final response.")
        if code >= 400:
            notes.append(f"Server returned HTTP {code}; headers on error pages may differ from normal pages.")
        elif not (200 <= code < 400):
            notes.append(f"Unusual HTTP status {code}.")
        return FetchResult(url, current, code, chain, headers,
                           int((time.monotonic() - start) * 1000), notes)

    raise FetchError("redirect", f"Exceeded the limit of {max_redirects} redirects.")
