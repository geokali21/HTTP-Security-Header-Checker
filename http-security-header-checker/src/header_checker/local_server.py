"""Local test server (127.0.0.1 only) with selectable header profiles."""
from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Tuple

PROFILES: Dict[str, Dict[str, str]] = {
    "secure": {
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    },
    "weak": {},
    "mixed": {
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        "Referrer-Policy": "unsafe-url",
    },
}

# Present on every response to prove the tool never prints unrelated headers.
DECOY_HEADERS = {
    "Set-Cookie": "session=SECRET_TEST_VALUE; HttpOnly",
    "Server": "DemoServer/1.0",
}


def make_handler(profile: str):
    extra = PROFILES[profile]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # keep test output quiet
            pass

        def _send(self, code: int, extra_headers=None):
            self.send_response(code)
            for k, v in {**DECOY_HEADERS, **extra, **(extra_headers or {})}.items():
                self.send_header(k, v)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def do_GET(self):  # noqa: N802
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif self.path == "/loop":
                self.send_response(302)
                self.send_header("Location", "/loop")
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif self.path == "/slow":
                time.sleep(2)
                self._send(200)
            elif self.path == "/error":
                self._send(500)
            else:
                self._send(200)

    return Handler


def start_server(profile: str = "weak") -> Tuple[ThreadingHTTPServer, str]:
    """Start a server on a free loopback port. Returns (server, base_url)."""
    if profile not in PROFILES:
        raise ValueError(f"Unknown profile: {profile}")
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(profile))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"
