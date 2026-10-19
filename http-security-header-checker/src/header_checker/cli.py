"""Command-line interface."""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional
from urllib.parse import urlsplit

from . import __version__
from .fetcher import FetchError, fetch
from .local_server import PROFILES, start_server
from .report import build_report, render_terminal, to_html, to_json
from .validators import InvalidURLError, is_loopback_host, validate_url

EXIT_OK, EXIT_INVALID, EXIT_NETWORK, EXIT_BLOCKED = 0, 2, 3, 4


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="header-checker",
        description="Passive HTTP security header review for sites you own or are authorised to test.")
    p.add_argument("url", nargs="?", help="Target http(s) URL")
    p.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds (default 10)")
    p.add_argument("--max-redirects", type=int, default=5, help="Maximum redirects to follow (default 5)")
    p.add_argument("--json", metavar="FILE", help="Write JSON report to FILE")
    p.add_argument("--html", metavar="FILE", help="Write HTML report to FILE")
    p.add_argument("--verbose", action="store_true", help="Show explanations for FOUND headers too")
    p.add_argument("--no-color", action="store_true", help="Disable colored output")
    p.add_argument("--confirm-authorized", action="store_true",
                   help="Confirm you own or have written permission to test a non-local target")
    p.add_argument("--demo", choices=sorted(PROFILES), metavar="PROFILE",
                   help=f"Test against a built-in local server ({', '.join(sorted(PROFILES))})")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    server = None
    try:
        if args.demo:
            server, base = start_server(args.demo)
            target = base + "/redirect"
            print(f"[demo] local '{args.demo}' server on {base}", file=sys.stderr)
        elif args.url:
            target = args.url
        else:
            print("error: provide a URL or use --demo PROFILE", file=sys.stderr)
            return EXIT_INVALID

        try:
            target = validate_url(target)
        except InvalidURLError as exc:
            print(f"error: invalid URL: {exc}", file=sys.stderr)
            return EXIT_INVALID
        if args.timeout <= 0 or not (0 <= args.max_redirects <= 20):
            print("error: --timeout must be > 0 and --max-redirects between 0 and 20", file=sys.stderr)
            return EXIT_INVALID
        if not is_loopback_host(urlsplit(target).hostname or "") and not args.confirm_authorized:
            print("error: non-local target. Re-run with --confirm-authorized to confirm you own "
                  "this site or have permission to test it.", file=sys.stderr)
            return EXIT_INVALID

        try:
            result = fetch(target, timeout=args.timeout, max_redirects=args.max_redirects)
        except FetchError as exc:
            print(f"error [{exc.category}]: {exc}", file=sys.stderr)
            return EXIT_BLOCKED if exc.category == "blocked" else EXIT_NETWORK

        report = build_report(result)
        color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
        print(render_terminal(report, color=color, verbose=args.verbose))
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(to_json(report))
        if args.html:
            with open(args.html, "w", encoding="utf-8") as fh:
                fh.write(to_html(report))
        return EXIT_OK
    finally:
        if server:
            server.shutdown()
            server.server_close()
