# HTTP Security Header Checker

A passive command-line tool that reviews the HTTP security headers of a **single website you own or are authorised to test**, and explains what each result means, the potential risk, and how to fix it.

> **Repository description (GitHub "About"):** Passive Python CLI that reviews HTTP security headers (CSP, HSTS, XCTO, XFO, Referrer-Policy, Permissions-Policy) with explanations, mitigations, and JSON/HTML reports.

## Features

- Accepts a URL via CLI; strictly validates `http`/`https` URLs (rejects other schemes, bad ports, embedded credentials, control characters)
- One GET request per hop with a timeout; bounded manual redirect following; shows the final URL and flags HTTPS→HTTP downgrades
- Checks `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`
- Three statuses: `FOUND`, `MISSING`, `REVIEW`, each with a documented rule (see [docs/FINDINGS.md](docs/FINDINGS.md))
- For each result: purpose, potential risk, mitigation, how to re-verify, and limitations
- Terminal, JSON and self-contained HTML reports (all values HTML-escaped)
- Handles timeouts, connection/TLS errors, redirect loops, and unusual HTTP statuses with distinct exit codes
- **Redirect safety (SSRF guard):** a redirect from a public target to a loopback, private, link-local, CGNAT or otherwise non-public address is blocked before any request is sent to it
- Built-in local test server with `secure`, `weak` and `mixed` profiles (`--demo`)
- 79 pytest tests

## Safety and scope

- Single target, single GET per redirect hop, response body is never downloaded. No crawling, fuzzing, or exploitation features.
- Non-local targets require `--confirm-authorized`. Only test systems you own or have written permission to test.
- **Internal-network protection:** if you start from a public target, redirects to internal/private destinations (e.g. `127.0.0.1`, `10.x`, `192.168.x`, `169.254.169.254`, `localhost`, `*.internal`, IPv4-mapped IPv6) are refused and fail closed if the name cannot be resolved. If you deliberately start from a local/internal target, internal redirects are allowed.
- Only the six security headers are printed. Other headers (cookies, `Server`, etc.) are never shown; this is covered by a test.
- **No security score is produced.** A missing header is an *observation* and a *potential risk*, not a confirmed vulnerability.

## Installation

```bash
git clone https://github.com/geokali21/http-security-header-checker.git
cd http-security-header-checker
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Without installing, you can also run `export PYTHONPATH=src` and use `python -m header_checker`.

## Usage

```bash
header-checker --demo mixed                       # safe local demo
header-checker https://example.org --confirm-authorized
header-checker https://example.org --confirm-authorized --json reports/out.json --html reports/out.html
header-checker --help
```

| Option | Description |
|---|---|
| `--timeout N` | Request timeout in seconds (default 10) |
| `--max-redirects N` | Max redirects to follow, 0-20 (default 5) |
| `--json FILE` / `--html FILE` | Export reports |
| `--verbose` | Show explanations for `FOUND` headers too |
| `--no-color` | Disable ANSI colors |
| `--confirm-authorized` | Required for non-local targets |
| `--demo PROFILE` | Test against the built-in local server |

Exit codes: `0` success, `2` invalid input, `3` network error, `4` redirect blocked by the internal-address guard.

## Example output (real run: `header-checker --demo mixed`)

```text
================================================================
 HTTP Security Header Checker v1.0.0
================================================================
Target      : http://127.0.0.1:37397/redirect
Final URL   : http://127.0.0.1:37397/
HTTP status : 200   (3 ms)
Redirects   : http://127.0.0.1:37397/redirect -> http://127.0.0.1:37397/
----------------------------------------------------------------
[REVIEW] Content-Security-Policy
    Value      : default-src 'self'; script-src 'self' 'unsafe-inline'
    Observation: CSP is present but should be reviewed: 'unsafe-inline' allowed for scripts without a nonce or hash.
    Purpose    : Restricts which sources the browser may load scripts, styles and frames from, limiting the impact of injected content.
    Potential risk: Without it, an XSS flaw (if one exists) is easier to exploit. Absence alone does not prove XSS exists.
    Mitigation : Define a policy starting from default-src 'self'; use nonces or hashes instead of 'unsafe-inline'; consider Report-Only first.

[REVIEW] Strict-Transport-Security
    Observation: Final URL uses HTTP; browsers ignore HSTS over HTTP, so it cannot be evaluated here. Re-test the HTTPS URL.
    Purpose    : Tells browsers to use HTTPS only for the site, reducing downgrade and SSL-stripping exposure.
    Potential risk: Without it, a user's first or later plain-HTTP request may be intercepted by a network attacker.
    Mitigation : Serve it on HTTPS responses with max-age of at least 15552000; add includeSubDomains only after checking subdomains.

[FOUND] X-Content-Type-Options
    Value      : nosniff
    Observation: X-Content-Type-Options is set to nosniff.

[FOUND] X-Frame-Options
    Value      : SAMEORIGIN
    Observation: X-Frame-Options is SAMEORIGIN.

[REVIEW] Referrer-Policy
    Value      : unsafe-url
    Observation: Effective policy 'unsafe-url' may leak full URLs to other origins.
    Purpose    : Controls how much referrer (URL) information is sent to other sites.
    Potential risk: Full URLs, which may hold tokens or identifiers in paths or queries, could leak to third parties.
    Mitigation : Use 'strict-origin-when-cross-origin' or stricter; avoid putting secrets in URLs.

[MISSING] Permissions-Policy
    Observation: No Permissions-Policy header was observed.
    Purpose    : Restricts access to powerful browser features (camera, microphone, geolocation) for the page and embedded frames.
    Potential risk: Embedded third-party content may request features the site does not need.
    Mitigation : Disable unused features, e.g. 'camera=(), microphone=(), geolocation=()'.

Summary: 2 found, 1 missing, 3 to review
Disclaimer: Findings are observations and potential risks based on one HTTP GET response. A missing or weak header does not by itself confirm a vulnerability, and this report is not a security score or a complete assessment.
```

Full outputs: [`examples/`](examples/) and [`reports/`](reports/) (JSON + HTML). The `secure` demo shows HSTS as `REVIEW` because the demo server uses plain HTTP, and browsers ignore HSTS over HTTP.

## Testing

```bash
pytest -v
```

The suite covers URL validation, every header rule (including edge cases such as CSP nonces and HSTS over HTTP), redirect handling, timeouts, connection errors, report generation, HTML escaping, and a check that decoy secrets served by the test server never appear in reports. Latest recorded run: [`reports/pytest_results.txt`](reports/pytest_results.txt).

## Documentation

- [docs/USAGE.md](docs/USAGE.md): usage guide (Bahasa Indonesia)
- [docs/DESIGN.md](docs/DESIGN.md): design and rationale (Bahasa Indonesia)
- [docs/FINDINGS.md](docs/FINDINGS.md): findings, risks, mitigations, verification (Bahasa Indonesia)

## Limitations

- Evaluates one response from one URL; other routes may send different headers.
- The redirect guard resolves a hostname and then `requests` resolves it again when connecting, so a DNS-rebinding attacker who controls a DNS server could in theory return different answers. Connection-level IP pinning is on the roadmap.
- CSP and Permissions-Policy are only partially analysed; manual review is still needed.
- Headers set via `<meta>` tags or by JavaScript are not seen.
- Error pages (4xx/5xx) and CDN/WAF responses may differ from normal pages.
- Deprecated headers and cookie flags are out of scope.

## Roadmap

- Pin the resolved IP at connection time to close the DNS-rebinding gap
- Cookie attribute review (`Secure`, `HttpOnly`, `SameSite`)
- Cross-origin headers (COOP, COEP, CORP)
- More detailed CSP parser
- Markdown/CSV export, config file with custom rules
- GitHub Actions CI running pytest

## License

MIT
