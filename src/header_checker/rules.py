"""Header evaluation rules.

Each check returns (Status, reason). Rules are intentionally conservative:
a missing header is an *observation* and a *potential risk*, never proof
of a vulnerability. No numeric "security score" is produced.
"""
from __future__ import annotations

import re
from typing import Callable, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from .models import HeaderFinding, Status

HSTS_MIN_MAX_AGE = 15_552_000  # 180 days; a common minimum recommendation
MAX_VALUE_LEN = 200

VALID_REFERRER_TOKENS = {
    "no-referrer", "no-referrer-when-downgrade", "origin",
    "origin-when-cross-origin", "same-origin", "strict-origin",
    "strict-origin-when-cross-origin", "unsafe-url",
}
WEAK_REFERRER_TOKENS = {"unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"}

Check = Callable[[Optional[str], Mapping[str, str], str], Tuple[Status, str]]


def safe_value(value: Optional[str]) -> Optional[str]:
    """Strip control characters and truncate so output stays safe to print."""
    if value is None:
        return None
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", value)
    if len(cleaned) > MAX_VALUE_LEN:
        cleaned = cleaned[:MAX_VALUE_LEN] + "...(truncated)"
    return cleaned


def _csp_directives(value: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            out.setdefault(tokens[0].lower(), tokens[1:])
    return out


def check_csp(value, headers, final_url):
    if value is None:
        return Status.MISSING, "No Content-Security-Policy header was observed."
    d = _csp_directives(value)
    issues: List[str] = []
    src = d.get("script-src", d.get("default-src"))
    if src is None:
        issues.append("no default-src or script-src directive, so script sources are not restricted")
    else:
        toks = [t.lower() for t in src]
        has_nonce_or_hash = any(
            t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or t == "'strict-dynamic'"
            for t in toks
        )
        if "'unsafe-inline'" in toks and not has_nonce_or_hash:
            issues.append("'unsafe-inline' allowed for scripts without a nonce or hash")
        if "'unsafe-eval'" in toks:
            issues.append("'unsafe-eval' allowed for scripts")
        if any(t in ("*", "http:", "https:", "data:") for t in toks):
            issues.append("overly broad script source (wildcard or whole scheme)")
    if issues:
        return Status.REVIEW, "CSP is present but should be reviewed: " + "; ".join(issues) + "."
    return Status.FOUND, "CSP is present with no weak script-source patterns detected by this tool."


def check_hsts(value, headers, final_url):
    is_https = urlsplit(final_url).scheme == "https"
    if not is_https:
        return Status.REVIEW, (
            "Final URL uses HTTP; browsers ignore HSTS over HTTP, so it cannot be "
            "evaluated here. Re-test the HTTPS URL."
        )
    if value is None:
        return Status.MISSING, "No Strict-Transport-Security header was observed on HTTPS."
    m = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.IGNORECASE)
    if not m:
        return Status.REVIEW, "HSTS is present but has no valid max-age directive."
    age = int(m.group(1))
    if age < HSTS_MIN_MAX_AGE:
        return Status.REVIEW, f"HSTS max-age is {age}s, below the {HSTS_MIN_MAX_AGE}s (180 days) reference."
    return Status.FOUND, f"HSTS is present with max-age={age}."


def check_xcto(value, headers, final_url):
    if value is None:
        return Status.MISSING, "No X-Content-Type-Options header was observed."
    if value.strip().lower() == "nosniff":
        return Status.FOUND, "X-Content-Type-Options is set to nosniff."
    return Status.REVIEW, "X-Content-Type-Options is present but its value is not 'nosniff'."


def check_xfo(value, headers, final_url):
    csp = headers.get("content-security-policy")
    has_fa = bool(csp) and "frame-ancestors" in _csp_directives(csp)
    if value is None:
        if has_fa:
            return Status.REVIEW, (
                "X-Frame-Options is absent, but CSP frame-ancestors is set, which "
                "modern browsers prefer. Review whether legacy-browser coverage matters."
            )
        return Status.MISSING, "No X-Frame-Options header (and no CSP frame-ancestors) was observed."
    v = value.strip().upper()
    if v in ("DENY", "SAMEORIGIN"):
        return Status.FOUND, f"X-Frame-Options is {v}."
    return Status.REVIEW, "X-Frame-Options has a non-standard or obsolete value (e.g. ALLOW-FROM)."


def check_referrer(value, headers, final_url):
    if value is None:
        return Status.MISSING, "No Referrer-Policy header was observed (browser default applies)."
    tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
    valid = [t for t in tokens if t in VALID_REFERRER_TOKENS]
    if not valid:
        return Status.REVIEW, "Referrer-Policy has no recognised policy token."
    effective = valid[-1]  # browsers use the last recognised token
    if effective in WEAK_REFERRER_TOKENS:
        return Status.REVIEW, f"Effective policy '{effective}' may leak full URLs to other origins."
    return Status.FOUND, f"Effective Referrer-Policy is '{effective}'."


def check_permissions(value, headers, final_url):
    if value is None:
        return Status.MISSING, "No Permissions-Policy header was observed."
    if not value.strip():
        return Status.REVIEW, "Permissions-Policy is present but empty."
    return Status.FOUND, "Permissions-Policy is present; directives should be reviewed manually."


HEADER_RULES: List[Tuple[str, Check, Dict[str, str]]] = [
    ("Content-Security-Policy", check_csp, dict(
        purpose="Restricts which sources the browser may load scripts, styles and frames from, limiting the impact of injected content.",
        risk="Without it, an XSS flaw (if one exists) is easier to exploit. Absence alone does not prove XSS exists.",
        mitigation="Define a policy starting from default-src 'self'; use nonces or hashes instead of 'unsafe-inline'; consider Report-Only first.",
        verification="Re-run the tool and check the header; test pages in the browser console for CSP violations.",
        limitation="The tool does not fully parse CSP semantics or evaluate every directive.")),
    ("Strict-Transport-Security", check_hsts, dict(
        purpose="Tells browsers to use HTTPS only for the site, reducing downgrade and SSL-stripping exposure.",
        risk="Without it, a user's first or later plain-HTTP request may be intercepted by a network attacker.",
        mitigation="Serve it on HTTPS responses with max-age of at least 15552000; add includeSubDomains only after checking subdomains.",
        verification="Re-run against the HTTPS URL and confirm max-age; browser dev tools show it under response headers.",
        limitation="Only meaningful over HTTPS; preload status is not checked.")),
    ("X-Content-Type-Options", check_xcto, dict(
        purpose="Stops browsers from guessing (MIME-sniffing) content types, preventing some content-confusion attacks.",
        risk="Uploaded or reflected content may be interpreted as an executable type in some scenarios.",
        mitigation="Send 'X-Content-Type-Options: nosniff' and ensure correct Content-Type on all responses.",
        verification="Re-run the tool; confirm the value is exactly nosniff.",
        limitation="Only the checked URL is evaluated; other routes may differ.")),
    ("X-Frame-Options", check_xfo, dict(
        purpose="Controls whether the page can be embedded in frames, mitigating clickjacking.",
        risk="A page that can be framed may be used in a clickjacking attempt against logged-in users.",
        mitigation="Use CSP 'frame-ancestors' (preferred); optionally also send X-Frame-Options: DENY or SAMEORIGIN.",
        verification="Re-run the tool; optionally try framing the page from a local test HTML file you control.",
        limitation="Whether framing is actually harmful depends on page functionality.")),
    ("Referrer-Policy", check_referrer, dict(
        purpose="Controls how much referrer (URL) information is sent to other sites.",
        risk="Full URLs, which may hold tokens or identifiers in paths or queries, could leak to third parties.",
        mitigation="Use 'strict-origin-when-cross-origin' or stricter; avoid putting secrets in URLs.",
        verification="Re-run the tool; check outgoing Referer headers in browser dev tools.",
        limitation="Policies set via <meta> tags or per-element attributes are not seen.")),
    ("Permissions-Policy", check_permissions, dict(
        purpose="Restricts access to powerful browser features (camera, microphone, geolocation) for the page and embedded frames.",
        risk="Embedded third-party content may request features the site does not need.",
        mitigation="Disable unused features, e.g. 'camera=(), microphone=(), geolocation=()'.",
        verification="Re-run the tool and review the directive list.",
        limitation="Directive contents are not validated; support varies across browsers.")),
]


def evaluate(headers: Mapping[str, str], final_url: str) -> List[HeaderFinding]:
    """Evaluate response headers (keys are matched case-insensitively)."""
    lower = {k.lower(): v for k, v in headers.items()}
    findings: List[HeaderFinding] = []
    for name, check, meta in HEADER_RULES:
        value = lower.get(name.lower())
        status, reason = check(value, lower, final_url)
        findings.append(HeaderFinding(
            name=name, status=status, observed_value=safe_value(value),
            reason=reason, **meta,
        ))
    return findings
