import pytest

from header_checker.models import Status
from header_checker.rules import evaluate, safe_value

HTTPS = "https://example.com/"
HTTP = "http://example.com/"


def status_of(headers, name, url=HTTPS):
    return {f.name: f for f in evaluate(headers, url)}[name].status


def test_all_headers_missing():
    assert all(f.status == Status.MISSING for f in evaluate({}, HTTPS))


def test_headers_matched_case_insensitively():
    assert status_of({"x-content-type-options": "NOSNIFF"}, "X-Content-Type-Options") == Status.FOUND


def test_csp_strong_found():
    assert status_of({"Content-Security-Policy": "default-src 'self'"}, "Content-Security-Policy") == Status.FOUND


def test_csp_unsafe_inline_review():
    h = {"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"}
    assert status_of(h, "Content-Security-Policy") == Status.REVIEW


def test_csp_unsafe_inline_with_nonce_ok():
    h = {"Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'nonce-abc123'"}
    assert status_of(h, "Content-Security-Policy") == Status.FOUND


def test_csp_without_script_restriction_review():
    assert status_of({"Content-Security-Policy": "img-src 'self'"}, "Content-Security-Policy") == Status.REVIEW


def test_hsts_over_http_is_review_not_missing():
    assert status_of({}, "Strict-Transport-Security", HTTP) == Status.REVIEW


def test_hsts_missing_on_https():
    assert status_of({}, "Strict-Transport-Security") == Status.MISSING


@pytest.mark.parametrize("value,expected", [
    ("max-age=31536000; includeSubDomains", Status.FOUND),
    ("max-age=300", Status.REVIEW),
    ("includeSubDomains", Status.REVIEW),
])
def test_hsts_values(value, expected):
    assert status_of({"Strict-Transport-Security": value}, "Strict-Transport-Security") == expected


def test_xcto_wrong_value_review():
    assert status_of({"X-Content-Type-Options": "sniff"}, "X-Content-Type-Options") == Status.REVIEW


def test_xfo_missing_but_frame_ancestors_is_review():
    h = {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"}
    assert status_of(h, "X-Frame-Options") == Status.REVIEW


@pytest.mark.parametrize("value,expected", [
    ("DENY", Status.FOUND), ("sameorigin", Status.FOUND), ("ALLOW-FROM https://a.com", Status.REVIEW)])
def test_xfo_values(value, expected):
    assert status_of({"X-Frame-Options": value}, "X-Frame-Options") == expected


@pytest.mark.parametrize("value,expected", [
    ("strict-origin-when-cross-origin", Status.FOUND), ("unsafe-url", Status.REVIEW),
    ("bogus", Status.REVIEW), ("unsafe-url, no-referrer", Status.FOUND)])
def test_referrer_values(value, expected):
    assert status_of({"Referrer-Policy": value}, "Referrer-Policy") == expected


def test_permissions_empty_review():
    assert status_of({"Permissions-Policy": " "}, "Permissions-Policy") == Status.REVIEW


def test_safe_value_strips_controls_and_truncates():
    out = safe_value("a\r\nb" + "x" * 500)
    assert "\n" not in out and out.endswith("(truncated)") and len(out) < 230
