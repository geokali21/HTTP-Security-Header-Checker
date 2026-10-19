import pytest

from header_checker.fetcher import FetchError, fetch
from header_checker.validators import InvalidURLError


def test_fetch_follows_redirect_and_reports_final_url(weak_server):
    r = fetch(weak_server + "/redirect")
    assert r.status_code == 200
    assert r.final_url == weak_server + "/"
    assert len(r.redirect_chain) == 2


def test_redirect_loop_is_bounded(weak_server):
    with pytest.raises(FetchError) as exc:
        fetch(weak_server + "/loop", max_redirects=3)
    assert exc.value.category == "redirect"


def test_timeout(weak_server):
    with pytest.raises(FetchError) as exc:
        fetch(weak_server + "/slow", timeout=0.5)
    assert exc.value.category == "timeout"


def test_connection_refused():
    with pytest.raises(FetchError) as exc:
        fetch("http://127.0.0.1:1/", timeout=2)
    assert exc.value.category == "connection"


def test_error_status_adds_note(weak_server):
    r = fetch(weak_server + "/error")
    assert r.status_code == 500 and any("500" in n for n in r.notes)


def test_invalid_url_rejected_before_network():
    with pytest.raises(InvalidURLError):
        fetch("ftp://example.com")
