import pytest

from header_checker.validators import InvalidURLError, is_loopback_host, validate_url


@pytest.mark.parametrize("url", ["http://example.com", "https://example.com/a?b=1",
                                 "  https://example.com:8443/  ", "http://127.0.0.1:8000"])
def test_valid_urls(url):
    assert validate_url(url) == url.strip()


@pytest.mark.parametrize("url", [
    "", "   ", "example.com", "ftp://example.com", "javascript:alert(1)",
    "file:///etc/passwd", "http://", "http://example.com:99999",
    "http://example.com:0", "http://user:pass@example.com", "http://exa mple.com",
    "http://example.com/" + "a" * 2100,
])
def test_invalid_urls(url):
    with pytest.raises(InvalidURLError):
        validate_url(url)


def test_loopback_detection():
    assert is_loopback_host("localhost") and is_loopback_host("127.0.0.1")
    assert not is_loopback_host("example.com") and not is_loopback_host("8.8.8.8")
