import pytest

from header_checker import cli
from header_checker.fetcher import FetchError, fetch
from header_checker.netguard import ResolutionError, host_is_internal, is_blocked_address

PUBLIC_IP = "93.184.216.34"


def public_resolver(host):
    return [PUBLIC_IP]


class FakeResp:
    def __init__(self, code, headers):
        self.status_code, self.headers = code, headers

    def close(self):
        pass


class FakeSession:
    """Serves canned responses and records every URL actually requested."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def get(self, url, **kwargs):
        self.calls.append(url)
        code, headers = self.routes[url]
        return FakeResp(code, headers)


def redirect_to(location):
    return FakeSession({
        "https://public.example/": (302, {"Location": location}),
        location: (200, {}),
    })


@pytest.mark.parametrize("target", [
    "http://127.0.0.1/", "http://10.0.0.5/", "http://172.16.0.1/",
    "http://192.168.1.1/", "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://100.64.0.1/",
    "http://0.0.0.0/", "http://localhost:8080/", "http://printer.local/",
    "http://svc.internal/", "http://[fe80::1]/",
])
def test_redirect_from_public_to_internal_is_blocked(target):
    sess = redirect_to(target)
    with pytest.raises(FetchError) as exc:
        fetch("https://public.example/", session=sess, resolver=public_resolver)
    assert exc.value.category == "blocked"
    assert sess.calls == ["https://public.example/"]  # internal URL never requested


def test_hostname_resolving_to_private_address_is_blocked():
    sess = redirect_to("http://sneaky.example/")
    resolver = lambda h: ["10.1.2.3"] if h == "sneaky.example" else [PUBLIC_IP]
    with pytest.raises(FetchError) as exc:
        fetch("https://public.example/", session=sess, resolver=resolver)
    assert exc.value.category == "blocked" and len(sess.calls) == 1


def test_mixed_public_and_private_answers_are_blocked():
    sess = redirect_to("http://multi.example/")
    resolver = lambda h: [PUBLIC_IP, "192.168.0.9"] if h == "multi.example" else [PUBLIC_IP]
    with pytest.raises(FetchError) as exc:
        fetch("https://public.example/", session=sess, resolver=resolver)
    assert exc.value.category == "blocked"


def test_unresolvable_redirect_target_fails_closed():
    def resolver(host):
        if host == "public.example":
            return [PUBLIC_IP]
        raise ResolutionError("nope")
    sess = redirect_to("http://gone.example/")
    with pytest.raises(FetchError) as exc:
        fetch("https://public.example/", session=sess, resolver=resolver)
    assert exc.value.category == "blocked"


def test_redirect_to_public_host_is_allowed():
    sess = redirect_to("https://other.example/")
    res = fetch("https://public.example/", session=sess, resolver=public_resolver)
    assert res.final_url == "https://other.example/" and len(sess.calls) == 2


def test_internal_start_may_redirect_internally():
    sess = FakeSession({
        "http://127.0.0.1:8000/": (302, {"Location": "http://10.0.0.5/x"}),
        "http://10.0.0.5/x": (200, {}),
    })
    res = fetch("http://127.0.0.1:8000/", session=sess, resolver=public_resolver)
    assert res.final_url == "http://10.0.0.5/x"


def test_blocked_error_maps_to_dedicated_exit_code(monkeypatch, capsys):
    def boom(*a, **k):
        raise FetchError("blocked", "Redirect to an internal/private address was blocked.")
    monkeypatch.setattr(cli, "fetch", boom)
    assert cli.main(["https://example.org", "--confirm-authorized"]) == cli.EXIT_BLOCKED
    assert "[blocked]" in capsys.readouterr().err


@pytest.mark.parametrize("addr,blocked", [
    ("8.8.8.8", False), ("2606:4700:4700::1111", False),
    ("224.0.0.1", True), ("198.18.0.1", True), ("::ffff:10.0.0.1", True),
])
def test_is_blocked_address(addr, blocked):
    assert is_blocked_address(addr) is blocked


def test_host_is_internal_names_and_literals():
    assert host_is_internal("LOCALHOST.") and host_is_internal("db.internal")
    assert host_is_internal("10.0.0.1") and not host_is_internal("8.8.8.8")
    with pytest.raises(ResolutionError):
        host_is_internal("", public_resolver)
