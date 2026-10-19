import pytest

from header_checker.local_server import start_server


def _make(profile):
    server, base = start_server(profile)
    yield base
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module")
def weak_server():
    yield from _make("weak")


@pytest.fixture(scope="module")
def secure_server():
    yield from _make("secure")


@pytest.fixture(scope="module")
def mixed_server():
    yield from _make("mixed")
