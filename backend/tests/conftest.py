"""Shared fixtures. No test touches the real network: DNS, TLS, WHOIS and
page fetches are replaced with fakes so the suite is fast and deterministic."""
import socket

import pytest

from phishguard.model.predictor import Predictor


@pytest.fixture(scope="session")
def predictor():
    return Predictor.load()


@pytest.fixture
def fake_dns(monkeypatch):
    """Make socket.getaddrinfo answer from a dict: host -> list of IPs."""
    table: dict[str, list[str]] = {}

    def getaddrinfo(host, port, *args, **kwargs):
        if host not in table:
            raise socket.gaierror("not found")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in table[host]]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    return table
