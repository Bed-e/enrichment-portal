"""Proves the no-real-network rule is enforced, not just stated (design.md D13)."""

import socket

import httpx
import pytest
import respx
from pytest_socket import SocketConnectBlockedError


def test_real_socket_connections_are_blocked() -> None:
    with pytest.raises(SocketConnectBlockedError):
        socket.create_connection(("93.184.216.34", 80), timeout=1)


async def test_unmocked_http_request_fails() -> None:
    with respx.mock(assert_all_mocked=True):
        async with httpx.AsyncClient() as http:
            with pytest.raises(AssertionError):
                await http.get("https://internetdb.shodan.io/8.8.8.8")
