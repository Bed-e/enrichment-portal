"""Test doubles: a fake DNS resolver and a fake clock (design.md D13)."""

from typing import Any


class FakeResolver:
    """Answers Team Cymru TXT queries from a recorded fixture, with no network.

    A query the fixture does not contain raises KeyError, so a client that asks for something
    unexpected fails the test loudly. `error` makes every query raise it instead.
    """

    def __init__(self, fixture: dict[str, Any] | None = None, error: Exception | None = None):
        self.queries = (fixture or {}).get("queries", {})
        self.error = error
        self.asked: list[str] = []

    async def resolve_txt(self, name: str) -> list[str] | None:
        self.asked.append(name)
        if self.error is not None:
            raise self.error
        return self.queries[name]["txt"] or None  # NXDOMAIN / NOANSWER -> None


class FakeClock:
    """A clock whose sleep advances time instantly, for the rate limiter."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds
