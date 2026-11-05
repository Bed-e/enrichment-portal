from app.sources.ratelimit import RateLimiter
from tests.fakes import FakeClock


def make(clock: FakeClock, max_calls: int = 3, period: float = 10.0) -> RateLimiter:
    return RateLimiter(max_calls, period, clock=clock, sleep=clock.sleep)


async def test_calls_under_the_limit_do_not_wait() -> None:
    clock = FakeClock()
    limiter = make(clock)
    assert [await limiter.acquire(max_wait=8) for _ in range(3)] == [True, True, True]
    assert clock.sleeps == []


async def test_the_call_over_the_limit_waits_for_the_window_to_open() -> None:
    clock = FakeClock()
    limiter = make(clock)
    for _ in range(3):
        await limiter.acquire(max_wait=10)
    clock.now = 4.0  # the first call was at t=0, so a slot frees up at t=10
    assert await limiter.acquire(max_wait=10) is True
    assert clock.sleeps == [6.0]
    assert clock.now == 10.0


async def test_gives_up_instead_of_waiting_longer_than_max_wait() -> None:
    clock = FakeClock()
    limiter = make(clock)
    for _ in range(3):
        await limiter.acquire(max_wait=8)
    assert await limiter.acquire(max_wait=8) is False  # would need to wait 10 s
    assert clock.sleeps == []  # it never slept


async def test_old_calls_leave_the_window() -> None:
    clock = FakeClock()
    limiter = make(clock)
    for _ in range(3):
        await limiter.acquire(max_wait=8)
    clock.now = 10.0
    assert await limiter.acquire(max_wait=8) is True
    assert clock.sleeps == []


async def test_a_refused_call_does_not_use_a_slot() -> None:
    clock = FakeClock()
    limiter = make(clock, max_calls=1)
    await limiter.acquire(max_wait=8)
    assert await limiter.acquire(max_wait=1) is False
    clock.now = 10.0
    assert await limiter.acquire(max_wait=1) is True
