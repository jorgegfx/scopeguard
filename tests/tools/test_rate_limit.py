from tools.rate_limit import RateLimiter


async def test_wait_is_a_noop_when_unlimited():
    limiter = RateLimiter(requests_per_second=None)
    # No monkeypatching -- if this actually slept, the test would be slow.
    await limiter.wait("10.0.0.5")
    await limiter.wait("10.0.0.5")


async def test_wait_sleeps_to_enforce_minimum_interval(monkeypatch):
    limiter = RateLimiter(requests_per_second=2)  # 0.5s minimum interval

    clock = [0.0]
    monkeypatch.setattr("tools.rate_limit.time.monotonic", lambda: clock[0])

    sleeps: list[float] = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr("tools.rate_limit.asyncio.sleep", fake_sleep)

    await limiter.wait("10.0.0.5")  # first call, nothing to wait for
    clock[0] += 0.1  # only 0.1s elapsed before the next call
    await limiter.wait("10.0.0.5")

    assert sleeps == [0.4]  # needed 0.5s, only 0.1s had passed


async def test_wait_tracks_targets_independently(monkeypatch):
    limiter = RateLimiter(requests_per_second=2)

    clock = [0.0]
    sleeps: list[float] = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr("tools.rate_limit.time.monotonic", lambda: clock[0])
    monkeypatch.setattr("tools.rate_limit.asyncio.sleep", fake_sleep)

    await limiter.wait("10.0.0.5")
    await limiter.wait("10.0.0.9")  # different target -- should not wait

    assert sleeps == []
