"""Per-key call limits, on the `limits` library (moving window, in memory).

A caller's `rate_limit` (e.g. "60/minute; 1000/day") counts its tool
calls across every route. Counts live in the gateway process: a restart
resets them, and two gateway processes count separately.
"""

import anyio
from limits import RateLimitItem, parse_many
from limits.aio.storage import MemoryStorage
from limits.aio.strategies import MovingWindowRateLimiter

from mcp_gateway.config import GatewayConfig


class CallLimiter:
    def __init__(self, config: GatewayConfig) -> None:
        self._limits: dict[str, list[RateLimitItem]] = {
            caller_id: parse_many(caller.rate_limit)
            for caller_id, caller in config.callers.items()
            if caller.rate_limit is not None
        }
        self._limiter = MovingWindowRateLimiter(MemoryStorage())
        # Test every limit, then take from every limit, as one step: a call
        # refused by one limit mustn't use up another.
        self._lock = anyio.Lock()

    async def take(self, caller_id: str) -> str | None:
        """None if the call may go ahead (and it is counted), else the limit it hit."""
        items = self._limits.get(caller_id, [])
        async with self._lock:
            for item in items:
                if not await self._limiter.test(item, caller_id):
                    return str(item)
            for item in items:
                await self._limiter.hit(item, caller_id)
        return None
