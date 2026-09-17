"""Base wrapper all tool-executing functions must use.

Every subprocess invocation goes through ToolExecutor.run(), which calls
scope.checker.authorize() first. A direct subprocess call anywhere else in
the codebase is a bug -- see CLAUDE.md.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import time
from dataclasses import dataclass

from audit.log import AuditLogger
from scope.checker import authorize
from scope.models import ScopeRecord, TestCategory
from tools.rate_limit import RateLimiter

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float


class ToolExecutor:
    def __init__(
        self,
        scope_record: ScopeRecord,
        audit_logger: AuditLogger,
        branch_id: str | None = None,
        semaphore: asyncio.Semaphore | None = None,
        rate_limiter: RateLimiter | None = None,
    ):
        self._scope_record = scope_record
        self._audit_logger = audit_logger
        self._branch_id = branch_id
        # Unbounded-in-practice defaults so callers that don't care about a
        # scan profile (tests, one-off scripts) don't need to construct
        # these -- a real run always passes the profile-derived versions,
        # see orchestrator.run.start_run.
        self._semaphore = semaphore or asyncio.Semaphore(1_000_000)
        self._rate_limiter = rate_limiter or RateLimiter(requests_per_second=None)

    async def run(self, target: str, category: TestCategory, command: list[str], timeout: float = 120.0) -> ToolResult:
        # Re-validated on every call -- fan-out branches must not be able to
        # bypass the gate just because a sibling branch already passed it.
        # authorize() itself logs+raises loudly on refusal; nothing more to
        # do here on that path.
        authorize(self._scope_record, target, category, self._audit_logger)
        await self._rate_limiter.wait(target)

        command_str = " ".join(command)
        logger.info("[%s] running: %s (category=%s)", target, command_str, category.value)

        self._audit_logger.log_event(
            "command_executed", {"command": command, "target": target}, branch_id=self._branch_id
        )

        start = time.monotonic()
        async with self._semaphore:
            proc = await asyncio.to_thread(
                subprocess.run, command, capture_output=True, text=True, timeout=timeout
            )
        duration = time.monotonic() - start

        result = ToolResult(
            command=command,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_seconds=duration,
        )

        if result.returncode == 0:
            logger.info("[%s] finished: %s (%.2fs)", target, command[0], duration)
        else:
            logger.warning(
                "[%s] non-zero exit: %s returncode=%d (%.2fs) stderr=%s",
                target,
                command[0],
                result.returncode,
                duration,
                result.stderr.strip()[:500],
            )

        self._audit_logger.log_event(
            "result",
            {
                "command": command,
                "target": target,
                "returncode": result.returncode,
                "duration_seconds": duration,
            },
            branch_id=self._branch_id,
        )
        return result
