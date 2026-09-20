"""Run lifecycle: load scope record + scan profile, create the audit logger,
execute the graph.

A run cannot start without a valid scope record -- see CLAUDE.md
"Non-negotiable product principle: authorization-first".
"""

from __future__ import annotations

import asyncio
import logging
import uuid

from audit.log import AuditLogger
from llm.client import LLMClient
from orchestrator.graph import build_graph
from orchestrator.profiles import load_scan_profile
from scope.loader import load_scope_record
from tools.rate_limit import RateLimiter

logger = logging.getLogger(__name__)


async def start_run(scope_record_path: str, profile_name: str = "recon_only") -> str:
    run_id = str(uuid.uuid4())
    scope_record = load_scope_record(scope_record_path)
    scan_profile = load_scan_profile(profile_name)
    audit_logger = AuditLogger(run_id=run_id)
    # Constructed once and shared across every branch -- see RunState.llm_client.
    llm_client = LLMClient()

    logger.info(
        "run %s: starting (profile=%s, targets=%d, max_concurrent_branches=%d, rate_limit_rps=%s)",
        run_id,
        profile_name,
        len(scope_record.targets),
        scan_profile.max_concurrent_branches,
        scan_profile.rate_limit_per_target_rps,
    )
    audit_logger.log_event(
        "run_started", {"scope_record_path": scope_record_path, "profile": profile_name}
    )

    graph = build_graph().compile()
    await graph.ainvoke(
        {
            "run_id": run_id,
            "scope_record": scope_record,
            "discovered_services": [],
            "service_findings": [],
            "report": None,
            "tool_semaphore": asyncio.Semaphore(scan_profile.max_concurrent_branches),
            "rate_limiter": RateLimiter(requests_per_second=scan_profile.rate_limit_per_target_rps),
            "llm_client": llm_client,
        }
    )

    logger.info("run %s: finished", run_id)
    return run_id
