"""LangGraph fan-out/fan-in graph: recon -> N parallel service testers -> report.

The service-tester fan-out uses LangGraph's Send API since the number of
services isn't known until recon completes (see CLAUDE.md: "Parallel
sub-agent execution"). Each test_service branch must re-run
scope.checker.authorize() itself -- fan-out must never become a way to
bypass the per-target, per-category authorization gate.
"""

from __future__ import annotations

import logging

from langgraph.graph import END, StateGraph
from langgraph.types import Send

from agents.recon.agent import ReconAgent
from agents.report.agent import ReportAgent
from agents.service_enum.agent import ServiceEnumAgent
from agents.vuln_scan.agent import VulnScanAgent
from agents.webapp.agent import WebAppAgent
from audit.log import AuditLogger
from orchestrator.state import Finding, RunState, ServiceFinding, ServiceTarget
from scope.models import ScopeRecord, TestCategory
from tools.base import ToolExecutor

logger = logging.getLogger(__name__)

_HTTP_PORTS = {80, 443, 8000, 8080, 8443, 8888}


async def recon_node(state: RunState) -> dict:
    scope_record = state["scope_record"]
    audit_logger = AuditLogger(run_id=state["run_id"])
    executor = ToolExecutor(
        scope_record,
        audit_logger,
        branch_id="recon",
        semaphore=state["tool_semaphore"],
        rate_limiter=state["rate_limiter"],
    )
    agent = ReconAgent(agent_name="recon")

    logger.info("recon: starting against %d target(s)", len(scope_record.targets))
    discovered: list[ServiceTarget] = []
    for scope_target in scope_record.targets:
        found = await agent.run(executor, scope_target.value)
        logger.info("recon: %s -> %d open port(s)", scope_target.value, len(found))
        discovered.extend(found)

    logger.info("recon: done, %d service(s) discovered total", len(discovered))
    return {"discovered_services": discovered}


def fan_out_to_service_testers(state: RunState) -> list[Send]:
    # A Send-based conditional edge IS the full set of transitions taken --
    # an empty list ends this branch of execution with no path to "report"
    # at all. Route straight there when recon found nothing to test.
    if not state["discovered_services"]:
        return [Send("report", state)]
    return [
        Send("test_service", {**state, "target_service": svc})
        for svc in state["discovered_services"]
    ]


def _looks_like_http(port: int, service: str | None) -> bool:
    if port in _HTTP_PORTS:
        return True
    return bool(service) and "http" in service.lower()


async def _run_category(category: TestCategory, target: str, port: int, run_agent) -> ServiceFinding:
    try:
        findings: list[Finding] = await run_agent()
        logger.info("[%s:%d] %s: %d finding(s)", target, port, category.value, len(findings))
        return {"target": target, "port": port, "category": category.value, "findings": findings, "error": None}
    except Exception as exc:  # noqa: BLE001 -- one branch's failure must not cancel its siblings
        logger.warning("[%s:%d] %s failed: %s", target, port, category.value, exc)
        return {"target": target, "port": port, "category": category.value, "findings": [], "error": str(exc)}


async def test_service_node(state: RunState) -> dict:
    scope_record: ScopeRecord = state["scope_record"]
    svc = state["target_service"]
    target, port, service = svc["target"], svc["port"], svc["service"]

    audit_logger = AuditLogger(run_id=state["run_id"])
    executor = ToolExecutor(
        scope_record,
        audit_logger,
        branch_id=f"{target}:{port}",
        semaphore=state["tool_semaphore"],
        rate_limiter=state["rate_limiter"],
    )

    logger.info("test_service: [%s:%d] service=%s", target, port, service)
    results: list[ServiceFinding] = []

    if scope_record.category_allowed(TestCategory.SERVICE_ENUM):
        agent = ServiceEnumAgent(agent_name="service_enum")
        results.append(
            await _run_category(
                TestCategory.SERVICE_ENUM, target, port, lambda: agent.run(executor, target, port, service)
            )
        )

    if scope_record.category_allowed(TestCategory.VULN_SCAN):
        agent = VulnScanAgent(agent_name="vuln_scan")
        results.append(
            await _run_category(
                TestCategory.VULN_SCAN, target, port, lambda: agent.run(executor, target, port, service)
            )
        )

    if scope_record.category_allowed(TestCategory.WEBAPP_TEST) and _looks_like_http(port, service):
        agent = WebAppAgent(agent_name="webapp")
        results.append(
            await _run_category(TestCategory.WEBAPP_TEST, target, port, lambda: agent.run(executor, target, port))
        )

    return {"service_findings": results}


async def report_node(state: RunState) -> dict:
    agent = ReportAgent(agent_name="report")
    paths = await agent.run(state["run_id"], state["scope_record"], state["service_findings"])
    logger.info("report: written to %s and %s", paths.markdown_path, paths.pdf_path)
    return {"report": str(paths.markdown_path)}


def build_graph() -> StateGraph:
    graph = StateGraph(RunState)
    graph.add_node("recon", recon_node)
    graph.add_node("test_service", test_service_node)
    graph.add_node("report", report_node)

    graph.set_entry_point("recon")
    graph.add_conditional_edges("recon", fan_out_to_service_testers, ["test_service", "report"])
    graph.add_edge("test_service", "report")
    graph.add_edge("report", END)

    return graph
