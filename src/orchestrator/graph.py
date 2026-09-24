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
from agents.service_tester.agent import ServiceTesterAgent, ToolSpec
from audit.log import AuditLogger
from orchestrator.state import RunState, ServiceFinding, ServiceTarget
from scope.models import ScopeRecord, TestCategory
from tools import content_discovery, curl, cve_lookup, http_headers, nikto, nmap, nuclei, passive_recon, tls
from tools.base import ToolExecutor

logger = logging.getLogger(__name__)

_HTTP_PORTS = {80, 443, 8000, 8080, 8443, 8888}
# Ports we treat as TLS-wrapped, so probes use https:// and the TLS scanner is
# offered. Previously only 443 was recognised, so an HTTPS service on 8443 was
# probed over plain http:// -- fixed here.
_HTTPS_PORTS = {443, 8443}


def _scheme_for(port: int) -> str:
    return "https" if port in _HTTPS_PORTS else "http"


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
    recon_failures: list[ServiceFinding] = []
    for scope_target in scope_record.targets:
        try:
            found = await agent.run(executor, scope_target.value)
        except Exception as exc:  # noqa: BLE001 -- one target's recon failure must not cancel the rest
            logger.warning("recon: %s failed: %s", scope_target.value, exc)
            recon_failures.append(
                {"target": scope_target.value, "port": 0, "category": "recon", "findings": [], "error": str(exc)}
            )
            continue
        logger.info("recon: %s -> %d open port(s)", scope_target.value, len(found))
        discovered.extend(found)

    logger.info("recon: done, %d service(s) discovered total", len(discovered))
    return {"discovered_services": discovered, "service_findings": recon_failures}


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


def _build_service_tool_specs(
    executor: ToolExecutor, scope_record: ScopeRecord, service_target: ServiceTarget
) -> list[ToolSpec]:
    target = service_target["target"]
    port = service_target["port"]
    service = service_target["service"]
    product = service_target.get("product")
    version = service_target.get("version")
    scheme = _scheme_for(port)
    is_http = _looks_like_http(port, service)
    specs: list[ToolSpec] = []

    if scope_record.category_allowed(TestCategory.PASSIVE_RECON):
        specs.append(
            ToolSpec(
                name="resolve_dns",
                description=f"Resolve DNS records for {target} (passive nslookup).",
                category=TestCategory.PASSIVE_RECON.value,
                handler=lambda: _passive_recon_text(executor, target),
            )
        )

    if scope_record.category_allowed(TestCategory.SERVICE_ENUM):
        specs.append(
            ToolSpec(
                name="enumerate_service",
                description=f"Run nmap's default scripts (-sC) against {target}:{port} for deeper fingerprinting.",
                category=TestCategory.SERVICE_ENUM.value,
                handler=lambda: nmap.enumerate_service(executor, target, port),
            )
        )

    if scope_record.category_allowed(TestCategory.VULN_SCAN):
        specs.append(
            ToolSpec(
                name="scan_vulnerabilities",
                description=f"Run nmap's `vuln` NSE script category against {target}:{port} (known-CVE matching).",
                category=TestCategory.VULN_SCAN.value,
                handler=lambda: nmap.scan_vulnerabilities(executor, target, port),
            )
        )
        if product and version:
            specs.append(
                ToolSpec(
                    name="lookup_known_cves",
                    description=(
                        f"Look up published CVEs for the detected version "
                        f"'{product} {version}' in the NVD database (advisory; may include false positives)."
                    ),
                    category=TestCategory.VULN_SCAN.value,
                    handler=lambda: _cve_lookup_text(product, version),
                )
            )
        if is_http:
            specs.append(
                ToolSpec(
                    name="scan_web_templates",
                    description=(
                        f"Run nuclei's default (non-intrusive) templates against {scheme}://{target}:{port}/ "
                        "to detect known CVEs, misconfigurations and exposed files/panels."
                    ),
                    category=TestCategory.VULN_SCAN.value,
                    handler=lambda: _nuclei_text(executor, target, port, scheme),
                )
            )
            specs.append(
                ToolSpec(
                    name="scan_web_server",
                    description=f"Run Nikto against {scheme}://{target}:{port}/ for known web-server issues.",
                    category=TestCategory.VULN_SCAN.value,
                    handler=lambda: _nikto_text(executor, target, port),
                )
            )
        if port in _HTTPS_PORTS:
            specs.append(
                ToolSpec(
                    name="scan_tls",
                    description=(
                        f"Assess the TLS configuration on {target}:{port} (weak protocols/ciphers, "
                        "certificate problems) with sslscan."
                    ),
                    category=TestCategory.VULN_SCAN.value,
                    handler=lambda: _tls_text(executor, target, port),
                )
            )

    if scope_record.category_allowed(TestCategory.WEBAPP_TEST) and is_http:
        specs.append(
            ToolSpec(
                name="probe_http",
                description=f"Fetch headers/title via a passive GET to {scheme}://{target}:{port}/.",
                category=TestCategory.WEBAPP_TEST.value,
                handler=lambda: _probe_http_text(executor, target, port, scheme),
            )
        )
        specs.append(
            ToolSpec(
                name="check_security_headers",
                description=(
                    f"Fetch {scheme}://{target}:{port}/ and report missing security headers, "
                    "insecure cookie flags and version disclosure."
                ),
                category=TestCategory.WEBAPP_TEST.value,
                handler=lambda: _security_headers_text(executor, target, port, scheme),
            )
        )

    if scope_record.category_allowed(TestCategory.CONTENT_DISCOVERY) and is_http:
        specs.append(
            ToolSpec(
                name="discover_content",
                description=(
                    f"Brute-force a small wordlist of common paths against {scheme}://{target}:{port}/ "
                    "(directory/file discovery; noisier than a single probe)."
                ),
                category=TestCategory.CONTENT_DISCOVERY.value,
                handler=lambda: _content_discovery_text(executor, target, port, scheme),
            )
        )

    return specs


async def _probe_http_text(executor: ToolExecutor, target: str, port: int, scheme: str) -> str:
    result = await curl.probe(executor, target, port, scheme=scheme)
    lines = [f"url: {result.url}"]
    if result.status_line:
        lines.append(f"status: {result.status_line}")
    if result.server_header:
        lines.append(f"server: {result.server_header}")
    if result.title:
        lines.append(f"title: {result.title}")
    lines.append("raw headers:")
    lines.append(result.raw_headers)
    return "\n".join(lines)


async def _security_headers_text(executor: ToolExecutor, target: str, port: int, scheme: str) -> str:
    result = await curl.probe(executor, target, port, scheme=scheme)
    issues = http_headers.analyze(result.raw_headers, is_https=(scheme == "https"))
    if not issues:
        return f"No security-header issues found on {result.url}."
    lines = [f"Security-header findings for {result.url}:"]
    lines.extend(f"- [{issue.severity.value}] {issue.summary}" for issue in issues)
    return "\n".join(lines)


async def _nuclei_text(executor: ToolExecutor, target: str, port: int, scheme: str) -> str:
    results = await nuclei.scan(executor, target, port, scheme=scheme)
    if not results:
        return f"nuclei: no templates matched on {scheme}://{target}:{port}/."
    lines = [f"nuclei matches on {scheme}://{target}:{port}/:"]
    for r in results:
        cve = f" {', '.join(r.cve_ids)}" if r.cve_ids else ""
        cvss = f" cvss={r.cvss_score}" if r.cvss_score is not None else ""
        lines.append(f"- [{r.severity}] {r.name} ({r.template_id}){cve}{cvss} @ {r.matched_at}")
    return "\n".join(lines)


async def _nikto_text(executor: ToolExecutor, target: str, port: int) -> str:
    items = await nikto.scan(executor, target, port)
    if not items:
        return f"nikto: no items reported for {target}:{port}."
    lines = [f"nikto items for {target}:{port}:"]
    lines.extend(f"- {item.description}" + (f" ({item.uri})" if item.uri else "") for item in items)
    return "\n".join(lines)


async def _tls_text(executor: ToolExecutor, target: str, port: int) -> str:
    result = await tls.scan(executor, target, port)
    if not result.has_issues:
        return f"TLS configuration on {target}:{port} looks clean (no weak protocols/ciphers/cert issues)."
    lines = [f"TLS issues on {target}:{port}:"]
    for label, values in (
        ("weak protocols", result.weak_protocols),
        ("weak ciphers", result.weak_ciphers),
        ("certificate", result.certificate_issues),
    ):
        for value in values:
            lines.append(f"- {label}: {value}")
    return "\n".join(lines)


async def _content_discovery_text(executor: ToolExecutor, target: str, port: int, scheme: str) -> str:
    found = await content_discovery.scan(executor, target, port, scheme=scheme)
    if not found:
        return f"content discovery: no listed paths responded on {scheme}://{target}:{port}/."
    lines = [f"Discovered paths on {scheme}://{target}:{port}/:"]
    lines.extend(f"- /{p.path} -> {p.status} ({p.length} bytes)" for p in found)
    return "\n".join(lines)


async def _cve_lookup_text(product: str, version: str) -> str:
    matches = await cve_lookup.lookup(product, version)
    if not matches:
        return f"No NVD CVEs matched '{product} {version}'."
    lines = [f"NVD CVEs associated with '{product} {version}' (advisory -- verify before acting):"]
    for m in matches:
        score = f" cvss={m.cvss_score}" if m.cvss_score is not None else ""
        sev = f" [{m.severity}]" if m.severity else ""
        lines.append(f"- {m.cve_id}{sev}{score}: {m.description[:160]}")
    return "\n".join(lines)


async def _passive_recon_text(executor: ToolExecutor, target: str) -> str:
    result = await passive_recon.resolve_dns(executor, target)
    if not result.addresses:
        return f"DNS: no addresses resolved for {target}."
    return f"DNS addresses for {target}: {', '.join(result.addresses)}"


async def _run_reasoning(
    agent: ServiceTesterAgent, target: str, port: int, service: str | None, tool_specs: list[ToolSpec]
) -> ServiceFinding:
    try:
        findings = await agent.run(target, port, service, tool_specs)
        logger.info("[%s:%d] llm_reasoning: %d finding(s)", target, port, len(findings))
        return {"target": target, "port": port, "category": "llm_reasoning", "findings": findings, "error": None}
    except Exception as exc:  # noqa: BLE001 -- LM Studio down/etc must fail closed for this branch only
        logger.warning("[%s:%d] llm_reasoning failed: %s", target, port, exc)
        return {"target": target, "port": port, "category": "llm_reasoning", "findings": [], "error": str(exc)}


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

    tool_specs = _build_service_tool_specs(executor, scope_record, svc)
    if not tool_specs:
        logger.info("test_service: [%s:%d] no authorized categories for this service, skipping", target, port)
        return {"service_findings": []}

    agent = ServiceTesterAgent(agent_name="service_tester", llm_client=state["llm_client"])
    result = await _run_reasoning(agent, target, port, service, tool_specs)
    return {"service_findings": [result]}


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
