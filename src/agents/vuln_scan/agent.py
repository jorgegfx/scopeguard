"""Known-CVE-matching sub-agent, via nmap's `vuln` NSE script category.
Detection/enumeration only -- explicitly not active exploitation. See
CLAUDE.md ("treat active exploitation modules as a distinct,
explicitly-opt-in, more heavily gated category").
"""

from __future__ import annotations

import re

from agents.base import Agent
from orchestrator.state import Finding, Severity
from tools import nmap
from tools.base import ToolExecutor

# nmap's vuln scripts print a scan header even when nothing is found --
# only surface a finding when a script actually flagged something.
_VULN_INDICATOR = re.compile(r"VULNERABLE|CVE-\d{4}-\d+", re.IGNORECASE)
_CVE_ID = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


class VulnScanAgent(Agent):
    async def run(self, executor: ToolExecutor, target: str, port: int, service: str | None) -> list[Finding]:
        raw_output = await nmap.scan_vulnerabilities(executor, target, port)

        if not _VULN_INDICATOR.search(raw_output):
            return []

        cve_ids = sorted({m.upper() for m in _CVE_ID.findall(raw_output)})
        title = f"nmap vuln script findings on port {port}"
        if service:
            title += f" ({service})"

        return [
            Finding(
                title=title,
                severity=Severity.MEDIUM,
                description=(
                    f"nmap's `vuln` script category flagged something against "
                    f"{target}:{port}. This is unfiltered NSE output, not a "
                    "confirmed/exploited vulnerability -- review before acting on it."
                ),
                evidence=raw_output,
                cve_ids=cve_ids,
            )
        ]
