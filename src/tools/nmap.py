"""nmap subprocess wrapper. Output is parsed into structured findings,
never passed as raw text between agents."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass

from scope.models import TestCategory
from tools.base import ToolExecutor


@dataclass
class OpenPort:
    port: int
    protocol: str
    service: str | None
    product: str | None
    version: str | None


async def scan_target(executor: ToolExecutor, target: str) -> list[OpenPort]:
    result = await executor.run(
        target=target,
        category=TestCategory.PORT_SCAN,
        command=["nmap", "-sV", "-oX", "-", target],
    )
    return _parse_nmap_xml(result.stdout)


async def enumerate_service(executor: ToolExecutor, target: str, port: int) -> str:
    """Default NSE scripts (-sC) against a single port -- deeper fingerprinting
    than recon's initial -sV pass. Returns raw nmap text output as evidence."""
    result = await executor.run(
        target=target,
        category=TestCategory.SERVICE_ENUM,
        command=["nmap", "-p", str(port), "-sC", "-oN", "-", target],
    )
    return result.stdout


async def scan_vulnerabilities(executor: ToolExecutor, target: str, port: int) -> str:
    """nmap's `vuln` NSE script category against a single port -- known-CVE
    matching, not exploitation. Returns raw nmap text output as evidence."""
    result = await executor.run(
        target=target,
        category=TestCategory.VULN_SCAN,
        command=["nmap", "-p", str(port), "--script", "vuln", "-oN", "-", target],
    )
    return result.stdout


def _parse_nmap_xml(xml_text: str) -> list[OpenPort]:
    root = ET.fromstring(xml_text)
    ports: list[OpenPort] = []
    for port_el in root.findall(".//port"):
        state = port_el.find("state")
        if state is None or state.get("state") != "open":
            continue
        service_el = port_el.find("service")
        ports.append(
            OpenPort(
                port=int(port_el.get("portid")),
                protocol=port_el.get("protocol"),
                service=service_el.get("name") if service_el is not None else None,
                product=service_el.get("product") if service_el is not None else None,
                version=service_el.get("version") if service_el is not None else None,
            )
        )
    return ports
