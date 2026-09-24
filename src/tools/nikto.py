"""Nikto web-server scanner wrapper.

Flags known web-server issues (dated software, risky default files, missing
hardening). Detection/enumeration only. Largely redundant once nuclei is in
place, but useful against older servers nuclei's templates cover less well.
Runs under VULN_SCAN. Output parsed from Nikto's XML.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass

from scope.models import TestCategory
from tools.base import ToolExecutor

NIKTO_TIMEOUT_SECONDS = 1200.0


@dataclass
class NiktoItem:
    description: str
    uri: str | None
    osvdb_id: str | None


async def scan(executor: ToolExecutor, target: str, port: int) -> list[NiktoItem]:
    result = await executor.run(
        target=target,
        category=TestCategory.VULN_SCAN,
        command=["nikto", "-host", target, "-port", str(port), "-Format", "xml", "-output", "-"],
        timeout=NIKTO_TIMEOUT_SECONDS,
    )
    return _parse_nikto_xml(result.stdout)


def _parse_nikto_xml(xml_text: str) -> list[NiktoItem]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    items: list[NiktoItem] = []
    for item in root.iter("item"):
        description = (item.findtext("description") or "").strip()
        if not description:
            continue
        uri = item.findtext("uri")
        items.append(
            NiktoItem(
                description=description,
                uri=uri.strip() if uri else None,
                osvdb_id=item.get("osvdbid") or None,
            )
        )
    return items
