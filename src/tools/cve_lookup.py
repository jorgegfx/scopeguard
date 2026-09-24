"""Map an nmap product/version string to known CVEs via the NVD 2.0 API.

This talks to the National Vulnerability Database, not to the scanned target,
so it does not go through scope.checker -- there is no target traffic to
authorize. It is deliberately kept as a separate egress path from the
scanning tools (different host, different failure mode).

Detection only: it reports what CVEs are publicly associated with a version
string; it does not confirm exploitability. A version-string match can be a
false positive (back-ported fixes, distro patching), so findings are advisory.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

_NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class CveMatch:
    cve_id: str
    description: str
    cvss_score: float | None
    severity: str | None  # NVD's own qualitative rating


async def lookup(
    product: str | None,
    version: str | None,
    *,
    client: httpx.AsyncClient | None = None,
    limit: int = 10,
) -> list[CveMatch]:
    """Query NVD for `product version`. Returns [] when there's nothing to
    search on (recon didn't resolve a product/version) rather than issuing a
    useless wildcard query."""
    if not product or not version:
        return []

    keyword = f"{product} {version}".strip()
    params = {"keywordSearch": keyword, "resultsPerPage": limit}

    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=30.0)
    try:
        response = await client.get(_NVD_ENDPOINT, params=params)
        response.raise_for_status()
        return _parse_nvd_response(response.json())
    finally:
        if owns_client:
            await client.aclose()


def _parse_nvd_response(data: dict) -> list[CveMatch]:
    matches: list[CveMatch] = []
    for entry in data.get("vulnerabilities") or []:
        cve = entry.get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue

        description = ""
        for desc in cve.get("descriptions") or []:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        score, severity = _extract_cvss(cve.get("metrics") or {})
        matches.append(
            CveMatch(cve_id=cve_id, description=description, cvss_score=score, severity=severity)
        )
    return matches


def _extract_cvss(metrics: dict) -> tuple[float | None, str | None]:
    # Prefer the newest CVSS version present.
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        cvss_data = entries[0].get("cvssData") or {}
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or entries[0].get("baseSeverity")
        return (float(score) if isinstance(score, (int, float)) else None, severity)
    return (None, None)
