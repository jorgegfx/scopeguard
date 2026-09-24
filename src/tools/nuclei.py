"""nuclei wrapper: templated detection of known CVEs, misconfigurations,
exposed files/panels and default-credential *pages*.

Detection only. nuclei is run with its default (non-intrusive) template set;
this is not exploitation -- see CLAUDE.md ("Keep the default toolset to
discovery/enumeration/known-CVE-matching"). Output is nuclei's own JSONL,
parsed into structured findings rather than passed around as raw text.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from scope.models import TestCategory
from tools.base import ToolExecutor

# nuclei can take a long time on a large template set. Give it a generous
# ceiling like nmap rather than ToolExecutor's 120s curl-tuned default.
NUCLEI_TIMEOUT_SECONDS = 1800.0


@dataclass
class NucleiResult:
    template_id: str
    name: str
    severity: str  # info | low | medium | high | critical (nuclei's own scale)
    description: str | None
    matched_at: str | None
    cve_ids: list[str] = field(default_factory=list)
    cvss_score: float | None = None


async def scan(executor: ToolExecutor, target: str, port: int, scheme: str = "http") -> list[NucleiResult]:
    url = f"{scheme}://{target}:{port}/"
    result = await executor.run(
        target=target,
        category=TestCategory.VULN_SCAN,
        # -jsonl: one JSON object per finding on stdout. -silent/-nc: keep the
        # banner and colour codes out of the machine-readable stream.
        command=["nuclei", "-target", url, "-jsonl", "-silent", "-nc"],
        timeout=NUCLEI_TIMEOUT_SECONDS,
    )
    return _parse_nuclei_jsonl(result.stdout)


def _parse_nuclei_jsonl(raw: str) -> list[NucleiResult]:
    results: list[NucleiResult] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            # A non-JSON line (stray log output) is skipped rather than
            # aborting the whole parse -- one malformed line shouldn't lose
            # every real finding on the other lines.
            continue

        info = obj.get("info") or {}
        classification = info.get("classification") or {}
        cve_ids = [c.upper() for c in (classification.get("cve-id") or []) if c]
        cvss = classification.get("cvss-score")

        results.append(
            NucleiResult(
                template_id=obj.get("template-id") or obj.get("templateID") or "unknown",
                name=info.get("name") or "unnamed template",
                severity=(info.get("severity") or "info").lower(),
                description=info.get("description"),
                matched_at=obj.get("matched-at") or obj.get("matched") or obj.get("host"),
                cve_ids=sorted(set(cve_ids)),
                cvss_score=float(cvss) if isinstance(cvss, (int, float)) else None,
            )
        )
    return results
