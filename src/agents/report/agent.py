"""Rolls findings from every branch into the final report: a Markdown
document (source of truth, easy to review/diff) and a PDF rendered
independently from the same structured findings, for client delivery.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from agents.base import Agent
from agents.report.render import render_markdown, render_pdf
from orchestrator.state import ServiceFinding
from scope.models import ScopeRecord


@dataclass
class ReportPaths:
    markdown_path: Path
    pdf_path: Path


class ReportAgent(Agent):
    async def run(
        self,
        run_id: str,
        scope_record: ScopeRecord,
        service_findings: list[ServiceFinding],
        output_dir: str | Path = "reports",
    ) -> ReportPaths:
        # run_id is the orchestrator's per-invocation ID (state["run_id"]),
        # deliberately not scope_record.run_id -- that's a user-authored
        # label in the scope record itself and can repeat across separate
        # runs of the same authorization, which would collide report files.
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        markdown_path = output_dir / f"{run_id}.md"
        markdown_path.write_text(render_markdown(run_id, scope_record, service_findings), encoding="utf-8")

        pdf_path = render_pdf(run_id, scope_record, service_findings, output_dir / f"{run_id}.pdf")

        return ReportPaths(markdown_path=markdown_path, pdf_path=pdf_path)
