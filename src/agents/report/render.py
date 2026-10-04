"""Renders scan results into a Markdown report and a PDF report.

Both are built directly from structured findings, independently of each
other -- not by converting Markdown to PDF -- so each stays simple and
neither format's quirks leak into the other.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from audit.models import AuditEvent
from orchestrator.state import Finding, ServiceFinding, Severity
from scope.models import ScopeRecord

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


@dataclass(frozen=True)
class ToolInvocation:
    """One distinct (tool, command, target) that actually ran during a scan,
    with how many times it ran. Built from the audit log's command_executed
    events -- the authoritative record of exactly what was invoked -- so the
    report's methodology section can't drift from what the tools really did."""

    tool: str
    command: list[str] = field(hash=False)
    target: str
    count: int

    @property
    def parameters(self) -> str:
        """The arguments passed to the tool (everything after the binary)."""
        return " ".join(self.command[1:])

    @property
    def command_str(self) -> str:
        return " ".join(self.command)


def summarize_tool_usage(events: list[AuditEvent]) -> list[ToolInvocation]:
    """Collapse command_executed audit events into distinct invocations.

    Identical (command, target) pairs are merged with a run count so a scan
    that hit one target with the same command many times reads as one row,
    not hundreds. Order of first appearance is preserved for a stable report.
    """
    grouped: "OrderedDict[tuple[str, tuple[str, ...]], dict]" = OrderedDict()
    for event in events:
        if event.event_type != "command_executed":
            continue
        command = event.payload.get("command")
        if not command:
            continue
        target = event.payload.get("target", "")
        key = (target, tuple(command))
        entry = grouped.get(key)
        if entry is None:
            grouped[key] = {"command": list(command), "target": target, "count": 1}
        else:
            entry["count"] += 1

    invocations: list[ToolInvocation] = []
    for entry in grouped.values():
        command = entry["command"]
        tool = Path(command[0]).name if command else ""
        invocations.append(
            ToolInvocation(tool=tool, command=command, target=entry["target"], count=entry["count"])
        )
    return invocations


def _group_by_severity(
    service_findings: list[ServiceFinding],
) -> dict[Severity, list[tuple[ServiceFinding, Finding]]]:
    grouped: dict[Severity, list[tuple[ServiceFinding, Finding]]] = {s: [] for s in _SEVERITY_ORDER}
    for sf in service_findings:
        for finding in sf.get("findings", []):
            grouped[finding.severity].append((sf, finding))
    return grouped


def render_markdown(
    run_id: str,
    scope_record: ScopeRecord,
    service_findings: list[ServiceFinding],
    tool_invocations: list[ToolInvocation] | None = None,
) -> str:
    by_severity = _group_by_severity(service_findings)
    total = sum(len(items) for items in by_severity.values())

    lines = [
        f"# ScopeGuard Report -- Run {run_id}",
        "",
        f"**Targets:** {', '.join(t.value for t in scope_record.targets)}  ",
        f"**Window:** {scope_record.time_window.starts_at} -> {scope_record.time_window.ends_at}  ",
        f"**Categories tested:** {', '.join(c.value for c in scope_record.allowed_categories)}",
        "",
        f"## Summary ({total} finding{'s' if total != 1 else ''})",
        "",
    ]
    for severity in _SEVERITY_ORDER:
        count = len(by_severity[severity])
        if count:
            lines.append(f"- **{severity.value.upper()}**: {count}")
    lines.append("")

    for severity in _SEVERITY_ORDER:
        items = by_severity[severity]
        if not items:
            continue
        lines.append(f"## {severity.value.upper()} severity")
        lines.append("")
        for sf, finding in items:
            lines.append(f"### {finding.title}")
            lines.append(f"**Target:** {sf['target']}:{sf['port']} ({sf['category']})")
            lines.append("")
            lines.append(finding.description)
            if finding.cve_ids:
                lines.append("")
                lines.append(f"**CVEs:** {', '.join(finding.cve_ids)}")
            if finding.evidence:
                lines.append("")
                lines.append("```")
                lines.append(finding.evidence)
                lines.append("```")
            lines.append("")

    if tool_invocations:
        lines.append("## Tools used")
        lines.append("")
        lines.append("| Tool | Target | Parameters | Runs |")
        lines.append("| --- | --- | --- | --- |")
        for inv in tool_invocations:
            # Escape pipes so a command arg can't break out of the table cell.
            params = f"`{inv.parameters.replace('|', '\\|')}`" if inv.parameters else "_(none)_"
            target = (inv.target or "-").replace("|", "\\|")
            lines.append(f"| {inv.tool} | {target} | {params} | {inv.count} |")
        lines.append("")

    errored = [sf for sf in service_findings if sf.get("error")]
    if errored:
        lines.append("## Test failures")
        lines.append("")
        for sf in errored:
            lines.append(f"- {sf['target']}:{sf['port']} ({sf['category']}): {sf['error']}")
        lines.append("")

    return "\n".join(lines)


def _line(pdf: FPDF, height: float, text: str) -> None:
    # multi_cell's defaults don't reset the cursor to the left margin in
    # this fpdf2 version, which corrupts every following line's available
    # width -- pin new_x/new_y explicitly on every call.
    pdf.multi_cell(0, height, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def render_pdf(
    run_id: str,
    scope_record: ScopeRecord,
    service_findings: list[ServiceFinding],
    output_path: str | Path,
    tool_invocations: list[ToolInvocation] | None = None,
) -> Path:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 18)
    _line(pdf, 10, f"ScopeGuard Report - Run {run_id}")
    pdf.set_font("Helvetica", "", 10)
    _line(pdf, 6, f"Targets: {', '.join(t.value for t in scope_record.targets)}")
    _line(pdf, 6, f"Window: {scope_record.time_window.starts_at} -> {scope_record.time_window.ends_at}")
    pdf.ln(4)

    by_severity = _group_by_severity(service_findings)
    for severity in _SEVERITY_ORDER:
        items = by_severity[severity]
        if not items:
            continue
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, f"{severity.value.upper()} severity", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        for sf, finding in items:
            pdf.set_font("Helvetica", "B", 11)
            _line(pdf, 7, finding.title)
            pdf.set_font("Helvetica", "", 10)
            _line(pdf, 6, f"Target: {sf['target']}:{sf['port']} ({sf['category']})")
            _line(pdf, 6, finding.description)
            if finding.cve_ids:
                _line(pdf, 6, f"CVEs: {', '.join(finding.cve_ids)}")
            pdf.ln(3)

    if tool_invocations:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Tools used", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        for inv in tool_invocations:
            pdf.set_font("Helvetica", "B", 11)
            runs = f" (x{inv.count})" if inv.count > 1 else ""
            _line(pdf, 7, f"{inv.tool} -> {inv.target or '-'}{runs}")
            pdf.set_font("Helvetica", "", 10)
            _line(pdf, 6, f"Parameters: {inv.parameters or '(none)'}")
            pdf.ln(2)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(output_path))
    return output_path
