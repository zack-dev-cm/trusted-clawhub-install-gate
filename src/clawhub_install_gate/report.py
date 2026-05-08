from __future__ import annotations

from .models import InspectReport


def render_text_report(report: InspectReport) -> str:
    lines = [
        f"Trusted ClawHub Install Gate report for {report.root}",
        f"skill={report.skill_name} verdict={report.verdict} findings={len(report.findings)} files={report.file_count}",
        f"content_sha256={report.content_sha256}",
    ]
    if not report.findings:
        lines.append("No blocking issues or warnings found in the reviewed artifact.")
        lines.append("This is not a guarantee of safety; review provenance before installation.")
        return "\n".join(lines)

    for finding in report.findings:
        location = finding.path
        if finding.line is not None:
            location = f"{location}:{finding.line}"
        lines.append(f"- {finding.severity} {finding.code} {location}: {finding.message}")
    return "\n".join(lines)

