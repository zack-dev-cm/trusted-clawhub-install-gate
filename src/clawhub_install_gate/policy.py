from __future__ import annotations

from .models import Finding


def classify_verdict(findings: list[Finding]) -> str:
    if any(finding.severity == "BLOCK" for finding in findings):
        return "BLOCK"
    if any(finding.severity == "WARNING" for finding in findings):
        return "REVIEW"
    return "PASS"


def can_install(verdict: str, *, allow_review: bool) -> tuple[bool, str | None]:
    if verdict == "BLOCK":
        return False, "Installation denied because the artifact verdict is BLOCK."
    if verdict == "REVIEW" and not allow_review:
        return (
            False,
            "Installation denied because the artifact verdict is REVIEW. Re-run with --allow-review to override.",
        )
    return True, None

