from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True, slots=True)
class Finding:
    severity: str
    code: str
    path: str
    line: int | None
    message: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class InspectReport:
    root: str
    skill_name: str
    verdict: str
    findings: list[Finding]
    file_count: int
    content_sha256: str
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict[str, object]:
        return {
            "root": self.root,
            "skill_name": self.skill_name,
            "verdict": self.verdict,
            "findings": [item.to_dict() for item in self.findings],
            "file_count": self.file_count,
            "content_sha256": self.content_sha256,
            "generated_at": self.generated_at,
        }


@dataclass(frozen=True, slots=True)
class InstallReceipt:
    receipt_id: str
    installed_path: str
    override_review: bool
    report: InspectReport
    source_content_sha256: str = ""
    installed_content_sha256: str = ""
    recorded_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict[str, object]:
        return {
            "receipt_id": self.receipt_id,
            "installed_path": self.installed_path,
            "override_review": self.override_review,
            "source_content_sha256": self.source_content_sha256 or self.report.content_sha256,
            "installed_content_sha256": self.installed_content_sha256,
            "recorded_at": self.recorded_at,
            "report": self.report.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class VerificationResult:
    report: InspectReport
    receipt: InstallReceipt | None
    verified: bool
    reasons: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "verified": self.verified,
            "reasons": self.reasons,
            "report": self.report.to_dict(),
            "receipt": self.receipt.to_dict() if self.receipt else None,
        }
