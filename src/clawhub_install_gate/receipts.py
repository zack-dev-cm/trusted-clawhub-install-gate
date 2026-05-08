from __future__ import annotations

import json
import os
from pathlib import Path
import uuid

from .models import Finding, InstallReceipt, InspectReport


def gate_home() -> Path:
    env_value = os.environ.get("CLAW_INSTALL_GATE_HOME", "").strip()
    if env_value:
        return Path(env_value).expanduser().resolve()
    return Path.home() / ".local" / "share" / "clawhub-install-gate"


def receipts_dir() -> Path:
    return gate_home() / "receipts"


def write_receipt(
    report: InspectReport,
    installed_path: Path,
    *,
    override_review: bool,
    installed_content_sha256: str,
) -> InstallReceipt:
    receipt = InstallReceipt(
        receipt_id=uuid.uuid4().hex,
        installed_path=str(installed_path),
        override_review=override_review,
        report=report,
        source_content_sha256=report.content_sha256,
        installed_content_sha256=installed_content_sha256,
    )
    root = receipts_dir()
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{receipt.receipt_id}.json"
    path.write_text(json.dumps(receipt.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return receipt


def load_receipt(path: str | Path) -> InstallReceipt:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    report_payload = payload["report"]
    report = InspectReport(
        root=report_payload["root"],
        skill_name=report_payload["skill_name"],
        verdict=report_payload["verdict"],
        findings=[Finding(**finding) for finding in report_payload["findings"]],
        file_count=report_payload["file_count"],
        content_sha256=report_payload["content_sha256"],
        generated_at=report_payload["generated_at"],
    )
    return InstallReceipt(
        receipt_id=payload["receipt_id"],
        installed_path=payload["installed_path"],
        override_review=payload["override_review"],
        report=report,
        source_content_sha256=payload.get("source_content_sha256", report.content_sha256),
        installed_content_sha256=payload.get("installed_content_sha256", report.content_sha256),
        recorded_at=payload["recorded_at"],
    )


def find_receipt_for_installed_path(installed_path: str | Path) -> InstallReceipt | None:
    target = _canonical_path(installed_path)
    root = receipts_dir()
    if not root.exists():
        return None

    receipt_paths = sorted(root.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    for receipt_path in receipt_paths:
        try:
            receipt = load_receipt(receipt_path)
        except (OSError, KeyError, TypeError, json.JSONDecodeError):
            continue
        if _canonical_path(receipt.installed_path) == target:
            return receipt
    return None


def _canonical_path(path: str | Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)
