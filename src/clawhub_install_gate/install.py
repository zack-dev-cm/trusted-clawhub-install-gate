from __future__ import annotations

import shutil
from pathlib import Path

from .models import InspectReport, InstallReceipt, VerificationResult
from .policy import can_install
from .receipts import find_receipt_for_installed_path, write_receipt
from .scanner import PolicyError, compute_manifest_sha256, inspect_target


def install_target(
    target: str,
    *,
    destination_root: str | None = None,
    allow_review: bool = False,
    replace: bool = False,
) -> tuple[InspectReport, InstallReceipt]:
    report = inspect_target(target)
    allowed, message = can_install(report.verdict, allow_review=allow_review)
    if not allowed:
        raise PolicyError(message or "Installation denied by policy.")

    if destination_root is None:
        raise PolicyError("Install destination is required in v0.1. Pass --dest /path/to/workspace/skills.")

    source_root = Path(report.root)
    install_root = Path(destination_root).expanduser().resolve()
    install_root.mkdir(parents=True, exist_ok=True)
    install_path = install_root / source_root.name

    if install_path.exists():
        if not replace:
            raise PolicyError(f"Install destination already exists: {install_path}. Use --replace to overwrite.")
        if install_path.is_dir() and not install_path.is_symlink():
            shutil.rmtree(install_path)
        else:
            install_path.unlink()

    shutil.copytree(source_root, install_path, symlinks=True)
    installed_content_sha256 = compute_manifest_sha256(install_path)
    if installed_content_sha256 != report.content_sha256:
        if install_path.is_dir() and not install_path.is_symlink():
            shutil.rmtree(install_path)
        else:
            install_path.unlink(missing_ok=True)
        raise PolicyError("Installed content hash differs from reviewed source content.")

    receipt = write_receipt(
        report,
        install_path,
        override_review=report.verdict == "REVIEW",
        installed_content_sha256=installed_content_sha256,
    )
    return report, receipt


def verify_installed_skill(target: str) -> VerificationResult:
    report = inspect_target(target)
    receipt = find_receipt_for_installed_path(report.root)
    reasons: list[str] = []

    if receipt is None:
        reasons.append("No matching install receipt found for this installed path.")
        return VerificationResult(report=report, receipt=None, verified=False, reasons=reasons)

    if report.content_sha256 != receipt.installed_content_sha256:
        reasons.append("Installed content hash differs from the receipt.")
    if report.verdict != receipt.report.verdict:
        reasons.append("Current verdict differs from the receipt verdict.")
    if receipt.report.verdict == "REVIEW" and not receipt.override_review:
        reasons.append("Receipt does not record an explicit REVIEW override.")
    if receipt.source_content_sha256 and receipt.source_content_sha256 != receipt.report.content_sha256:
        reasons.append("Receipt source hash differs from the recorded inspection report.")

    return VerificationResult(report=report, receipt=receipt, verified=not reasons, reasons=reasons)
