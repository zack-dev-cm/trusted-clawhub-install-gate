from __future__ import annotations

from collections import Counter
from pathlib import Path
import json

from .receipts import load_receipt, receipts_dir


def summarize_usage(*, receipts_root: str | Path | None = None) -> dict[str, object]:
    root = Path(receipts_root).expanduser().resolve() if receipts_root is not None else receipts_dir()
    verdicts: Counter[str] = Counter()
    skills: Counter[str] = Counter()
    overrides = 0
    receipts: list[dict[str, object]] = []

    if not root.exists():
        return {
            "receipts_dir": str(root),
            "total_receipts": 0,
            "override_review_receipts": 0,
            "verdict_counts": {},
            "skill_counts": {},
            "receipts": [],
        }

    for receipt_path in sorted(root.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            receipt = load_receipt(receipt_path)
        except (OSError, KeyError, TypeError, json.JSONDecodeError):
            continue
        verdicts[receipt.report.verdict] += 1
        skills[receipt.report.skill_name] += 1
        if receipt.override_review:
            overrides += 1
        receipts.append(
            {
                "receipt_id": receipt.receipt_id,
                "skill_name": receipt.report.skill_name,
                "verdict": receipt.report.verdict,
                "override_review": receipt.override_review,
                "installed_path": receipt.installed_path,
                "recorded_at": receipt.recorded_at,
                "installed_content_sha256": receipt.installed_content_sha256,
            }
        )

    return {
        "receipts_dir": str(root),
        "total_receipts": len(receipts),
        "override_review_receipts": overrides,
        "verdict_counts": dict(sorted(verdicts.items())),
        "skill_counts": dict(sorted(skills.items())),
        "receipts": receipts,
    }
