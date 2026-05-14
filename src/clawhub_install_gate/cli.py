from __future__ import annotations

import argparse
import json
import sys

from .install import install_target, verify_installed_skill
from .report import render_text_report
from .scanner import InspectError, PolicyError, inspect_target
from .usage import summarize_usage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Trusted ClawHub Install Gate")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect", help="Inspect a local unpacked skill directory")
    inspect_parser.add_argument("target", help="Local skill directory to inspect")
    inspect_parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    install_parser = subparsers.add_parser("install", help="Inspect and install a local unpacked skill directory")
    install_parser.add_argument("target", help="Local skill directory to install")
    install_parser.add_argument("--dest", required=True, help="Destination skills directory")
    install_parser.add_argument("--allow-review", action="store_true", help="Allow install when verdict is REVIEW")
    install_parser.add_argument("--replace", action="store_true", help="Replace an existing installed skill directory")
    install_parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    verify_parser = subparsers.add_parser("verify", help="Re-inspect an installed skill directory")
    verify_parser.add_argument("target", help="Installed skill directory")
    verify_parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    usage_parser = subparsers.add_parser("usage", help="Summarize install receipts and approved REVIEW usage")
    usage_parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    usage_parser.add_argument("--receipts-dir", help="Override receipts directory for reporting")

    return parser


def _print_json(payload: dict[str, object]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "inspect":
            report = inspect_target(args.target)
            if args.json:
                _print_json(report.to_dict())
            else:
                print(render_text_report(report))
            return 0 if report.verdict == "PASS" else 1

        if args.command == "install":
            report, receipt = install_target(
                args.target,
                destination_root=args.dest,
                allow_review=args.allow_review,
                replace=args.replace,
            )
            if args.json:
                _print_json(
                    {
                        "report": report.to_dict(),
                        "receipt": receipt.to_dict(),
                    }
                )
            else:
                print(render_text_report(report))
                print(f"installed_path={receipt.installed_path}")
                print(f"receipt_id={receipt.receipt_id}")
            return 0

        if args.command == "verify":
            result = verify_installed_skill(args.target)
            if args.json:
                _print_json(result.to_dict())
            else:
                print(render_text_report(result.report))
                print(f"verified={str(result.verified).lower()}")
                if result.receipt is not None:
                    print(f"receipt_id={result.receipt.receipt_id}")
                for reason in result.reasons:
                    print(f"- VERIFY {reason}")
            return 0 if result.verified else 1

        if args.command == "usage":
            summary = summarize_usage(receipts_root=args.receipts_dir)
            if args.json:
                _print_json(summary)
            else:
                print(f"receipts_dir={summary['receipts_dir']}")
                print(f"total_receipts={summary['total_receipts']}")
                print(f"override_review_receipts={summary['override_review_receipts']}")
                for verdict, count in (summary["verdict_counts"] or {}).items():
                    print(f"verdict.{verdict}={count}")
                for receipt in summary["receipts"]:
                    print(
                        "receipt="
                        f"{receipt['receipt_id']} "
                        f"skill={receipt['skill_name']} "
                        f"verdict={receipt['verdict']} "
                        f"override_review={str(receipt['override_review']).lower()} "
                        f"path={receipt['installed_path']}"
                    )
            return 0
    except (InspectError, PolicyError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    parser.error(f"Unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
