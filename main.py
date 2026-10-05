# Main entry point. Loads an AD snapshot, runs the checks, and builds the HTML report.

import argparse
from datetime import datetime, timezone

from src.loader import load_snapshot
from src.report import render_report
from src.rules import audit_snapshot


def get_args():
    parser = argparse.ArgumentParser(
        description="AccessLens - Active Directory privilege and account audit"
    )
    parser.add_argument(
        "--input",
        default="data/sample_ad.json",
        help="JSON snapshot to scan",
    )
    parser.add_argument(
        "--output",
        default="reports/accesslens_report.html",
        help="Where to save the HTML report",
    )
    parser.add_argument(
        "--stale-days",
        type=int,
        default=90,
        help="How many inactive days count as stale",
    )
    return parser.parse_args()


def main():
    args = get_args()
    data = load_snapshot(args.input)

    findings = audit_snapshot(
        data,
        stale_days=args.stale_days,
        now=datetime.now(timezone.utc),
    )

    render_report(data, findings, args.output)

    print("\nAccessLens")
    print("=" * 60)
    print(f"Input: {args.input}")
    print(f"Users: {len(data['users'])}")
    print(f"Groups: {len(data['groups'])}")
    print(f"Findings: {len(findings)}")
    print("-" * 60)

    for item in findings:
        print(
            f"[{item['severity']:<8}] "
            f"{item['rule_id']} | "
            f"{item['account']} | "
            f"{item['title']}"
        )

    print("-" * 60)
    print(f"Report saved to: {args.output}\n")


if __name__ == "__main__":
    main()
