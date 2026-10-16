"""Command-line entry point.

Example:
    python costcanary.py sample_data/compromised_month.csv --markdown report.md
"""

import argparse
import sys

from canary.loader import load_billing_csv
from canary.report import print_report, write_json, write_markdown
from canary.rules import run_all_rules


def parse_args():
    parser = argparse.ArgumentParser(
        description="Find signs of a cloud breach in an AWS Cost and Usage Report CSV.")
    parser.add_argument("csv_file", help="path to the billing CSV export")
    parser.add_argument("--recent-days", type=int, default=7,
                        help="how many of the latest days to check (default: 7)")
    parser.add_argument("--multiplier", type=float, default=3.0,
                        help="how many times normal spend counts as a spike (default: 3)")
    parser.add_argument("--min-cost", type=float, default=10.0,
                        help="ignore spikes smaller than this many dollars per day (default: 10)")
    parser.add_argument("--markdown", metavar="FILE",
                        help="also save the report as a Markdown file")
    parser.add_argument("--json", metavar="FILE",
                        help="also save the findings as a JSON file")
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        rows = load_billing_csv(args.csv_file)
        findings = run_all_rules(rows, args.recent_days, args.multiplier, args.min_cost)
    except (OSError, ValueError) as error:
        print(f"Error: {error}")
        return 2

    print_report(findings, args.csv_file)
    if args.markdown:
        write_markdown(findings, args.csv_file, args.markdown)
    if args.json:
        write_json(findings, args.csv_file, args.json)

    # Exit code 1 when anything HIGH is found, so scripts and CI pipelines can react.
    return 1 if any(f["severity"] == "HIGH" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
