"""Command-line interface. Run it with `python billhound.py ...` or, once installed, `billhound ...`.

Example:
    billhound sample_data/compromised_month.csv --markdown report.md
"""

import argparse
import os

from hound import __version__
from hound.loader import load_allowlist, load_billing_csv
from hound.notify import send_webhook
from hound.report import print_report, write_json, write_markdown
from hound.rules import run_all_rules


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="billhound",
        description="Find signs of a cloud breach in an AWS Cost and Usage Report export "
                    "(.csv, .csv.gz or .parquet).")
    parser.add_argument("csv_file", help="path to the billing export")
    parser.add_argument("--recent-days", type=int, default=7,
                        help="how many of the latest days to check (default: 7)")
    parser.add_argument("--multiplier", type=float, default=3.0,
                        help="how many times normal spend counts as a spike (default: 3)")
    parser.add_argument("--min-cost", type=float, default=10.0,
                        help="ignore spikes smaller than this many dollars per day (default: 10)")
    parser.add_argument("--allowlist", metavar="FILE",
                        help="JSON file of regions, services, instance types and accounts you expect")
    parser.add_argument("--markdown", metavar="FILE",
                        help="also save the report as a Markdown file")
    parser.add_argument("--json", metavar="FILE",
                        help="also save the findings as a JSON file")
    # Read from an environment variable by default so the secret URL stays out of shell history.
    parser.add_argument("--webhook", metavar="URL", default=os.environ.get("BILLHOUND_WEBHOOK_URL"),
                        help="post a summary to this Slack-style webhook when there are findings "
                             "(default: the BILLHOUND_WEBHOOK_URL environment variable)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        allow = load_allowlist(args.allowlist) if args.allowlist else None
        rows = load_billing_csv(args.csv_file)
        findings = run_all_rules(rows, args.recent_days, args.multiplier, args.min_cost, allow)
    except (OSError, ValueError) as error:
        print(f"Error: {error}")
        return 2

    print_report(findings, args.csv_file)
    if args.markdown:
        write_markdown(findings, args.csv_file, args.markdown)
    if args.json:
        write_json(findings, args.csv_file, args.json)
    if args.webhook and findings:
        send_webhook(args.webhook, findings, args.csv_file)

    # Exit code 1 when anything HIGH is found, so scripts and CI pipelines can react.
    return 1 if any(f["severity"] == "HIGH" for f in findings) else 0
