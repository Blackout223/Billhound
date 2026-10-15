"""Creates two fake billing files in sample_data/ so anyone can try CostCanary.

normal_month.csv       a quiet, healthy account
compromised_month.csv  the same account, but stolen keys are abused in the last 5 days

Run from the project folder:  python tools/generate_sample_data.py
"""

import csv
import random
from datetime import date, timedelta
from pathlib import Path

COLUMNS = [
    "line_item_usage_start_date",
    "line_item_product_code",
    "product_region_code",
    "line_item_usage_type",
    "product_instance_type",
    "line_item_unblended_cost",
]

# (service, region, usage type, instance type, normal daily cost in dollars)
NORMAL_USAGE = [
    ("AmazonEC2", "us-east-1", "BoxUsage:t3.medium", "t3.medium", 24.0),
    ("AmazonEC2", "eu-west-2", "EUW2-BoxUsage:t3.large", "t3.large", 18.0),
    ("AmazonS3", "us-east-1", "TimedStorage-ByteHrs", "", 6.0),
    ("AmazonS3", "us-east-1", "DataTransfer-Out-Bytes", "", 3.0),
    ("AmazonRDS", "us-east-1", "InstanceUsage:db.t3.medium", "db.t3.medium", 15.0),
    ("AWSLambda", "us-east-1", "Lambda-GB-Second", "", 2.0),
    ("AmazonCloudWatch", "us-east-1", "CW:Requests", "", 1.5),
    ("AWSCloudTrail", "global", "PaidEventsRecorded", "", 0.5),
]

# What the attacker adds in the compromised file: (first day number, row)
ATTACK_USAGE = [
    # Crypto-mining on GPU machines in a region the company never uses
    (26, ("AmazonEC2", "sa-east-1", "SAE1-BoxUsage:p3.8xlarge", "p3.8xlarge", 293.0)),
    # LLMjacking: stolen keys used to call AI models
    (27, ("AmazonBedrock", "us-west-2", "USW2-ModelInvocation-InputTokens", "", 140.0)),
    # Data theft: a big download from S3
    (29, ("AmazonS3", "us-east-1", "DataTransfer-Out-Bytes", "", 410.0)),
]


def make_row(day, usage, wobble):
    service, region, usage_type, instance_type, daily_cost = usage
    cost = daily_cost * wobble.uniform(0.85, 1.15)  # real bills vary a little each day
    return [f"{day.isoformat()}T00:00:00Z", service, region, usage_type, instance_type, f"{cost:.4f}"]


def build_month(include_attack):
    wobble = random.Random(42)  # fixed seed: the same "random" numbers every run
    start = date(2026, 9, 1)
    rows = []
    for day_number in range(1, 31):
        day = start + timedelta(days=day_number - 1)
        for usage in NORMAL_USAGE:
            rows.append(make_row(day, usage, wobble))
        if include_attack:
            for first_day, usage in ATTACK_USAGE:
                if day_number >= first_day:
                    rows.append(make_row(day, usage, wobble))
    return rows


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(COLUMNS)
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to {path}")


if __name__ == "__main__":
    out_dir = Path(__file__).resolve().parent.parent / "sample_data"
    out_dir.mkdir(exist_ok=True)
    write_csv(out_dir / "normal_month.csv", build_month(include_attack=False))
    write_csv(out_dir / "compromised_month.csv", build_month(include_attack=True))
