"""Reads an AWS Cost and Usage Report (CUR) CSV into simple Python dictionaries."""

import csv
from datetime import date

# The CUR 2.0 columns BillHound needs. Real exports have 100+ columns;
# we ignore everything else.
REQUIRED_COLUMNS = [
    "line_item_usage_start_date",
    "line_item_product_code",
    "product_region_code",
    "line_item_usage_type",
    "product_instance_type",
    "line_item_unblended_cost",
]


def load_billing_csv(path):
    """Return a list of billing rows, each one a small dictionary."""
    rows = []
    with open(path, newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)

        missing = [c for c in REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"{path} is missing columns: {', '.join(missing)}")

        # Line 1 is the header, so data starts on line 2.
        for line_number, raw in enumerate(reader, start=2):
            try:
                rows.append({
                    # "2026-09-01T00:00:00Z" -> keep "2026-09-01" and turn it into a date
                    "date": date.fromisoformat(raw["line_item_usage_start_date"][:10]),
                    "service": raw["line_item_product_code"].strip(),
                    "region": raw["product_region_code"].strip() or "global",
                    "usage_type": raw["line_item_usage_type"].strip(),
                    "instance_type": raw["product_instance_type"].strip(),
                    "cost": float(raw["line_item_unblended_cost"] or 0),
                })
            except ValueError:
                print(f"Warning: skipping line {line_number}, it has a bad date or cost")
    return rows
