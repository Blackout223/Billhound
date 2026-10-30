"""Reads an AWS Cost and Usage Report (CUR) export into simple Python dictionaries.

Supported formats: .csv, .csv.gz (how AWS delivers CSV exports) and .parquet.
"""

import csv
import gzip
import json
from datetime import date, datetime

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

# Read if present. Single-account exports may leave it out.
ACCOUNT_COLUMN = "line_item_usage_account_id"

# What an allowlist file may contain. Each key is a list of things you expect to see.
ALLOWLIST_KEYS = ("regions", "services", "instance_types", "accounts")


def _read_raw_rows(path):
    """Return (column names, list of raw row dictionaries) for any supported format."""
    path = str(path)
    if path.endswith(".parquet"):
        try:
            import pyarrow.parquet as pq  # optional: only needed for Parquet files
        except ImportError:
            raise ValueError("Reading Parquet files needs pyarrow. Run: pip install pyarrow") from None
        table = pq.read_table(path)
        return table.column_names, table.to_pylist()

    # gzip.open and open take the same arguments, so pick one and read the same way.
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        return reader.fieldnames or [], list(reader)


def _text(value):
    """Parquet gives None for empty cells and CSV gives "", so treat both the same."""
    return str(value).strip() if value is not None else ""


def _to_date(value):
    """CSV dates are text like "2026-09-01T00:00:00Z"; Parquet dates are datetime objects."""
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(_text(value)[:10])


def load_billing_csv(path):
    """Return a list of billing rows, each one a small dictionary."""
    columns, raw_rows = _read_raw_rows(path)

    missing = [c for c in REQUIRED_COLUMNS if c not in columns]
    if missing:
        raise ValueError(f"{path} is missing columns: {', '.join(missing)}")

    rows = []
    # Line 1 is the header, so data starts on line 2.
    for line_number, raw in enumerate(raw_rows, start=2):
        try:
            rows.append({
                "date": _to_date(raw["line_item_usage_start_date"]),
                "account": _text(raw.get(ACCOUNT_COLUMN)) or "unknown",
                "service": _text(raw["line_item_product_code"]),
                "region": _text(raw["product_region_code"]) or "global",
                "usage_type": _text(raw["line_item_usage_type"]),
                "instance_type": _text(raw["product_instance_type"]),
                "cost": float(raw["line_item_unblended_cost"] or 0),
            })
        except (ValueError, TypeError):
            print(f"Warning: skipping line {line_number}, it has a bad date or cost")
    return rows


def load_allowlist(path):
    """Read a JSON allowlist of regions, services, instance types and accounts you expect."""
    with open(path, encoding="utf-8") as allow_file:
        data = json.load(allow_file)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    unknown = [key for key in data if key not in ALLOWLIST_KEYS]
    if unknown:
        raise ValueError(f"{path} has unknown keys: {', '.join(unknown)}. "
                         f"Allowed keys: {', '.join(ALLOWLIST_KEYS)}")
    return {key: set(data.get(key, [])) for key in ALLOWLIST_KEYS}
