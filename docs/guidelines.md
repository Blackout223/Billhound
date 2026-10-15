# Usage guidelines

## Responsible use

- Only analyse billing data you are authorised to access.
- Treat findings as leads, not proof. A new region or GPU instance can be a legitimate project.
- Keep billing exports private. Do not commit them to Git or paste them into public issues.
- Use CostCanary alongside real-time detection such as GuardDuty and CloudTrail alerts, not instead of it.

## Using your own AWS data

1. In the AWS Billing console, create a Data Export (CUR 2.0) delivered to S3 as CSV.
2. Download an export covering at least two weeks.
3. Run `python costcanary.py path/to/export.csv`.

Only these columns are read: `line_item_usage_start_date`, `line_item_product_code`,
`product_region_code`, `line_item_usage_type`, `product_instance_type`, `line_item_unblended_cost`.

## Options

| Option | Default | Meaning |
|---|---|---|
| `--recent-days` | 7 | Number of latest days to check. Earlier days form the baseline. |
| `--multiplier` | 3 | How many times normal daily spend counts as a spike. |
| `--min-cost` | 10 | Ignore spikes below this many dollars per day. |
| `--markdown FILE` | none | Also save the report as Markdown. |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No high-severity findings |
| 1 | High-severity findings |
| 2 | Error, such as a missing file or columns |

## Limitations

- Billing data can arrive up to 24 hours late.
- At least one to two weeks of history is needed for a baseline.

## Running the tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

## AI disclosure

The first version of this project was written with Claude (Anthropic) and reviewed and tested by the author.
