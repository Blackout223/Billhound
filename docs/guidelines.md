# Usage guidelines

## Responsible use

- Only analyse billing data you are authorised to access.
- Treat findings as leads, not proof. A new region or GPU instance can be a legitimate project.
- Keep billing exports private. Do not commit them to Git or paste them into public issues.
- Use BillHound alongside real-time detection such as GuardDuty and CloudTrail alerts, not instead of it.

## Using your own AWS data

1. In the AWS Billing console, create a Data Export (CUR 2.0) delivered to S3.
2. Download an export covering at least two weeks. `.csv`, `.csv.gz` and `.parquet` files all work.
   Parquet needs `pip install pyarrow`.
3. Run `python billhound.py path/to/export.csv.gz`.

Only these columns are read: `line_item_usage_start_date`, `line_item_product_code`,
`product_region_code`, `line_item_usage_type`, `product_instance_type`, `line_item_unblended_cost`.
`line_item_usage_account_id` is also read when present, which turns on the `NEW_ACCOUNT` rule.

## Allowlist

To stop alerts for things you expect, pass a JSON file with `--allowlist`. All four keys are optional:

```json
{
  "regions": ["eu-west-2"],
  "services": ["AmazonSageMaker"],
  "instance_types": ["g5.xlarge"],
  "accounts": ["444455556666"]
}
```

Unknown keys are rejected, so a typo such as `"region"` fails loudly instead of being ignored.

## Webhook alerts

`--webhook URL` posts a short summary when there are findings. It sends `{"text": "..."}`, the format
Slack incoming webhooks accept. Other chat tools may need a different format.

- Treat the URL as a secret. Set it in the `BILLHOUND_WEBHOOK_URL` environment variable instead of
  typing it on the command line.
- Only `https://` URLs are used.
- If the message fails to send, BillHound prints a warning and still returns the normal exit code.

## Options

| Option | Default | Meaning |
|---|---|---|
| `--recent-days` | 7 | Number of latest days to check. Earlier days form the baseline. |
| `--multiplier` | 3 | How many times normal daily spend counts as a spike. |
| `--min-cost` | 10 | Ignore spikes below this many dollars per day. |
| `--allowlist FILE` | none | JSON file of regions, services, instance types and accounts you expect. |
| `--markdown FILE` | none | Also save the report as Markdown. |
| `--json FILE` | none | Also save the findings as JSON. |
| `--webhook URL` | `BILLHOUND_WEBHOOK_URL` | Post a summary to a Slack-style webhook when there are findings. |
| `--version` | | Print the version. |

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
