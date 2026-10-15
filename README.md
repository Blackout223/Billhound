# CostCanary

**Find signs of a cloud breach hiding in your AWS bill.**

![tests](https://github.com/Blackout223/costcanary/actions/workflows/tests.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

When attackers steal AWS keys, the first sign is often a bill, not a log alert. They use the keys for
crypto-mining on GPU machines in a quiet region, resell access to AI models ("LLMjacking"), or
download data. CostCanary reads an AWS **Cost and Usage Report** and flags the spending patterns
that point to a compromise rather than normal growth.

## Why this exists

**The problem.** Leaked cloud credentials are one of the most common ways AWS accounts get breached.
Keys end up in public GitHub repos, laptop backups, CI logs and phishing kits. When an attacker gets
them, they usually want to make money fast:

- **Cryptojacking:** launching expensive GPU machines to mine cryptocurrency on your bill.
- **LLMjacking:** using your account to call paid AI models, then reselling that access.
- **Data theft:** copying S3 buckets or databases out of AWS.

All three cost money, so all three show up in the bill. That makes the bill one of the few signals
an attacker can't avoid creating.

**The gap.** Finance teams watch the bill but don't know what attacks look like. Security teams know
the attacks but rarely look at the bill. Existing tools don't close that gap:

- **AWS Cost Anomaly Detection** spots unusual *spend*, but it doesn't tell you whether that spend
  looks like an attack. It can also take time to learn what's normal, and a slow, steady miner can
  blend into the baseline.
- **GuardDuty and other threat-detection tools** watch logs and network traffic. They're essential,
  but they cost money per event, aren't enabled everywhere, and can be switched off by an attacker
  with enough access.
- **Cost-optimisation tools** look for waste, not for intruders.

**The solution.** CostCanary reads the billing data you already have and asks a security
question: *does this spending look like an attacker?* It checks for the specific patterns real
attacks leave behind. Each finding is explained in plain English, so an engineer, a finance analyst
or a manager can understand why it matters and what to check.

**Who it's for:**

- Small teams and start-ups without a full security operations centre.
- Cloud and FinOps engineers who want a security view of the bill.
- Security analysts and incident responders checking whether an account was abused.
- Students and learners who want realistic cloud security data to practise on, using the included samples.

## Features

### Detection rules

| Rule | Severity | What it catches | Why attackers cause it |
|---|---|---|---|
| `NEW_REGION` | High | Spend in a region with no previous history | Attackers launch resources in regions nobody monitors, so they run longer before anyone notices. |
| `GPU_INSTANCE` | High | New GPU or ML instance types (p2–p5, g3–g6, trn, inf, dl) | GPUs are the most profitable machines for crypto-mining. |
| `EGRESS_SPIKE` | High | Data-transfer-out costs far above normal for a region | Copying large amounts of data out of AWS is how data is stolen. |
| `NEW_SERVICE` | High / Medium | A service billed for the first time. It's High for abuse-prone services: Bedrock, SageMaker, Lightsail and SES. | Stolen keys are used for AI model access, hidden compute, cheap servers and spam. |
| `SPEND_SPIKE` | Medium | A service's daily spend jumps to several times its normal level | Attackers scale up existing services, for example by launching many more EC2 instances. |

### Tool features

- **Plain-English findings.** Every finding says what happened, how much it cost and why it might be
  an attack, so anyone can act on it.
- **Ranked results.** Findings are sorted by severity and then by cost, so the most urgent and
  expensive issues come first.
- **Tunable sensitivity.** `--recent-days`, `--multiplier` and `--min-cost` let you match the
  thresholds to the size and noise level of your account.
- **Two output formats.** It prints a plain-text terminal report that works anywhere, and can save a
  Markdown report you can paste into a ticket, wiki or pull request.
- **Automation-friendly exit codes.** It returns `0` when the account is clean, `1` for high-severity
  findings and `2` for errors, so you can run it on a schedule or in a CI pipeline and alert on
  the result.
- **Works with real AWS exports.** It reads the standard CUR 2.0 CSV format and ignores the 100+
  columns it doesn't need.
- **No AWS access needed.** It only reads a file, so it needs no credentials, makes no API calls and
  can't change anything in your account. It's safe to run during an incident.
- **No dependencies.** It uses only Python's standard library, so there's nothing to install to
  run it.
- **Sample data included.** A normal month and a compromised month (with crypto-mining, LLMjacking
  and data theft) let you see results within seconds, plus a script to generate more.
- **Tested.** Automated tests cover every rule, including tests that check normal daily variation
  does *not* raise false alarms. GitHub Actions runs them on every push.

## Quick start

No AWS account needed. The repo includes sample data.

```bash
git clone https://github.com/Blackout223/costcanary.git
cd costcanary
python costcanary.py sample_data/compromised_month.csv
```

## Example output

```text
CostCanary report for sample_data/compromised_month.csv
============================================================

[!!] HIGH: New region in use: sa-east-1
     Cost in recent period: $1,497.35
     Spend started in sa-east-1, which had no spend before. Services: AmazonEC2. ...

[!!] HIGH: New GPU instances: p3.8xlarge in sa-east-1
     Cost in recent period: $1,497.35
     GPU machines are the favourite target for crypto-mining with stolen keys. ...

7 finding(s), 5 high severity.
```

See the full [example report](docs/example-report.md).

## Usage

```text
python costcanary.py CSV_FILE [--recent-days 7] [--multiplier 3] [--min-cost 10] [--markdown report.md]
```

| Option | Default | Meaning |
|---|---|---|
| `--recent-days` | 7 | How many of the latest days to check. Earlier days are the "normal" baseline. |
| `--multiplier` | 3 | How many times normal daily spend counts as a spike. |
| `--min-cost` | 10 | Ignore spikes smaller than this many dollars per day. |
| `--markdown` | | Also save the report as a Markdown file. |

**Exit codes:** `0` means nothing high severity, `1` means high-severity findings, and `2` means an error.
That lets you run it on a schedule or in a pipeline and alert on `1`.

### Using your own AWS data

1. In the AWS Billing console, create a **Data Export** (CUR 2.0) delivered to S3 as CSV.
2. Download a file covering at least two weeks.
3. Run CostCanary on it. Real exports have 100+ columns, and only these six are used:
   `line_item_usage_start_date`, `line_item_product_code`, `product_region_code`,
   `line_item_usage_type`, `product_instance_type`, `line_item_unblended_cost`.

> Billing data reveals your account's architecture. Never commit real exports to a public repo.

## How it works

1. **Load:** read the CSV and keep the six useful columns ([`canary/loader.py`](canary/loader.py)).
2. **Split:** the last *N* days are "recent" and everything before is the "baseline".
3. **Detect:** each rule compares recent against baseline ([`canary/rules.py`](canary/rules.py)).
4. **Report:** sort by severity and cost, then print or save ([`canary/report.py`](canary/report.py)).

## Project structure

```text
costcanary/
├── costcanary.py             # command-line entry point
├── canary/
│   ├── loader.py             # reads the billing CSV
│   ├── rules.py              # detection rules
│   └── report.py             # terminal and Markdown output
├── sample_data/              # fake normal and compromised months
├── tools/generate_sample_data.py
├── tests/test_rules.py
└── docs/example-report.md
```

## Running the tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

## Roadmap

- [ ] Read billing data straight from AWS with `boto3` (Cost Explorer API)
- [ ] Send alerts to Slack or email
- [ ] Map findings to MITRE ATT&CK (e.g. T1496 Resource Hijacking)
- [ ] Support Azure and Google Cloud billing exports
- [ ] Run daily as an AWS Lambda function

## Limitations

- It finds *patterns*, not proof. A new region might be a legitimate project, so every finding needs a human check.
- It needs at least a week or two of normal history to compare against.
- AWS billing data can arrive up to 24 hours late, so it complements real-time tools like GuardDuty and doesn't replace them.

## AI disclosure

This project was built with the help of AI. **Claude** (Anthropic) suggested the original idea and
wrote the first version of the code, the sample data, the tests and this documentation. I reviewed
and tested it, I'm learning how every part works, and I'm extending it myself as my Python skills
grow (see the Roadmap). All code is checked by the automated tests in `tests/`.

AI-assisted code can contain mistakes. Please review it before relying on it, and
[open an issue](https://github.com/Blackout223/costcanary/issues) if you find one.

## Usage guidelines

- **Only analyse billing data you're authorised to access.** Use your own accounts, or ones your employer or client has given you permission to review.
- **Treat findings as leads, not proof.** Each finding needs a human check before anyone acts on it. A new region or a GPU instance can be a legitimate project.
- **Keep billing data private.** Exports reveal your architecture and spending. Never commit them to Git, paste them into public issues, or upload them to AI tools your organisation hasn't approved.
- **Use it alongside your existing security tools, not instead of them.** Billing data can arrive up to a day late, so keep real-time detection such as GuardDuty and CloudTrail alerts in place.
- **Run it read-only.** The tool only reads files. If you later connect it to AWS, give it a read-only role (for example `ce:GetCostAndUsage`) and never use administrator or root keys.
- **Tune it for your account.** The default thresholds (`--multiplier 3`, `--min-cost 10`) suit small accounts. Raise them if you get too many false alarms.
- **No warranty.** This is a portfolio and learning project, provided as is under the MIT License. Test it on sample data before using it on anything important.

## Author

**Blackout**: cybersecurity professional moving into cloud security.
[GitHub](https://github.com/Blackout223)

## License

MIT. See [LICENSE](LICENSE).
