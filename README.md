# BillHound

[![tests](https://github.com/Blackout223/billhound/actions/workflows/tests.yml/badge.svg)](https://github.com/Blackout223/billhound/actions/workflows/tests.yml)
[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg)](https://github.com/RichardLitt/standard-readme)

Detect signs of AWS compromise (crypto-mining, LLMjacking, data theft) hidden in your cloud bill.

- Flags new regions, GPU instances, abuse-prone services, disabled security logging, spend spikes and data egress spikes.
- Ranks findings by severity and cost, with a plain-English reason for each.
- Reads AWS Cost and Usage Report (CUR 2.0) CSV files and needs no AWS credentials.
- Saves Markdown or JSON reports, and exits with code 1 on high-severity findings for use in scripts and CI.

## Table of Contents

- [Why billing data](#why-billing-data)
- [Detection rules](#detection-rules)
- [Example output](#example-output)
- [Design decisions](#design-decisions)
- [Limitations](#limitations)
- [Install](#install)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Why billing data

CloudTrail and GuardDuty are the main ways to spot a compromised AWS account, but an attacker with enough access can turn them off. They can't turn off the bill. Whatever they run, whether that's GPU instances for mining, Bedrock for LLMjacking or big downloads out of S3, shows up as cost.

The bill is also something most companies already export and almost nobody reads with security in mind. BillHound is meant to sit alongside real-time detection, not replace it.

## Detection rules

Each run splits the data into a baseline (everything before the last 7 days) and a recent period (the last 7 days), then compares the two. All the rules are in [`hound/rules.py`](hound/rules.py).

| Rule | What it looks for | Severity | MITRE ATT&CK | Common false positives |
|---|---|---|---|---|
| `NEW_REGION` | Spend in a region that had none in the baseline | HIGH | [T1535](https://attack.mitre.org/techniques/T1535/) Unused/Unsupported Cloud Regions | A team expanding into a new region |
| `NEW_SERVICE` | A service billed for the first time. HIGH if it's one attackers commonly abuse (Bedrock, SageMaker, Lightsail, SES, Systems Manager, Route 53, ECS), MEDIUM otherwise | HIGH / MEDIUM | [T1496.004](https://attack.mitre.org/techniques/T1496/004/) Cloud Service Hijacking | Someone trying out a new service |
| `GPU_INSTANCE` | A GPU or ML instance type (p, g, trn, inf, dl families) not seen in the baseline | HIGH | [T1496.001](https://attack.mitre.org/techniques/T1496/001/) Compute Hijacking | ML or data science work |
| `SECURITY_SERVICE_STOPPED` | CloudTrail, GuardDuty, Config or Security Hub was billed before but not in the last 2 days | HIGH | [T1562.008](https://attack.mitre.org/techniques/T1562/008/) Disable or Modify Cloud Logs, [T1562.001](https://attack.mitre.org/techniques/T1562/001/) Disable or Modify Tools | Free tier usage, or a service moved to another account |
| `SPEND_SPIKE` | A service's daily spend reaching 3x its baseline daily average and at least $10 | MEDIUM | [T1496](https://attack.mitre.org/techniques/T1496/) Resource Hijacking | Load tests, migrations, month-end batch jobs |
| `EGRESS_SPIKE` | Data transfer out of a region reaching 3x its normal daily cost and at least $10, or appearing for the first time | HIGH | [T1530](https://attack.mitre.org/techniques/T1530/) Data from Cloud Storage | Backups to another provider, a big release download |

The 3x multiplier, $10 minimum and 7-day window can all be changed with command line options. The $10 minimum is there so a service going from $0.01 to $0.05 a day doesn't raise an alert.

Findings are sorted by severity, then by cost, so the most expensive high-severity problems come first.

## Example output

Running it against the included sample data, which simulates an account where stolen keys were used for mining, LLMjacking and data theft:

```
$ python billhound.py sample_data/compromised_month.csv

[!!] HIGH: New GPU instances: p3.8xlarge in sa-east-1
     Cost in recent period: $1,497.35
     GPU machines are the favourite target for crypto-mining with stolen keys. Confirm a team launched these on purpose.

[!!] HIGH: New service in use: AmazonBedrock
     Cost in recent period: $526.68
     AmazonBedrock has never been billed before. Watch out: LLM access is resold by attackers ('LLMjacking').

[!!] HIGH: Security service went silent: AWSCloudTrail
     Cost in recent period: $0.00
     AWSCloudTrail (audit logging) was billed before but not in the last 2 days. Attackers switch off logging and detection to hide their activity. Check it is still enabled.
```

The full report is in [docs/example-report.md](docs/example-report.md).

## Design decisions

- It reads CUR CSV exports rather than calling the Cost Explorer API. That means it needs no AWS credentials, so it can't be used to change anything in an account, and you can run it on an export someone sends you.
- It uses only the Python standard library, so there's nothing to install and no third-party packages to trust.
- It compares the account against its own history rather than fixed limits. $500 a day on EC2 is normal for some accounts and a major incident for others.
- It exits with code 1 when there's a HIGH finding, so it can be run on a schedule or in a CI pipeline and fail the job.

## Limitations

- Billing data can be up to 24 hours behind, so this won't catch something in real time.
- It needs at least one to two weeks of history to build a baseline.
- A careful attacker who stays in regions and services the account already uses, and keeps spend low, won't trigger the rules.
- Every finding is a lead to investigate, not proof of compromise.

## Install

Requires [Python](https://www.python.org/downloads/) 3.10 or newer. There are no other dependencies.

```bash
git clone https://github.com/Blackout223/billhound.git
cd billhound
```

## Usage

### CLI

```bash
# Try it on the included sample data
python billhound.py sample_data/compromised_month.csv

# Check your own CUR export and save a Markdown report
python billhound.py path/to/cur-export.csv --markdown report.md

# Save findings as JSON for a SIEM, Slack bot or dashboard
python billhound.py path/to/cur-export.csv --json report.json

# List all options
python billhound.py --help
```

See the [usage guidelines](docs/guidelines.md) for options, exit codes, limitations and responsible use.

## Contributing

Questions and bug reports are welcome in [GitHub issues](https://github.com/Blackout223/billhound/issues).
Pull requests are accepted. Please make sure `python -m pytest` passes and add a test for any new detection rule.

## License

[MIT](LICENSE) © Blackout
