# CostCanary

Detects signs of a compromised AWS account (crypto-mining, LLMjacking, data theft) in AWS billing exports.

## Features

- Flags new regions, new GPU instances, abuse-prone services, spend spikes and data egress spikes.
- Ranks findings by severity and cost, with a plain-English reason for each.
- Reads AWS Cost and Usage Report (CUR 2.0) CSV files and needs no AWS credentials.
- Exits with code 1 on high-severity findings, for use in scripts and CI.

## Install

Requires Python 3.10 or newer. There are no other dependencies.

```bash
git clone https://github.com/Blackout223/costcanary.git
cd costcanary
```

## Usage

```bash
python costcanary.py sample_data/compromised_month.csv
python costcanary.py path/to/cur-export.csv --markdown report.md
```

Run `python costcanary.py --help` to see all options.

## Documentation

- [Usage guidelines](docs/guidelines.md)
- [License](LICENSE) (MIT)
