# CostCanary _(costcanary)_

[![tests](https://github.com/Blackout223/costcanary/actions/workflows/tests.yml/badge.svg)](https://github.com/Blackout223/costcanary/actions/workflows/tests.yml)
[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg)](https://github.com/RichardLitt/standard-readme)

Detect signs of AWS compromise (crypto-mining, LLMjacking, data theft) hidden in your cloud bill.

- Flags new regions, GPU instances, abuse-prone services, disabled security logging, spend spikes and data egress spikes.
- Ranks findings by severity and cost, with a plain-English reason for each.
- Reads AWS Cost and Usage Report (CUR 2.0) CSV files and needs no AWS credentials.
- Exits with code 1 on high-severity findings, for use in scripts and CI.

## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Install

Requires [Python](https://www.python.org/downloads/) 3.10 or newer. There are no other dependencies.

```bash
git clone https://github.com/Blackout223/costcanary.git
cd costcanary
```

## Usage

### CLI

```bash
# Try it on the included sample data
python costcanary.py sample_data/compromised_month.csv

# Check your own CUR export and save a Markdown report
python costcanary.py path/to/cur-export.csv --markdown report.md

# List all options
python costcanary.py --help
```

See the [usage guidelines](docs/guidelines.md) for options, exit codes, limitations and responsible use.

## Contributing

Questions and bug reports are welcome in [GitHub issues](https://github.com/Blackout223/costcanary/issues).
Pull requests are accepted. Please make sure `python -m pytest` passes and add a test for any new detection rule.

## License

[MIT](LICENSE) © Blackout
