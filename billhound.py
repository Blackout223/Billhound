"""Run BillHound from a downloaded copy of the repo, without installing it.

Example:
    python billhound.py sample_data/compromised_month.csv --markdown report.md
"""

import sys

from hound.cli import main

if __name__ == "__main__":
    sys.exit(main())
