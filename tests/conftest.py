# Lets the tests import the "canary" package from the project folder.
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
