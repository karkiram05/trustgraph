import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
