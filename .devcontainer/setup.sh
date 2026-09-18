#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
pip install -e . -q

echo ""
echo "Setup complete. Try it now:"
echo "  source .venv/bin/activate"
echo "  trustgraph scan examples/vulnerable-project --repo-name my-org/vulnerable-project"
echo "  trustgraph explain TG-001 --in examples/vulnerable-project"
echo "  trustgraph scan examples/hardened-project --repo-name my-org/hardened-project"
echo ""
echo "To run the tests instead:"
echo "  python -m pytest -v"
echo ""
echo "Running a first scan now as a smoke test:"
trustgraph scan examples/vulnerable-project --repo-name my-org/vulnerable-project
