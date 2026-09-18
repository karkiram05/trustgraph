#!/usr/bin/env bash
# One-command local setup: creates a venv, installs dependencies, installs
# the package in editable mode, and runs a smoke-test scan. Works whether
# you're on your own machine or in GitHub Codespaces (which also runs this
# automatically via .devcontainer/devcontainer.json).
set -euo pipefail
cd "$(dirname "$0")"
exec .devcontainer/setup.sh
