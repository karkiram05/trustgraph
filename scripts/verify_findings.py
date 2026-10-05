#!/usr/bin/env python3
"""Cross-check every real-world finding against the raw YAML, without using
TrustGraph's own parser, so a parser bug can't confirm itself.

For each row of data/processed/findings.csv:
- unpinned-action: the exact `uses:` string is in that job's steps, and the
  job's effective `id-token` permission matches the finding's elevation;
- overpermissioned-token: the job grants both `id-token: write` and
  `contents: write`.

Usage:
    python scripts/verify_findings.py
"""
import csv
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw" / "real_workflows"


def effective(job: dict, doc: dict) -> dict:
    perms = job.get("permissions") if job.get("permissions") is not None else doc.get("permissions")
    return perms if isinstance(perms, dict) else {}


def main() -> int:
    rows = list(csv.DictReader((ROOT / "data" / "processed" / "findings.csv").open()))
    bad = 0
    for row in rows:
        path = RAW / row["repo"].replace("/", "__") / row["workflow"]
        doc = yaml.safe_load(path.read_text())
        job = doc["jobs"][row["job"]]
        perms = effective(job, doc)
        if row["rule"] == "unpinned-action":
            uses = row["uses"]
            needle = f"{uses}:{row['ref']}" if uses.startswith("docker://") else f"{uses}@{row['ref']}"
            in_steps = any(isinstance(s, dict) and str(s.get("uses", "")).strip() == needle
                           for s in job.get("steps", []) or [])
            in_job = str(job.get("uses", "")).strip() == needle
            ok = (in_steps or in_job) and (perms.get("id-token") == "write") == bool(int(row["elevated_context"]))
        elif row["rule"] == "overpermissioned-token":
            ok = perms.get("id-token") == "write" and "write" in (perms.get("contents"), perms.get("actions"))
        else:
            ok = False
        if not ok:
            bad += 1
            print(f"NOT CONFIRMED: {row['repo']} {row['workflow']} job={row['job']} {row['title']}")
    print(f"{len(rows) - bad} of {len(rows)} findings confirmed against the raw YAML")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
