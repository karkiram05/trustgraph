#!/usr/bin/env python3
"""Scan the pinned real-world workflows in data/raw/real_workflows/ and
write every intermediate table, so each number in docs/results.md can be
recomputed from a CSV instead of taken on trust.

    data/raw/real_workflows/         raw YAML, pinned by commit (fetch_real_workflows.py)
      -> data/clean/action_references.csv  one row per `uses:` (step, reusable
                                           workflow or docker image)
      -> data/clean/job_permissions.csv    one row per job: where its token
                                           permissions come from, id-token, write scopes
      -> data/clean/parse_errors.csv       files the parser rejected, with the reason
      -> data/processed/findings.csv       every finding TrustGraph raised
      -> data/processed/summary_by_repo.csv
      -> data/processed/summary.json

The parsed inventories are what the original evaluation called checking
"by hand": instead of a person reading 188 files, every permission and
action reference the rules depend on is in a table anyone can filter.

Usage:
    python scripts/evaluate_real_workflows.py
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from trustgraph.detections.engine import run_detections  # noqa: E402
from trustgraph.graph.builder import build_graph  # noqa: E402
from trustgraph.parsers.github_actions import UNSPECIFIED, parse_workflow  # noqa: E402

RAW_DIR = REPO_ROOT / "data" / "raw" / "real_workflows"
CLEAN_DIR = REPO_ROOT / "data" / "clean"
PROCESSED_DIR = REPO_ROOT / "data" / "processed"

SCOPES = (
    "actions", "attestations", "checks", "contents", "deployments", "discussions",
    "id-token", "issues", "packages", "pages", "pull-requests", "repository-projects",
    "security-events", "statuses",
)


def write_csv(path: Path, rows: list[dict], columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def permission_source(workflow, job) -> str:
    if job.permissions is not None:
        return "job"
    if workflow.permissions is not None:
        return "workflow"
    return UNSPECIFIED


def main() -> int:
    manifest = json.loads((RAW_DIR / "manifest.json").read_text())
    refs, jobs_rows, errors, finding_rows, repo_rows = [], [], [], [], []

    for entry in manifest["repositories"]:
        repo, commit = entry["repo"], entry["commit"]
        repo_dir = RAW_DIR / repo.replace("/", "__")
        workflows = []
        for item in entry["files"]:
            rel = item["path"]
            try:
                workflows.append((rel, parse_workflow(repo_dir / rel)))
            except Exception as exc:  # noqa: BLE001 -- record every parse failure, keep going
                errors.append({"repo": repo, "commit": commit, "workflow": rel,
                               "error": f"{type(exc).__name__}: {exc}".replace(str(repo_dir) + "/", "")})

        for rel, wf in workflows:
            # Report paths relative to the scanned repo, not this machine.
            wf.path = rel
            for job in wf.jobs:
                elevated = wf.job_requests_id_token(job)
                write_scopes = [s for s in SCOPES if wf.effective_permission(job, s) == "write"]
                jobs_rows.append({
                    "repo": repo, "workflow": rel, "job": job.id,
                    "permission_source": permission_source(wf, job),
                    "requests_id_token": int(elevated),
                    "write_scopes": ";".join(write_scopes),
                    "write_all": int("write-all" in (job.permissions, wf.permissions)
                                     if job.permissions is None else job.permissions == "write-all"),
                    "calls_reusable_workflow": int(job.reusable_workflow is not None),
                    "action_references": len(job.action_uses()),
                })
                for action in job.action_uses():
                    same_repo = action.repository == repo.lower()
                    refs.append({
                        "repo": repo, "workflow": rel, "job": job.id, "kind": action.kind,
                        "uses": action.uses, "ref": action.ref, "pinned": int(action.pinned),
                        # Same definition the unpinned-action rule uses:
                        # not actions/* or github/*, and not this repo itself.
                        "third_party": int(action.is_third_party and not same_repo),
                        "same_repo": int(same_repo),
                        "job_requests_id_token": int(elevated),
                    })

        parsed = [wf for _, wf in workflows]
        graph = build_graph(parsed, [], [], repo_name=repo)
        findings = run_detections(parsed, [], graph, repo_name=repo)
        for f in findings:
            ev = f.evidence
            finding_rows.append({
                "repo": repo, "commit": commit, "finding": f.id, "rule": f.rule_id,
                "severity": f.severity.value, "title": f.title,
                "workflow": f.entry_point.removeprefix("CI workflow (").split(",")[0].rstrip(")"),
                "job": ev.get("job", ev.get("job_id", "")), "uses": ev.get("uses", ""),
                "ref": ev.get("ref", ""), "elevated_context": int(bool(ev.get("elevated_context"))),
            })

        repo_refs = [r for r in refs if r["repo"] == repo]
        repo_jobs = [j for j in jobs_rows if j["repo"] == repo]
        sev = Counter(f.severity.value for f in findings)
        third = [r for r in repo_refs if r["third_party"]]
        repo_rows.append({
            "repo": repo, "commit": commit,
            "workflow_files": len(entry["files"]), "parsed": len(workflows),
            "jobs": len(repo_jobs),
            "jobs_permissions_unspecified": sum(j["permission_source"] == UNSPECIFIED for j in repo_jobs),
            "jobs_requesting_id_token": sum(j["requests_id_token"] for j in repo_jobs),
            "action_references": len(repo_refs),
            "first_party_references": len(repo_refs) - len(third),
            "same_repo_references": sum(r["same_repo"] for r in repo_refs),
            "third_party_references": len(third),
            "third_party_pinned": sum(r["pinned"] for r in third),
            "third_party_unpinned": sum(not r["pinned"] for r in third),
            "findings": len(findings),
            **{f"findings_{s.lower()}": sev.get(s, 0) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        })

    write_csv(CLEAN_DIR / "action_references.csv", refs,
              ["repo", "workflow", "job", "kind", "uses", "ref", "pinned", "third_party",
               "same_repo", "job_requests_id_token"])
    write_csv(CLEAN_DIR / "job_permissions.csv", jobs_rows,
              ["repo", "workflow", "job", "permission_source", "requests_id_token",
               "write_scopes", "write_all", "calls_reusable_workflow", "action_references"])
    write_csv(CLEAN_DIR / "parse_errors.csv", errors, ["repo", "commit", "workflow", "error"])
    write_csv(PROCESSED_DIR / "findings.csv", finding_rows,
              ["repo", "commit", "finding", "rule", "severity", "title", "workflow", "job",
               "uses", "ref", "elevated_context"])
    write_csv(PROCESSED_DIR / "summary_by_repo.csv", repo_rows, list(repo_rows[0]))

    totals = {k: sum(r[k] for r in repo_rows) for k in repo_rows[0] if k not in ("repo", "commit")}
    summary = {
        "fetched_at": manifest["fetched_at"],
        "repositories": len(repo_rows),
        "repositories_with_findings": sum(r["findings"] > 0 for r in repo_rows),
        **totals,
        "parse_errors": len(errors),
        "findings_by_rule": dict(Counter(r["rule"] for r in finding_rows)),
        "unpinned_third_party_by_kind": dict(Counter(
            r["kind"] for r in refs if r["third_party"] and not r["pinned"])),
    }
    (PROCESSED_DIR / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
