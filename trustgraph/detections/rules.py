"""Detection rules. Each rule is a plain function: (workflows, trust_policies,
graph) -> Iterator[Finding]. Every rule here corresponds to a documented,
real-world CI/CD supply-chain anti-pattern (GitHub's own OIDC hardening
docs, and public writeups on overpermissioned Actions tokens and unpinned
third-party actions) -- not an invented one.
"""
from __future__ import annotations

import fnmatch
from typing import Iterator

from trustgraph.detections.base import Finding, Severity
from trustgraph.graph.builder import repo_id_for_workflow
from trustgraph.parsers.github_actions import Workflow
from trustgraph.parsers.iam_trust import TrustPolicy


def _subject_candidates(repo_name: str, branches: list[str]) -> list[str]:
    candidates = [f"repo:{repo_name}:ref:refs/heads/{b}" for b in branches]
    candidates.append(f"repo:{repo_name}:pull_request")
    return candidates


def roles_reachable_from_repo(repo_name: str, trust_policies: list[TrustPolicy], branches: list[str] | None = None) -> list[TrustPolicy]:
    """Which roles' trust conditions this repo's OIDC token could satisfy.

    Heuristic: builds a small set of plausible `sub` claim values for the
    repo (its default/main branch and pull_request context) and checks them
    against each trust policy's subject pattern with shell-style wildcard
    matching, which is how AWS's StringLike condition operator actually
    behaves. This is real trust evaluation on the *shape* of the condition,
    not a guess -- its limitation is that it doesn't know your repo's real
    branch names or environments if they're unconventional; see
    docs/architecture.md.
    """
    branches = branches or ["main", "master"]
    candidates = _subject_candidates(repo_name, branches)
    matched = []
    for policy in trust_policies:
        if not policy.trusts_github_oidc():
            continue
        for pattern in policy.subject_patterns:
            if any(fnmatch.fnmatch(c, pattern) for c in candidates):
                matched.append(policy)
                break
    return matched


def rule_overpermissioned_token(workflows: list[Workflow], repo_name: str | None = None) -> Iterator[dict]:
    """An id-token: write job that ALSO holds contents:write or
    actions:write has more standing privilege than an OIDC federation
    pattern needs -- the token exchange itself only needs id-token: write;
    everything else should be minted narrowly by the assumed cloud role,
    not sitting in the GITHUB_TOKEN too."""
    for workflow in workflows:
        for job in workflow.jobs:
            if workflow.effective_permission(job, "id-token") != "write":
                continue
            extra = [
                scope for scope in ("contents", "actions")
                if workflow.effective_permission(job, scope) == "write"
            ]
            if extra:
                yield {
                    "rule_id": "overpermissioned-token",
                    "workflow": workflow,
                    "job_id": job.id,
                    "extra_scopes": extra,
                }


def rule_wildcard_oidc_trust(trust_policies: list[TrustPolicy]) -> Iterator[dict]:
    for policy in trust_policies:
        if not policy.trusts_github_oidc():
            continue
        if policy.has_wildcard_subject() or not policy.subject_scoped_to_branch_or_env():
            yield {"rule_id": "wildcard-oidc-trust", "policy": policy}


def rule_missing_audience_restriction(trust_policies: list[TrustPolicy]) -> Iterator[dict]:
    for policy in trust_policies:
        if policy.trusts_github_oidc() and not policy.audience_restricted():
            yield {"rule_id": "missing-audience-restriction", "policy": policy}


def rule_unpinned_action(workflows: list[Workflow]) -> Iterator[dict]:
    for workflow in workflows:
        elevated = workflow.any_job_requests_id_token()
        for action in workflow.all_action_uses():
            if action.pinned:
                continue
            if not action.is_third_party:
                continue
            yield {
                "rule_id": "unpinned-action",
                "workflow": workflow,
                "action": action,
                "elevated_context": elevated,
            }
