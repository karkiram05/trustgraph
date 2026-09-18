"""Orchestrates the rule functions, turns their raw findings into fully
explained Finding objects (with a plain-English attack path when one is
derivable from the graph), and assigns stable TG-NNN ids.
"""
from __future__ import annotations

from trustgraph.detections.base import Finding, Severity
from trustgraph.detections.rules import (
    roles_reachable_from_repo,
    rule_missing_audience_restriction,
    rule_overpermissioned_token,
    rule_unpinned_action,
    rule_wildcard_oidc_trust,
)
from trustgraph.graph.builder import repo_id_for_workflow
from trustgraph.graph.model import NodeType, TrustGraph
from trustgraph.parsers.github_actions import Workflow
from trustgraph.parsers.iam_trust import TrustPolicy
from trustgraph.remediation.suggest import suggest_remediation


def _role_can_access_resources(graph: TrustGraph, role_id: str) -> list[str]:
    return [e.target for e in graph.out_edges(role_id) if e.type.value == "can_access"]


def _build_path(graph: TrustGraph, repo_id: str, through: list[str]) -> list[str]:
    path = [repo_id]
    for node_id in through:
        if node_id and node_id != path[-1]:
            path.append(node_id)
    return path


def run_detections(
    workflows: list[Workflow],
    trust_policies: list[TrustPolicy],
    graph: TrustGraph,
    repo_name: str | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    counter = 1

    def next_id() -> str:
        nonlocal counter
        fid = f"TG-{counter:03d}"
        counter += 1
        return fid

    # --- Overpermissioned token ---
    for raw in rule_overpermissioned_token(workflows, repo_name):
        workflow: Workflow = raw["workflow"]
        rid = repo_id_for_workflow(workflow, repo_name)
        short_repo = rid.removeprefix("repo:")
        matched_roles = roles_reachable_from_repo(short_repo, trust_policies)
        resources = []
        for policy in matched_roles:
            resources.extend(_role_can_access_resources(graph, f"role:{policy.role_name}"))

        severity = Severity.CRITICAL if resources else Severity.HIGH
        extra = ", ".join(raw["extra_scopes"])
        path = _build_path(
            graph, rid,
            [f"workflow:{workflow.path}", "oidc:token.actions.githubusercontent.com",
             *(f"role:{p.role_name}" for p in matched_roles), *resources],
        )
        findings.append(Finding(
            id=next_id(),
            rule_id="overpermissioned-token",
            title="Overpowered GitHub Actions token",
            severity=severity,
            entry_point=f"CI workflow ({workflow.path}, job `{raw['job_id']}`)",
            problem=(
                f"Job `{raw['job_id']}` requests `id-token: write` (an OIDC cloud "
                f"credential) while also holding `{extra}: write` on the GITHUB_TOKEN."
            ),
            cloud_trust=(
                f"That combination means a single compromised step in this job can "
                f"both mint a cloud identity token AND modify the repository/workflow."
                + (f" That token can be exchanged for role(s): {', '.join(p.role_name for p in matched_roles)}." if matched_roles else "")
            ),
            result=(
                "A compromised dependency or malicious PR step in this job could "
                "pivot from code execution to cloud access in one step."
                + (f" Reachable resources: {', '.join(r.removeprefix('resource:') for r in resources)}." if resources else "")
            ),
            remediation=suggest_remediation("overpermissioned-token", raw),
            path=path,
            evidence={"job_id": raw["job_id"], "extra_scopes": raw["extra_scopes"]},
        ))

    # --- Wildcard OIDC trust ---
    for raw in rule_wildcard_oidc_trust(trust_policies):
        policy: TrustPolicy = raw["policy"]
        role_id = f"role:{policy.role_name}"
        resources = _role_can_access_resources(graph, role_id)
        severity = Severity.CRITICAL if resources else Severity.HIGH
        path = _build_path(graph, "oidc:token.actions.githubusercontent.com", [role_id, *resources])
        findings.append(Finding(
            id=next_id(),
            rule_id="wildcard-oidc-trust",
            title="Overly broad OIDC trust condition",
            severity=severity,
            entry_point=f"IAM role trust policy ({policy.path})",
            problem=(
                f"Role `{policy.role_name}` trusts GitHub's OIDC provider with subject "
                f"pattern(s) {policy.subject_patterns} -- not scoped to a specific ref "
                f"or environment."
            ),
            cloud_trust=(
                "Any workflow run whose OIDC subject claim matches that wildcard "
                "(potentially any branch, any workflow, in any repo the pattern covers) "
                "can assume this role."
            ),
            result=(
                "A workflow you didn't intend to trust -- a feature branch, a fork's "
                "pull_request build, or a different repo entirely, depending on how "
                "wide the wildcard is -- could assume this role."
                + (f" Reachable resources: {', '.join(r.removeprefix('resource:') for r in resources)}." if resources else "")
            ),
            remediation=suggest_remediation("wildcard-oidc-trust", raw),
            path=path,
            evidence={"subject_patterns": policy.subject_patterns},
        ))

    # --- Missing audience restriction ---
    for raw in rule_missing_audience_restriction(trust_policies):
        policy: TrustPolicy = raw["policy"]
        findings.append(Finding(
            id=next_id(),
            rule_id="missing-audience-restriction",
            title="OIDC audience not pinned in trust policy",
            severity=Severity.MEDIUM,
            entry_point=f"IAM role trust policy ({policy.path})",
            problem=(
                f"Role `{policy.role_name}`'s trust policy doesn't restrict "
                f"`token.actions.githubusercontent.com:aud`."
            ),
            cloud_trust=(
                "The audience claim is one of the two independent checks GitHub "
                "recommends pinning (the other is the subject claim); leaving it "
                "unrestricted removes a defense-in-depth layer."
            ),
            result=(
                "Not exploitable on its own, but weakens the trust policy's "
                "resistance to token misuse if the subject condition is ever "
                "loosened or misconfigured."
            ),
            remediation=suggest_remediation("missing-audience-restriction", raw),
            path=[f"role:{policy.role_name}"],
            evidence={},
        ))

    # --- Unpinned third-party actions ---
    for raw in rule_unpinned_action(workflows):
        workflow: Workflow = raw["workflow"]
        action = raw["action"]
        rid = repo_id_for_workflow(workflow, repo_name)
        elevated = raw["elevated_context"]
        severity = Severity.MEDIUM
        matched_roles = []
        resources = []
        if elevated:
            short_repo = rid.removeprefix("repo:")
            matched_roles = roles_reachable_from_repo(short_repo, trust_policies)
            for policy in matched_roles:
                resources.extend(_role_can_access_resources(graph, f"role:{policy.role_name}"))
            severity = Severity.CRITICAL if resources else Severity.HIGH

        path = _build_path(
            graph, rid,
            [f"workflow:{workflow.path}", f"action:{action.uses}"]
            + ([f"oidc:token.actions.githubusercontent.com",
                *(f"role:{p.role_name}" for p in matched_roles), *resources] if elevated else []),
        )
        findings.append(Finding(
            id=next_id(),
            rule_id="unpinned-action",
            title=f"Unpinned third-party action: {action.uses}",
            severity=severity,
            entry_point=f"CI workflow ({workflow.path})",
            problem=f"`{action.uses}` is referenced by mutable ref `{action.ref}`, not a commit SHA.",
            cloud_trust=(
                "Whoever controls that ref can change what code runs in this workflow "
                "at any time, with whatever permissions the job holds."
                + (f" This job also requests an OIDC token; reachable role(s): "
                   f"{', '.join(p.role_name for p in matched_roles)}." if matched_roles else "")
            ),
            result=(
                "A compromised or malicious update to that action's tag runs "
                "arbitrary code in your CI with this job's full permission set."
                + (f" Reachable resources: {', '.join(r.removeprefix('resource:') for r in resources)}." if resources else "")
            ),
            remediation=suggest_remediation("unpinned-action", raw),
            path=path,
            evidence={"uses": action.uses, "ref": action.ref, "elevated_context": elevated},
        ))

    findings.sort(key=lambda f: f.severity.rank)
    return findings
