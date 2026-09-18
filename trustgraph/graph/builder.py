"""Builds a TrustGraph from parsed workflows, trust policies, and an
optional (simple) role -> cloud resource access map.

The role -> resource mapping isn't discovered automatically in this phase
(that would require actually parsing IAM permission policies, not just
trust policies, and simulating policy evaluation -- a hard problem, see
docs/architecture.md's roadmap) -- it's supplied as a small JSON file
describing what each role can reach. Everything upstream of that (the CI
identity chain) *is* derived automatically from the workflow and trust
policy files.
"""
from __future__ import annotations

import json
from pathlib import Path

from trustgraph.graph.model import Edge, EdgeType, Node, NodeType, TrustGraph
from trustgraph.parsers.github_actions import Workflow
from trustgraph.parsers.iam_trust import GITHUB_OIDC_ISSUER, TrustPolicy

OIDC_NODE_ID = f"oidc:{GITHUB_OIDC_ISSUER}"


def repo_id_for_workflow(workflow: Workflow, repo_name: str | None = None) -> str:
    if repo_name:
        return f"repo:{repo_name}"
    # Fall back to the parent-of-parent directory name (…/<repo>/.github/workflows/x.yml)
    parts = Path(workflow.path).resolve().parts
    if ".github" in parts:
        idx = parts.index(".github")
        if idx > 0:
            return f"repo:{parts[idx - 1]}"
    return f"repo:{Path(workflow.path).stem}"


def build_graph(
    workflows: list[Workflow],
    trust_policies: list[TrustPolicy],
    resource_access: list[dict] | None = None,
    repo_name: str | None = None,
) -> TrustGraph:
    graph = TrustGraph()
    resource_access = resource_access or []

    oidc_added = False

    for workflow in workflows:
        rid = repo_id_for_workflow(workflow, repo_name)
        if rid not in {n.id for n in graph.nodes(NodeType.REPOSITORY)}:
            graph.add_node(Node(id=rid, type=NodeType.REPOSITORY, attrs={"name": rid.removeprefix("repo:")}))

        wid = f"workflow:{workflow.path}"
        graph.add_node(Node(id=wid, type=NodeType.WORKFLOW, attrs={
            "name": workflow.name,
            "path": workflow.path,
            "on": workflow.on,
        }))
        graph.add_edge(Edge(source=rid, target=wid, type=EdgeType.DEFINES))

        for action in workflow.all_action_uses():
            aid = f"action:{action.uses}"
            graph.add_node(Node(id=aid, type=NodeType.THIRD_PARTY_ACTION, attrs={
                "uses": action.uses,
                "is_third_party": action.is_third_party,
            }))
            graph.add_edge(Edge(source=wid, target=aid, type=EdgeType.USES_ACTION, attrs={
                "ref": action.ref,
                "pinned": action.pinned,
                "step_name": action.step_name,
            }))

        if workflow.any_job_requests_id_token():
            if not oidc_added:
                graph.add_node(Node(id=OIDC_NODE_ID, type=NodeType.OIDC_PROVIDER, attrs={"issuer": GITHUB_OIDC_ISSUER}))
                oidc_added = True
            requesting_jobs = [j.id for j in workflow.jobs if workflow.effective_permission(j, "id-token") == "write"]
            graph.add_edge(Edge(source=wid, target=OIDC_NODE_ID, type=EdgeType.REQUESTS_TOKEN, attrs={
                "jobs": requesting_jobs,
            }))

    for policy in trust_policies:
        role_id = f"role:{policy.role_name}"
        graph.add_node(Node(id=role_id, type=NodeType.IAM_ROLE, attrs={
            "name": policy.role_name,
            "audience_restricted": policy.audience_restricted(),
            "wildcard_subject": policy.has_wildcard_subject(),
            "subject_patterns": policy.subject_patterns,
            "subject_scoped": policy.subject_scoped_to_branch_or_env(),
        }))
        if policy.trusts_github_oidc():
            if not oidc_added:
                graph.add_node(Node(id=OIDC_NODE_ID, type=NodeType.OIDC_PROVIDER, attrs={"issuer": GITHUB_OIDC_ISSUER}))
                oidc_added = True
            graph.add_edge(Edge(source=OIDC_NODE_ID, target=role_id, type=EdgeType.TRUSTS, attrs={
                "subject_patterns": policy.subject_patterns,
                "audience_restricted": policy.audience_restricted(),
            }))

    for entry in resource_access:
        role_id = f"role:{entry['role']}"
        resource_id = f"resource:{entry['resource']}"
        if resource_id not in {n.id for n in graph.nodes(NodeType.CLOUD_RESOURCE)}:
            graph.add_node(Node(id=resource_id, type=NodeType.CLOUD_RESOURCE, attrs={
                "name": entry["resource"],
                "description": entry.get("description", ""),
            }))
        graph.add_edge(Edge(source=role_id, target=resource_id, type=EdgeType.CAN_ACCESS, attrs={
            "permission": entry.get("permission", "unknown"),
        }))

    return graph


def load_resource_access(path: str | Path) -> list[dict]:
    with open(path) as f:
        return json.load(f)
