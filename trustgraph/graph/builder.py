"""Builds a TrustGraph from parsed workflows, trust policies, and role ->
cloud resource access.

Resource access comes from two sources and they can both be in play at
once: a hand-supplied resources.json (role/resource/permission triples,
for when you just know the mapping and don't want to write out a full IAM
policy), and/or auto-derived reachability computed by
parsers/iam_permissions.py from real permission-policy JSON + a resource
catalog. Auto-derived entries are tagged source="permission-policy" so a
reader can tell "the tool worked this out" apart from "someone asserted
this." See docs/architecture.md for what the permission-policy evaluation
does and doesn't cover.
"""
from __future__ import annotations

import json
from pathlib import Path

from trustgraph.graph.model import Edge, EdgeType, Node, NodeType, TrustGraph
from trustgraph.parsers._io import read_capped
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
                "kind": action.kind,
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

    known_role_ids = {n.id for n in graph.nodes(NodeType.IAM_ROLE)}
    for entry in resource_access:
        role_id = f"role:{entry['role']}"
        if role_id not in known_role_ids:
            # Adding an edge for a role that was never added as a node would
            # have networkx silently create a bare, attribute-less node for
            # it -- later code that reads node "type" (e.g. nodes()) would
            # then crash with a confusing KeyError far from the real cause.
            # A resources.json role that doesn't match any trust-policy
            # filename is virtually always a typo/mismatch, so fail loudly
            # here instead, naming the actual mismatch.
            raise ValueError(
                f"resources.json references role {entry['role']!r}, but no "
                f"trust-policies/*.json file defines that role (role name "
                f"is taken from the trust-policy filename, e.g. "
                f"trust-policies/{entry['role']}.json). Known roles: "
                f"{sorted(r.removeprefix('role:') for r in known_role_ids) or 'none'}."
            )
        resource_id = f"resource:{entry['resource']}"
        if resource_id not in {n.id for n in graph.nodes(NodeType.CLOUD_RESOURCE)}:
            graph.add_node(Node(id=resource_id, type=NodeType.CLOUD_RESOURCE, attrs={
                "name": entry["resource"],
                "description": entry.get("description", ""),
            }))
        graph.add_edge(Edge(source=role_id, target=resource_id, type=EdgeType.CAN_ACCESS, attrs={
            "permission": entry.get("permission", "unknown"),
            "source": entry.get("source", "manual"),
        }))

    return graph


def load_resource_access(path: str | Path) -> list[dict]:
    data = json.loads(read_capped(Path(path)))
    if not isinstance(data, list) or not all(
        isinstance(e, dict) and isinstance(e.get("role"), str) and isinstance(e.get("resource"), str)
        for e in data
    ):
        raise ValueError(f"{path}: expected a list of {{\"role\": str, \"resource\": str}} objects")
    return data


def derive_resource_access(permission_policies: list, catalog: list[dict]) -> list[dict]:
    """Run each role's permission policy against the resource catalog and
    return resource_access entries in the same shape build_graph() expects,
    marked source="permission-policy" so they can be told apart from a
    hand-typed resources.json entry downstream."""
    from trustgraph.parsers.iam_permissions import reachable_resources

    derived = []
    for policy in permission_policies:
        for hit in reachable_resources(policy, catalog):
            derived.append({
                "role": policy.role_name,
                "resource": hit["resource"],
                "description": hit["description"],
                "permission": hit["permission"],
                "source": "permission-policy",
            })
    return derived


def merge_resource_access(*lists: list[dict]) -> list[dict]:
    """Combine resource_access lists, deduping on (role, resource). First
    occurrence wins -- put hand-supplied entries first if you want a manual
    override to take precedence over an auto-derived one for the same pair."""
    seen = set()
    merged = []
    for entries in lists:
        for entry in entries:
            key = (entry["role"], entry["resource"])
            if key in seen:
                continue
            seen.add(key)
            merged.append(entry)
    return merged
