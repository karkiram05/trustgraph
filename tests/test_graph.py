from tests.conftest import FIXTURES_DIR
from trustgraph.graph.builder import build_graph
from trustgraph.graph.model import NodeType
from trustgraph.parsers.github_actions import parse_workflow
from trustgraph.parsers.iam_trust import parse_trust_policy


def test_build_graph_creates_expected_node_types():
    wf = parse_workflow(FIXTURES_DIR / "overpermissioned.yml")
    policy = parse_trust_policy(FIXTURES_DIR / "wildcard_trust.json")
    graph = build_graph([wf], [policy], repo_name="my-org/repo")

    types = {n.type for n in graph.nodes()}
    assert NodeType.REPOSITORY in types
    assert NodeType.WORKFLOW in types
    assert NodeType.OIDC_PROVIDER in types
    assert NodeType.IAM_ROLE in types


def test_build_graph_links_role_to_resource():
    wf = parse_workflow(FIXTURES_DIR / "overpermissioned.yml")
    policy = parse_trust_policy(FIXTURES_DIR / "wildcard_trust.json")
    resource_access = [{"role": "wildcard_trust", "resource": "prod-bucket", "description": "x"}]
    graph = build_graph([wf], [policy], resource_access, repo_name="my-org/repo")

    role_id = "role:wildcard_trust"
    resource_id = "resource:prod-bucket"
    edges = list(graph.out_edges(role_id))
    targets = {e.target for e in edges}
    assert resource_id in targets


def test_all_paths_finds_repo_to_resource_chain():
    wf = parse_workflow(FIXTURES_DIR / "overpermissioned.yml")
    policy = parse_trust_policy(FIXTURES_DIR / "wildcard_trust.json")
    resource_access = [{"role": "wildcard_trust", "resource": "prod-bucket", "description": "x"}]
    graph = build_graph([wf], [policy], resource_access, repo_name="my-org/repo")

    paths = graph.all_paths("repo:my-org/repo", "resource:prod-bucket")
    assert len(paths) >= 1
    assert paths[0][0] == "repo:my-org/repo"
    assert paths[0][-1] == "resource:prod-bucket"


def test_no_path_when_no_id_token_requested():
    wf = parse_workflow(FIXTURES_DIR / "unpinned_action.yml")  # no id-token
    policy = parse_trust_policy(FIXTURES_DIR / "wildcard_trust.json")
    graph = build_graph([wf], [policy], repo_name="my-org/repo")

    # No REQUESTS_TOKEN edge should exist since this workflow never asks for id-token.
    workflow_id = f"workflow:{wf.path}"
    out_types = {e.type.value for e in graph.out_edges(workflow_id)}
    assert "requests_token" not in out_types


def test_build_graph_rejects_resource_access_for_unknown_role():
    """Regression test: a resources.json entry whose "role" doesn't match
    any trust-policy filename used to get silently added to the graph as a
    bare, attribute-less node (networkx auto-vivifies edge endpoints), which
    then crashed nodes()/other readers with a confusing KeyError('type')
    far away from the actual mistake. It should fail loudly, at the point
    of the actual mismatch, instead."""
    wf = parse_workflow(FIXTURES_DIR / "overpermissioned.yml")
    policy = parse_trust_policy(FIXTURES_DIR / "wildcard_trust.json")
    resource_access = [{"role": "some-other-role-name", "resource": "prod-bucket", "description": "x"}]

    try:
        build_graph([wf], [policy], resource_access, repo_name="my-org/repo")
        raise AssertionError("expected build_graph to reject the unknown role")
    except ValueError as exc:
        assert "some-other-role-name" in str(exc)
        assert "wildcard_trust" in str(exc)  # the one role that *is* known
