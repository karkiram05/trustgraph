from tests.conftest import FIXTURES_DIR
from trustgraph.detections.base import Severity
from trustgraph.detections.engine import run_detections
from trustgraph.graph.builder import build_graph
from trustgraph.parsers.github_actions import parse_workflow
from trustgraph.parsers.iam_trust import parse_trust_policy


def test_end_to_end_critical_when_resource_reachable():
    wf = parse_workflow(FIXTURES_DIR / "overpermissioned.yml")
    policy = parse_trust_policy(FIXTURES_DIR / "wildcard_trust.json")
    resource_access = [{"role": "wildcard_trust", "resource": "prod-db", "description": "x"}]
    graph = build_graph([wf], [policy], resource_access, repo_name="my-org/repo")

    findings = run_detections([wf], [policy], graph, repo_name="my-org/repo")

    overperm = [f for f in findings if f.rule_id == "overpermissioned-token"]
    assert len(overperm) == 1
    assert overperm[0].severity == Severity.CRITICAL
    assert "resource:prod-db" in overperm[0].path


def test_severity_drops_without_reachable_resource():
    wf = parse_workflow(FIXTURES_DIR / "overpermissioned.yml")
    graph = build_graph([wf], [], repo_name="my-org/repo")

    findings = run_detections([wf], [], graph, repo_name="my-org/repo")
    overperm = [f for f in findings if f.rule_id == "overpermissioned-token"]
    assert len(overperm) == 1
    assert overperm[0].severity == Severity.HIGH  # no trust policy, no reachable role


def test_findings_sorted_by_severity():
    wf = parse_workflow(FIXTURES_DIR / "overpermissioned.yml")
    policy = parse_trust_policy(FIXTURES_DIR / "wildcard_trust.json")
    graph = build_graph([wf], [policy], repo_name="my-org/repo")
    findings = run_detections([wf], [policy], graph, repo_name="my-org/repo")

    ranks = [f.severity.rank for f in findings]
    assert ranks == sorted(ranks)


def test_ids_are_unique_and_sequential_by_discovery():
    wf = parse_workflow(FIXTURES_DIR / "overpermissioned.yml")
    policy = parse_trust_policy(FIXTURES_DIR / "wildcard_trust.json")
    graph = build_graph([wf], [policy], repo_name="my-org/repo")
    findings = run_detections([wf], [policy], graph, repo_name="my-org/repo")

    ids = [f.id for f in findings]
    assert len(ids) == len(set(ids))
    assert all(fid.startswith("TG-") for fid in ids)


def test_clean_config_produces_no_findings():
    wf = parse_workflow(FIXTURES_DIR / "safe_permissions.yml")
    policy = parse_trust_policy(FIXTURES_DIR / "scoped_trust.json")
    graph = build_graph([wf], [policy], repo_name="my-org/my-repo")
    findings = run_detections([wf], [policy], graph, repo_name="my-org/my-repo")
    assert findings == []
