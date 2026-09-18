from tests.conftest import FIXTURES_DIR
from trustgraph.detections.rules import (
    roles_reachable_from_repo,
    rule_missing_audience_restriction,
    rule_overpermissioned_token,
    rule_unpinned_action,
    rule_wildcard_oidc_trust,
)
from trustgraph.parsers.github_actions import parse_workflow
from trustgraph.parsers.iam_trust import parse_trust_policy


def test_overpermissioned_token_flags_write_plus_id_token():
    wf = parse_workflow(FIXTURES_DIR / "overpermissioned.yml")
    findings = list(rule_overpermissioned_token([wf]))
    assert len(findings) == 1
    assert findings[0]["job_id"] == "deploy"
    assert "contents" in findings[0]["extra_scopes"]


def test_overpermissioned_token_silent_on_safe_config():
    wf = parse_workflow(FIXTURES_DIR / "safe_permissions.yml")
    findings = list(rule_overpermissioned_token([wf]))
    assert findings == []


def test_unpinned_action_flags_third_party_unpinned_only():
    wf = parse_workflow(FIXTURES_DIR / "unpinned_action.yml")
    findings = list(rule_unpinned_action([wf]))
    flagged = {f["action"].uses for f in findings}
    assert "some-org/some-action" in flagged
    assert "actions/checkout" not in flagged  # not third-party


def test_unpinned_action_silent_when_pinned():
    wf = parse_workflow(FIXTURES_DIR / "pinned_action.yml")
    findings = list(rule_unpinned_action([wf]))
    assert findings == []


def test_wildcard_oidc_trust_detected():
    policy = parse_trust_policy(FIXTURES_DIR / "wildcard_trust.json")
    findings = list(rule_wildcard_oidc_trust([policy]))
    assert len(findings) == 1


def test_scoped_oidc_trust_not_flagged():
    policy = parse_trust_policy(FIXTURES_DIR / "scoped_trust.json")
    findings = list(rule_wildcard_oidc_trust([policy]))
    assert findings == []


def test_missing_audience_restriction():
    wildcard = parse_trust_policy(FIXTURES_DIR / "wildcard_trust.json")
    scoped = parse_trust_policy(FIXTURES_DIR / "scoped_trust.json")
    findings = list(rule_missing_audience_restriction([wildcard, scoped]))
    assert len(findings) == 1
    assert findings[0]["policy"].role_name == "wildcard_trust"


def test_roles_reachable_from_repo_matches_wildcard():
    policy = parse_trust_policy(FIXTURES_DIR / "wildcard_trust.json")
    matched = roles_reachable_from_repo("my-org/anything-at-all", [policy])
    assert matched == [policy]


def test_roles_reachable_from_repo_rejects_non_matching_org():
    policy = parse_trust_policy(FIXTURES_DIR / "wildcard_trust.json")
    matched = roles_reachable_from_repo("other-org/some-repo", [policy])
    assert matched == []


def test_roles_reachable_from_repo_exact_match_required_for_scoped():
    policy = parse_trust_policy(FIXTURES_DIR / "scoped_trust.json")
    matched_correct = roles_reachable_from_repo("my-org/my-repo", [policy])
    assert matched_correct == [policy]

    matched_wrong_repo = roles_reachable_from_repo("my-org/different-repo", [policy])
    assert matched_wrong_repo == []
