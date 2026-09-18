from tests.conftest import FIXTURES_DIR
from trustgraph.parsers.github_actions import parse_workflow
from trustgraph.parsers.iam_trust import parse_trust_policy


def test_parses_workflow_level_permissions():
    wf = parse_workflow(FIXTURES_DIR / "overpermissioned.yml")
    assert wf.permissions == {"contents": "write", "id-token": "write"}
    assert len(wf.jobs) == 1
    assert wf.jobs[0].id == "deploy"


def test_job_level_permissions_override_workflow_level():
    wf = parse_workflow(FIXTURES_DIR / "safe_permissions.yml")
    job = wf.jobs[0]
    assert wf.effective_permission(job, "id-token") == "write"
    assert wf.effective_permission(job, "contents") == "read"


def test_any_job_requests_id_token():
    wf = parse_workflow(FIXTURES_DIR / "overpermissioned.yml")
    assert wf.any_job_requests_id_token() is True

    wf2 = parse_workflow(FIXTURES_DIR / "unpinned_action.yml")
    assert wf2.any_job_requests_id_token() is False


def test_action_pinned_detection():
    wf = parse_workflow(FIXTURES_DIR / "unpinned_action.yml")
    actions = {a.uses: a for a in wf.all_action_uses()}
    assert actions["some-org/some-action"].pinned is False
    assert actions["actions/checkout"].pinned is False  # v4 is a tag too

    wf2 = parse_workflow(FIXTURES_DIR / "pinned_action.yml")
    actions2 = {a.uses: a for a in wf2.all_action_uses()}
    assert actions2["some-org/some-action"].pinned is True


def test_third_party_classification():
    wf = parse_workflow(FIXTURES_DIR / "unpinned_action.yml")
    actions = {a.uses: a for a in wf.all_action_uses()}
    assert actions["actions/checkout"].is_third_party is False
    assert actions["some-org/some-action"].is_third_party is True


def test_wildcard_trust_policy_parsing():
    policy = parse_trust_policy(FIXTURES_DIR / "wildcard_trust.json")
    assert policy.trusts_github_oidc() is True
    assert policy.has_wildcard_subject() is True
    assert policy.audience_restricted() is False
    assert policy.subject_scoped_to_branch_or_env() is False


def test_scoped_trust_policy_parsing():
    policy = parse_trust_policy(FIXTURES_DIR / "scoped_trust.json")
    assert policy.has_wildcard_subject() is False
    assert policy.audience_restricted() is True
    assert policy.subject_scoped_to_branch_or_env() is True
