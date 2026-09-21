import json

from trustgraph.graph.builder import derive_resource_access, merge_resource_access
from trustgraph.parsers.iam_permissions import parse_permission_policy, reachable_resources

CATALOG = [
    {"arn": "arn:aws:s3:::prod-data", "name": "prod-bucket", "description": "prod data"},
    {"arn": "arn:aws:s3:::prod-data/exports", "name": "prod-exports", "description": "export prefix"},
    {"arn": "arn:aws:s3:::other-team-bucket", "name": "other-bucket", "description": "not this role's"},
]


def _write_policy(tmp_path, statements):
    doc = {"Version": "2012-10-17", "Statement": statements}
    path = tmp_path / "some-role.json"
    path.write_text(json.dumps(doc))
    return path


def test_wildcard_action_and_resource_grant_access(tmp_path):
    path = _write_policy(tmp_path, [
        {"Effect": "Allow", "Action": "s3:Get*", "Resource": "arn:aws:s3:::prod-data*"},
    ])
    policy = parse_permission_policy(path)
    hits = {h["resource"] for h in reachable_resources(policy, CATALOG)}
    assert hits == {"prod-bucket", "prod-exports"}


def test_no_matching_statement_means_not_reachable(tmp_path):
    path = _write_policy(tmp_path, [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::prod-data"},
    ])
    policy = parse_permission_policy(path)
    hits = {h["resource"] for h in reachable_resources(policy, CATALOG)}
    assert "other-bucket" not in hits


def test_explicit_deny_overrides_allow(tmp_path):
    path = _write_policy(tmp_path, [
        {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::prod-data*"},
        {"Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::prod-data/exports"},
    ])
    policy = parse_permission_policy(path)
    hits = {h["resource"] for h in reachable_resources(policy, CATALOG)}
    assert hits == {"prod-bucket"}
    assert "prod-exports" not in hits


def test_deny_order_does_not_matter(tmp_path):
    # Same policy, Deny statement listed first -- result must be identical,
    # since explicit deny wins regardless of statement order.
    path = _write_policy(tmp_path, [
        {"Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::prod-data/exports"},
        {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::prod-data*"},
    ])
    policy = parse_permission_policy(path)
    hits = {h["resource"] for h in reachable_resources(policy, CATALOG)}
    assert hits == {"prod-bucket"}


def test_role_name_defaults_to_filename(tmp_path):
    path = _write_policy(tmp_path, [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}])
    policy = parse_permission_policy(path)
    assert policy.role_name == "some-role"


def test_derive_resource_access_shapes_entries_for_the_graph_builder(tmp_path):
    path = _write_policy(tmp_path, [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::prod-data"},
    ])
    policy = parse_permission_policy(path)
    derived = derive_resource_access([policy], CATALOG)
    assert derived == [{
        "role": "some-role",
        "resource": "prod-bucket",
        "description": "prod data",
        "permission": "s3:GetObject",
        "source": "permission-policy",
    }]


def test_merge_prefers_manual_entry_over_derived_for_same_pair():
    manual = [{"role": "r", "resource": "res", "permission": "manual-note", "source": "manual"}]
    derived = [{"role": "r", "resource": "res", "permission": "s3:GetObject", "source": "permission-policy"}]
    merged = merge_resource_access(manual, derived)
    assert len(merged) == 1
    assert merged[0]["source"] == "manual"


def test_unsupported_not_statements_are_refused_not_ignored(tmp_path):
    import pytest
    path = _write_policy(tmp_path, [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}])
    with pytest.raises(ValueError, match="NotAction"):
        parse_permission_policy(path)


def test_malformed_policy_shapes_raise_value_error(tmp_path):
    import pytest
    for doc in ([], {"Statement": "x"}, {"Statement": [{"Effect": "Maybe", "Action": "s3:*", "Resource": "*"}]},
                {"Statement": [{"Effect": "Allow", "Action": [1], "Resource": "*"}]}):
        path = tmp_path / "bad.json"
        path.write_text(json.dumps(doc))
        with pytest.raises(ValueError):
            parse_permission_policy(path)


def test_condition_is_flagged_not_silently_ignored(tmp_path):
    path = _write_policy(tmp_path, [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::prod-data",
         "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}},
    ])
    hits = reachable_resources(parse_permission_policy(path), CATALOG)
    assert "Condition" in hits[0]["permission"]
