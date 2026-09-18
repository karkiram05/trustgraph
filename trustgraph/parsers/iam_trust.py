"""Parses an AWS IAM role trust policy (the JSON you'd attach to a role
that trusts GitHub's OIDC provider for `sts:AssumeRoleWithWebIdentity`).

Only models the GitHub Actions OIDC federation shape -- the one relevant
to the CI/CD attack paths this project cares about, not a general-purpose
IAM policy engine.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

GITHUB_OIDC_ISSUER = "token.actions.githubusercontent.com"


@dataclass
class TrustPolicy:
    path: str
    role_name: str
    federated_provider: str | None
    audience_values: list[str] = field(default_factory=list)     # from :aud condition
    subject_patterns: list[str] = field(default_factory=list)     # from :sub condition (StringLike or StringEquals)
    subject_condition_operator: str | None = None                 # "StringEquals" | "StringLike" | None

    def trusts_github_oidc(self) -> bool:
        return bool(self.federated_provider and GITHUB_OIDC_ISSUER in self.federated_provider)

    def audience_restricted(self) -> bool:
        """True only if the audience is pinned to exactly sts.amazonaws.com
        (GitHub's documented recommendation) -- an empty/missing condition
        means AWS's OIDC provider-level audience check is the only guard,
        which is weaker than pinning it here too."""
        return self.audience_values == ["sts.amazonaws.com"]

    def has_wildcard_subject(self) -> bool:
        return any("*" in pattern for pattern in self.subject_patterns)

    def subject_scoped_to_branch_or_env(self) -> bool:
        """A well-scoped subject pins a specific ref
        (repo:org/repo:ref:refs/heads/main) or environment
        (repo:org/repo:environment:prod), not just the repo, and doesn't
        wildcard within that ref/environment segment."""
        if not self.subject_patterns:
            return False
        for pattern in self.subject_patterns:
            if ":ref:" in pattern:
                tail = pattern.split(":ref:", 1)[1]
            elif ":environment:" in pattern:
                tail = pattern.split(":environment:", 1)[1]
            else:
                return False
            if "*" in tail:
                return False
        return True


def parse_trust_policy(path: str | Path, role_name: str | None = None) -> TrustPolicy:
    path = Path(path)
    with open(path) as f:
        doc = json.load(f)

    role_name = role_name or path.stem

    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    federated = None
    audience_values: list[str] = []
    subject_patterns: list[str] = []
    subject_operator = None

    for stmt in statements:
        if stmt.get("Action") not in ("sts:AssumeRoleWithWebIdentity", ["sts:AssumeRoleWithWebIdentity"]):
            continue
        principal = stmt.get("Principal", {})
        fed = principal.get("Federated")
        if fed:
            federated = fed if isinstance(fed, str) else (fed[0] if fed else None)

        condition = stmt.get("Condition", {})
        for operator in ("StringEquals", "StringLike"):
            cond = condition.get(operator, {})
            for key, value in cond.items():
                values = value if isinstance(value, list) else [value]
                if key.endswith(":aud"):
                    audience_values.extend(values)
                elif key.endswith(":sub"):
                    subject_patterns.extend(values)
                    subject_operator = operator

    return TrustPolicy(
        path=str(path),
        role_name=role_name,
        federated_provider=federated,
        audience_values=audience_values,
        subject_patterns=subject_patterns,
        subject_condition_operator=subject_operator,
    )
