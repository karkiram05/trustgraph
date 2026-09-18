"""Turns a raw detection into remediation text and, where the fix is
mechanical, a concrete before/after patch a person can apply by hand."""
from __future__ import annotations


def suggest_remediation(rule_id: str, raw: dict) -> list[str]:
    if rule_id == "overpermissioned-token":
        extra = ", ".join(raw["extra_scopes"])
        return [
            f"Drop `{extra}: write` from job `{raw['job_id']}` -- the OIDC "
            "token exchange only needs `id-token: write`.",
            "If the job genuinely needs to push commits or trigger workflows, "
            "scope that to a separate job that does NOT also hold id-token: write, "
            "so a single compromised step can't do both at once.",
            "Set `permissions: {}` at the workflow level and grant only what "
            "each job needs, rather than relying on the repository/org default.",
        ]
    if rule_id == "wildcard-oidc-trust":
        return [
            "Restrict the trust policy's `token.actions.githubusercontent.com:sub` "
            "condition to a specific repository, ref, and (ideally) GitHub "
            "Environment -- e.g. `repo:my-org/my-repo:environment:production` "
            "instead of `repo:my-org/*:*`.",
            "Use `StringEquals` instead of `StringLike` once the value is exact; "
            "`StringLike` should only be used when a wildcard is genuinely required.",
            "If multiple repos legitimately need this role, list them as separate "
            "explicit patterns rather than one broad wildcard.",
        ]
    if rule_id == "missing-audience-restriction":
        return [
            "Add a `StringEquals` condition on `token.actions.githubusercontent.com:aud` "
            "pinned to `sts.amazonaws.com` in the trust policy, in addition to any "
            "provider-level audience check.",
        ]
    if rule_id == "unpinned-action":
        action = raw["action"]
        note = (
            " This action runs in a workflow that also requests a cloud OIDC "
            "token, so a compromised tag on this action can reach whatever "
            "that token can reach."
            if raw["elevated_context"] else ""
        )
        return [
            f"Pin `{action.uses}@{action.ref}` to a full 40-character commit SHA "
            f"instead of a mutable tag/branch, e.g. "
            f"`{action.uses}@<commit-sha>  # {action.ref}`.{note}",
            "Enable Dependabot version updates for GitHub Actions "
            "(`.github/dependabot.yml`, `package-ecosystem: github-actions`) "
            "so pinned SHAs still get bumped automatically via reviewed PRs.",
        ]
    return ["No automated remediation available for this rule yet."]


def suggest_patch(rule_id: str, raw: dict) -> str | None:
    """A literal before/after snippet for the mechanical fixes."""
    if rule_id == "overpermissioned-token":
        extra = raw["extra_scopes"]
        before = "\n".join([f"  {s}: write" for s in ["id-token", *extra]])
        after = "  id-token: write"
        return f"permissions:\n{before}\n\n->\n\npermissions:\n{after}\n  contents: read"
    if rule_id == "unpinned-action":
        action = raw["action"]
        return (
            f"- uses: {action.uses}@{action.ref}\n"
            f"+ uses: {action.uses}@<full-40-char-commit-sha>  # {action.ref}"
        )
    if rule_id == "wildcard-oidc-trust":
        policy = raw["policy"]
        bad = policy.subject_patterns[0] if policy.subject_patterns else "repo:org/*:*"
        return (
            f'- "token.actions.githubusercontent.com:sub": "{bad}"\n'
            f'+ "token.actions.githubusercontent.com:sub": "repo:org/repo:ref:refs/heads/main"'
        )
    return None
