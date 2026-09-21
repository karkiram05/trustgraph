"""Parses an IAM identity-based permission policy (the JSON attached to a
role that says what it can actually do) and figures out which resources
in a supplied catalog it can reach.

Scope, on purpose: this only evaluates identity-based policies on a single
role. It does not merge in service control policies, permission boundaries,
resource-based policies (bucket policies, KMS key policies), or session
policies -- any of those can further restrict what a role can actually do,
and a real IAM simulation has to account for all of them. Folding that in
here would be exactly the "simplified, and likely wrong" permission engine
docs/architecture.md warns against. What this does cover -- Allow/Deny,
explicit-deny-wins, and wildcard matching on both Action and Resource -- is
the part of IAM evaluation that's well-defined enough to get right, and it's
also the part that answers TrustGraph's actual question: does this policy,
read literally, grant a path to this resource.
"""
from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path

from trustgraph.parsers._io import read_capped

MAX_PATTERN_LEN = 512


@dataclass
class Statement:
    effect: str
    actions: list[str]
    resources: list[str]
    has_condition: bool = False


@dataclass
class PermissionPolicy:
    path: str
    role_name: str
    statements: list[Statement] = field(default_factory=list)


def _string_list(value, what: str, path) -> list[str]:
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, list) or not all(isinstance(i, str) and len(i) <= MAX_PATTERN_LEN for i in items):
        raise ValueError(f"{path}: {what} must be a string or a list of short strings")
    return items


def parse_permission_policy(path: str | Path, role_name: str | None = None) -> PermissionPolicy:
    path = Path(path)
    doc = json.loads(read_capped(path))
    if not isinstance(doc, dict):
        raise ValueError(f"{path}: a policy document must be a JSON object")

    role_name = role_name or path.stem

    raw_statements = doc.get("Statement", [])
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]
    if not isinstance(raw_statements, list):
        raise ValueError(f"{path}: Statement must be an object or a list")

    statements = []
    for stmt in raw_statements:
        if not isinstance(stmt, dict):
            raise ValueError(f"{path}: every Statement entry must be an object")
        if "NotAction" in stmt or "NotResource" in stmt:
            raise ValueError(f"{path}: NotAction/NotResource statements are not supported")
        effect = stmt.get("Effect")
        if effect not in ("Allow", "Deny"):
            raise ValueError(f"{path}: Effect must be Allow or Deny, got {effect!r}")
        statements.append(Statement(
            effect=effect,
            actions=_string_list(stmt.get("Action", []), "Action", path),
            resources=_string_list(stmt.get("Resource", []), "Resource", path),
            has_condition=bool(stmt.get("Condition")),
        ))

    return PermissionPolicy(path=str(path), role_name=role_name, statements=statements)


def load_resource_catalog(path: str | Path) -> list[dict]:
    """A small JSON file naming the ARNs that exist, so we have something to
    check reachability against. Unlike resources.json this doesn't say who
    can reach what, it's just an inventory (arn, name, description)."""
    data = json.loads(read_capped(Path(path)))
    if not isinstance(data, list) or not all(
        isinstance(e, dict) and isinstance(e.get("arn"), str) and isinstance(e.get("name"), str) for e in data
    ):
        raise ValueError(f"{path}: expected a list of {{\"arn\": str, \"name\": str}} objects")
    return data


def _action_matches(pattern: str, action: str) -> bool:
    return fnmatch.fnmatch(action.lower(), pattern.lower())


def _resource_matches(pattern: str, arn: str) -> bool:
    return fnmatch.fnmatch(arn, pattern)


def reachable_resources(policy: PermissionPolicy, catalog: list[dict], action: str = "*") -> list[dict]:
    """For each resource in the catalog, check whether this policy grants
    `action` against it: an explicit Deny on a matching action+resource
    wins over any Allow, matching real IAM evaluation order.

    `action` defaults to "*" (any action) since TrustGraph cares about
    reachability, not which specific API call gets you there -- but the
    matched action is still returned per-resource for the finding text.
    """
    results = []
    for entry in catalog:
        arn = entry["arn"]
        allowed_action = None
        allowed_conditional = False
        denied = False

        for stmt in policy.statements:
            resource_hit = any(_resource_matches(p, arn) for p in stmt.resources)
            if not resource_hit:
                continue
            if action == "*":
                action_hit_patterns = stmt.actions
            else:
                action_hit_patterns = [p for p in stmt.actions if _action_matches(p, action)]
            if not action_hit_patterns:
                continue

            if stmt.effect == "Deny":
                denied = True
                break
            if stmt.effect == "Allow" and allowed_action is None:
                allowed_action = action_hit_patterns[0]
                allowed_conditional = stmt.has_condition

        if allowed_action and not denied:
            results.append({
                "resource": entry["name"],
                "arn": arn,
                "description": entry.get("description", ""),
                "permission": allowed_action + (" (has a Condition, not evaluated)" if allowed_conditional else ""),
            })

    return results
