"""Parses a GitHub Actions workflow YAML file into a typed model.

Deliberately doesn't try to be a full GitHub Actions schema validator --
it extracts exactly what the detection rules need: permission scopes
(workflow- and job-level), the OIDC token request, and every third-party
action reference with whether it's pinned to a commit SHA.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from trustgraph.parsers._io import read_capped

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# GitHub's own default token permissions when a workflow specifies none at
# all -- these vary by repo/org setting (classic default is broad "write",
# newer defaults are restricted "read"). We can't know which applies to a
# given repo from the YAML alone, so we surface this as "unspecified"
# rather than silently assuming one or the other -- see docs/architecture.md.
UNSPECIFIED = "unspecified"


@dataclass
class ActionUse:
    raw: str            # e.g. "actions/checkout@v4"
    uses: str            # e.g. "actions/checkout"
    ref: str             # e.g. "v4" or a 40-char SHA
    step_name: str | None = None
    # "action" (a step's `uses:`), "reusable-workflow" (a job's `uses:`,
    # which runs another repo's whole workflow) or "docker" (docker://).
    kind: str = "action"

    @property
    def pinned(self) -> bool:
        if self.kind == "docker":
            return bool(_DIGEST_RE.match(self.ref))
        return bool(_SHA_RE.match(self.ref))

    @property
    def repository(self) -> str | None:
        """`owner/repo` the reference points into (None for docker images)."""
        if self.kind == "docker":
            return None
        parts = self.uses.split("/")
        return "/".join(parts[:2]).lower() if len(parts) >= 2 else None

    @property
    def is_third_party(self) -> bool:
        # actions/* and github/* are GitHub-maintained; still worth noting
        # in the graph, but not treated as "third party" for blast-radius
        # framing the same way an arbitrary org's action is.
        if self.kind == "docker":
            return True
        owner = self.uses.split("/")[0] if "/" in self.uses else self.uses
        return owner not in {"actions", "github"}


@dataclass
class Job:
    id: str
    permissions: dict[str, str] | str | None  # None = not specified at job level
    steps: list[ActionUse] = field(default_factory=list)
    runs_on: str | None = None
    # Set when the job calls a reusable workflow (`jobs.<id>.uses`) instead
    # of running steps.
    reusable_workflow: ActionUse | None = None

    def action_uses(self) -> list[ActionUse]:
        return self.steps + ([self.reusable_workflow] if self.reusable_workflow else [])

    def requests_id_token(self) -> bool:
        return _permission_level(self.permissions, "id-token") == "write"


@dataclass
class Workflow:
    path: str
    name: str
    on: list[str]
    permissions: dict[str, str] | str | None  # workflow-level default
    jobs: list[Job] = field(default_factory=list)

    def effective_permission(self, job: Job, scope: str) -> str:
        """Job-level permissions fully override workflow-level (per GitHub's
        own semantics: specifying `permissions:` on a job replaces the
        workflow default for that job, it doesn't merge with it)."""
        if job.permissions is not None:
            return _permission_level(job.permissions, scope)
        return _permission_level(self.permissions, scope)

    def all_action_uses(self) -> list[ActionUse]:
        return [a for job in self.jobs for a in job.action_uses()]

    def job_requests_id_token(self, job: Job) -> bool:
        return self.effective_permission(job, "id-token") == "write"

    def any_job_requests_id_token(self) -> bool:
        return any(
            self.effective_permission(job, "id-token") == "write"
            for job in self.jobs
        )


def _permission_level(permissions: dict[str, str] | str | None, scope: str) -> str:
    if permissions is None:
        return UNSPECIFIED
    if isinstance(permissions, str):
        # "read-all" / "write-all" / "{}" (none)
        if permissions == "write-all":
            return "write"
        if permissions == "read-all":
            return "read"
        return "none"
    return permissions.get(scope, "none")


def _parse_action_use(raw: str, step_name: str | None, *, job_level: bool = False) -> ActionUse | None:
    if not isinstance(raw, str):
        return None
    raw = raw.strip()
    if raw.startswith("./"):
        # Local action or local reusable workflow: same repo, same commit.
        return None
    if raw.startswith("docker://"):
        image = raw.removeprefix("docker://")
        if "@" in image:
            name, digest = image.split("@", 1)
        else:
            # Tag (or no tag at all, i.e. :latest): mutable either way.
            name, _, tag = image.partition(":")
            digest = tag or "latest"
        return ActionUse(raw=raw, uses=f"docker://{name}", ref=digest,
                         step_name=step_name, kind="docker")
    if "@" not in raw:
        return None
    uses, ref = raw.rsplit("@", 1)
    return ActionUse(raw=raw, uses=uses, ref=ref, step_name=step_name,
                     kind="reusable-workflow" if job_level else "action")


def parse_workflow(path: str | Path) -> Workflow:
    path = Path(path)
    doc = yaml.safe_load(read_capped(path))

    if not isinstance(doc, dict):
        raise ValueError(f"{path}: not a valid workflow document")

    on = doc.get("on", doc.get(True, []))  # PyYAML may parse bare `on:` as True
    if isinstance(on, str):
        on = [on]
    elif isinstance(on, dict):
        on = list(on.keys())
    elif not isinstance(on, list):
        on = []

    workflow_permissions = doc.get("permissions")

    jobs: list[Job] = []
    for job_id, job_doc in (doc.get("jobs") or {}).items():
        if not isinstance(job_doc, dict):
            continue
        steps = []
        for step in job_doc.get("steps", []) or []:
            if not isinstance(step, dict):
                continue
            uses_raw = step.get("uses")
            if uses_raw:
                action = _parse_action_use(uses_raw, step.get("name"))
                if action:
                    steps.append(action)
        reusable = None
        if job_doc.get("uses"):
            reusable = _parse_action_use(job_doc["uses"], job_doc.get("name"), job_level=True)
        jobs.append(Job(
            id=str(job_id),
            permissions=job_doc.get("permissions"),
            steps=steps,
            runs_on=job_doc.get("runs-on"),
            reusable_workflow=reusable,
        ))

    return Workflow(
        path=str(path),
        name=doc.get("name", path.stem),
        on=on,
        permissions=workflow_permissions,
        jobs=jobs,
    )
