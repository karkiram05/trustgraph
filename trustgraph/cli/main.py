from __future__ import annotations

import json
import re
from pathlib import Path

import click

from trustgraph.detections.base import Severity
from trustgraph.detections.engine import run_detections
from trustgraph.graph.builder import (
    build_graph,
    derive_resource_access,
    load_resource_access,
    merge_resource_access,
)
from trustgraph.parsers.github_actions import parse_workflow
from trustgraph.parsers.iam_permissions import load_resource_catalog, parse_permission_policy
from trustgraph.parsers.iam_trust import parse_trust_policy

STATE_DIR = ".trustgraph"

# C0/C1 control characters, which covers ANSI escape sequences. Workflow
# files from a scanned repo are attacker-controlled, and an action name or
# step name containing ESC sequences could otherwise rewrite the user's
# terminal (hide lines, fake output) when findings are printed.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _safe(text) -> str:
    return _CONTROL_CHARS.sub("?", str(text))


def _echo(text="", **kwargs) -> None:
    click.echo(_safe(text), **kwargs)


def _inside(target: Path, path: Path) -> bool:
    """True if PATH, after resolving symlinks, is still inside TARGET."""
    try:
        path.resolve().relative_to(target.resolve())
        return True
    except ValueError:
        return False


def _only_inside(target: Path, paths: list[Path]) -> list[Path]:
    kept = []
    for p in paths:
        if _inside(target, p) and p.is_file():
            kept.append(p)
        else:
            _echo(f"Skipping {p}: symlink pointing outside the scanned directory.", err=True)
    return kept


def _discover_workflows(target: Path) -> list[Path]:
    wf_dir = target / ".github" / "workflows"
    if not wf_dir.exists():
        found = sorted(target.glob("*.yml")) + sorted(target.glob("*.yaml"))
    else:
        found = sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml"))
    return _only_inside(target, found)


def _discover_trust_policies(target: Path) -> list[Path]:
    tp_dir = target / "trust-policies"
    if tp_dir.exists():
        return _only_inside(target, sorted(tp_dir.glob("*.json")))
    return []


def _state_dir(target: Path, *, create: bool) -> Path:
    """The .trustgraph/ output directory, refusing symlinks.

    The scanned repo is untrusted. If it ships `.trustgraph` (or
    `.trustgraph/findings.json`) as a symlink, writing scan output would
    follow it and overwrite a file anywhere the user can write.
    """
    state = target / STATE_DIR
    if state.is_symlink():
        raise click.ClickException(f"{state} is a symlink; refusing to write scan output through it.")
    if create:
        state.mkdir(exist_ok=True)
    for name in ("findings.json", "graph.json"):
        if (state / name).is_symlink():
            raise click.ClickException(f"{state / name} is a symlink; refusing to use it.")
    return state


def _discover_permission_policies(target: Path) -> list[Path]:
    pp_dir = target / "permission-policies"
    if pp_dir.exists():
        return _only_inside(target, sorted(pp_dir.glob("*.json")))
    return []


@click.group()
@click.version_option()
def cli():
    """TrustGraph -- attack-path analysis for CI/CD and cloud trust."""


@cli.command()
@click.argument("target", type=click.Path(exists=True, file_okay=False), default=".")
@click.option("--repo-name", default=None, help="Override the detected repository name.")
@click.option("--trust-policy", "extra_policies", multiple=True, type=click.Path(exists=True),
              help="Additional trust policy JSON file(s), beyond trust-policies/*.json.")
@click.option("--resources", type=click.Path(exists=True), default=None,
              help="JSON file mapping roles to the cloud resources they can access.")
@click.option("--known-resources", type=click.Path(exists=True), default=None,
              help="JSON inventory of resource ARNs to check permission policies against "
                   "(default: known-resources.json in TARGET).")
@click.option("--json", "json_out", type=click.Path(), default=None, help="Write findings as JSON to this path.")
def scan(target, repo_name, extra_policies, resources, known_resources, json_out):
    """Scan TARGET (a repo checkout) for workflow and trust-policy findings."""
    target_path = Path(target)

    workflow_paths = _discover_workflows(target_path)
    policy_paths = list(_discover_trust_policies(target_path)) + [Path(p) for p in extra_policies]

    if not workflow_paths and not policy_paths:
        _echo("No workflows (.github/workflows/*.yml) or trust-policies/*.json found.", err=True)
        raise SystemExit(1)

    try:
        workflows = [parse_workflow(p) for p in workflow_paths]
        trust_policies = [parse_trust_policy(p) for p in policy_paths]

        resource_path = Path(resources) if resources else (target_path / "resources.json")
        if not resources and resource_path.exists() and not _inside(target_path, resource_path):
            raise ValueError(f"{resource_path}: symlink pointing outside the scanned directory")
        manual_access = load_resource_access(resource_path) if resource_path.exists() else []

        perm_policy_paths = _discover_permission_policies(target_path)
        catalog_path = Path(known_resources) if known_resources else (target_path / "known-resources.json")
        if not known_resources and catalog_path.exists() and not _inside(target_path, catalog_path):
            raise ValueError(f"{catalog_path}: symlink pointing outside the scanned directory")
        derived_access = []
        if perm_policy_paths and catalog_path.exists():
            permission_policies = [parse_permission_policy(p) for p in perm_policy_paths]
            derived_access = derive_resource_access(permission_policies, load_resource_catalog(catalog_path))

        resource_access = merge_resource_access(manual_access, derived_access)

        graph = build_graph(workflows, trust_policies, resource_access, repo_name=repo_name)
    except (ValueError, OSError) as exc:
        # yaml.YAMLError and json.JSONDecodeError are ValueError/Exception
        # subclasses with readable messages; show them, not a traceback.
        raise click.ClickException(_safe(exc)) from exc
    except Exception as exc:  # noqa: BLE001 -- e.g. yaml.YAMLError
        raise click.ClickException(f"Could not parse input: {_safe(exc)}") from exc
    findings = run_detections(workflows, trust_policies, graph, repo_name=repo_name)

    state_dir = _state_dir(target_path, create=True)
    (state_dir / "findings.json").write_text(json.dumps([f.to_dict() for f in findings], indent=2))
    (state_dir / "graph.json").write_text(json.dumps(graph.to_dict(), indent=2))

    if json_out:
        Path(json_out).write_text(json.dumps([f.to_dict() for f in findings], indent=2))

    summary = f"Scanned {len(workflow_paths)} workflow(s), {len(policy_paths)} trust polic{'y' if len(policy_paths)==1 else 'ies'}"
    if perm_policy_paths:
        summary += f", {len(perm_policy_paths)} permission polic{'y' if len(perm_policy_paths)==1 else 'ies'} ({len(derived_access)} resource(s) reachable)"
    _echo(summary + ".\n")
    if not findings:
        _echo("No findings. ✓")
        return

    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    _echo("SECURITY OVERVIEW\n")
    for sev in Severity:
        if counts[sev]:
            _echo(f"  {sev.value:<10} {counts[sev]}")
    _echo()

    for f in findings:
        _echo(f"[{f.severity.value}] {f.id}  {f.title}")
        _echo(f"    entry point: {f.entry_point}")
    _echo(f"\nRun `trustgraph explain <id>` for detail, `trustgraph fix <id>` for a suggested patch.")


@cli.command()
@click.argument("finding_id")
@click.option("--in", "target", type=click.Path(exists=True, file_okay=False), default=".")
def explain(finding_id, target):
    """Show the full attack-path explanation for a finding."""
    findings = _load_findings(Path(target))
    finding = _find(findings, finding_id)

    _echo(f"Finding: {finding['id']}")
    _echo(f"Risk: {finding['severity']}\n")
    _echo(f"Entry point:\n  {finding['entry_point']}\n")
    _echo(f"Problem:\n  {finding['problem']}\n")
    _echo(f"Cloud trust:\n  {finding['cloud_trust']}\n")
    _echo(f"Result:\n  {finding['result']}\n")
    if finding["path"]:
        _echo("Attack path:")
        _echo("  " + "\n        ↓\n  ".join(finding["path"]))
        _echo()
    _echo("Recommended remediation:")
    for i, step in enumerate(finding["remediation"], 1):
        _echo(f"  {i}. {step}")


@cli.command()
@click.argument("finding_id")
@click.option("--in", "target", type=click.Path(exists=True, file_okay=False), default=".")
def fix(finding_id, target):
    """Show a concrete before/after patch for a finding, where one is mechanical."""
    from trustgraph.remediation.suggest import suggest_patch

    findings = _load_findings(Path(target))
    finding = _find(findings, finding_id)
    _echo(f"Finding: {finding['id']} -- {finding['title']}\n")
    for i, step in enumerate(finding["remediation"], 1):
        _echo(f"  {i}. {step}")

    # suggest_patch needs the raw objects, which aren't in the serialized
    # finding -- for the mechanical rules we can reconstruct a patch preview
    # from evidence alone.
    ev = finding["evidence"]
    if finding["rule_id"] == "overpermissioned-token":
        extra = ev["extra_scopes"]
        before = "\n".join([f"  {s}: write" for s in ["id-token", *extra]])
        _echo(f"\npermissions:\n{before}\n\n->\n\npermissions:\n  id-token: write\n  contents: read")
    elif finding["rule_id"] == "unpinned-action" and ev.get("kind") == "docker":
        _echo(f"\n- uses: {ev['uses']}:{ev.get('ref', '')}\n+ uses: {ev['uses']}@sha256:<image-digest>")
    elif finding["rule_id"] == "unpinned-action":
        _echo(f"\n- uses: {ev['uses']}@{ev.get('ref', '')}\n+ uses: {ev['uses']}@<full-40-char-commit-sha>  # {ev.get('ref', '')}")
    else:
        _echo("\n(No mechanical patch preview for this rule -- see remediation steps above.)")


def _load_findings(target: Path) -> list[dict]:
    path = _state_dir(target, create=False) / "findings.json"
    if not path.exists():
        raise click.ClickException(f"No scan results found under {target}. Run `trustgraph scan` first.")
    return json.loads(path.read_text())


def _find(findings: list[dict], finding_id: str) -> dict:
    for f in findings:
        if f["id"] == finding_id:
            return f
    raise click.ClickException(f"No finding with id {finding_id}.")


if __name__ == "__main__":
    cli()
