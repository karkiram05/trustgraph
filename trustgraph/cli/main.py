from __future__ import annotations

import json
from pathlib import Path

import click

from trustgraph.detections.base import Severity
from trustgraph.detections.engine import run_detections
from trustgraph.graph.builder import build_graph, load_resource_access
from trustgraph.parsers.github_actions import parse_workflow
from trustgraph.parsers.iam_trust import parse_trust_policy

STATE_DIR = ".trustgraph"


def _discover_workflows(target: Path) -> list[Path]:
    wf_dir = target / ".github" / "workflows"
    if not wf_dir.exists():
        return sorted(target.glob("*.yml")) + sorted(target.glob("*.yaml"))
    return sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml"))


def _discover_trust_policies(target: Path) -> list[Path]:
    tp_dir = target / "trust-policies"
    if tp_dir.exists():
        return sorted(tp_dir.glob("*.json"))
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
@click.option("--json", "json_out", type=click.Path(), default=None, help="Write findings as JSON to this path.")
def scan(target, repo_name, extra_policies, resources, json_out):
    """Scan TARGET (a repo checkout) for workflow and trust-policy findings."""
    target_path = Path(target)

    workflow_paths = _discover_workflows(target_path)
    policy_paths = list(_discover_trust_policies(target_path)) + [Path(p) for p in extra_policies]

    if not workflow_paths and not policy_paths:
        click.echo("No workflows (.github/workflows/*.yml) or trust-policies/*.json found.", err=True)
        raise SystemExit(1)

    workflows = [parse_workflow(p) for p in workflow_paths]
    trust_policies = [parse_trust_policy(p) for p in policy_paths]

    resource_path = Path(resources) if resources else (target_path / "resources.json")
    resource_access = load_resource_access(resource_path) if resource_path.exists() else []

    graph = build_graph(workflows, trust_policies, resource_access, repo_name=repo_name)
    findings = run_detections(workflows, trust_policies, graph, repo_name=repo_name)

    state_dir = target_path / STATE_DIR
    state_dir.mkdir(exist_ok=True)
    (state_dir / "findings.json").write_text(json.dumps([f.to_dict() for f in findings], indent=2))
    (state_dir / "graph.json").write_text(json.dumps(graph.to_dict(), indent=2))

    if json_out:
        Path(json_out).write_text(json.dumps([f.to_dict() for f in findings], indent=2))

    click.echo(f"Scanned {len(workflow_paths)} workflow(s), {len(policy_paths)} trust polic{'y' if len(policy_paths)==1 else 'ies'}.\n")
    if not findings:
        click.echo("No findings. ✓")
        return

    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    click.echo("SECURITY OVERVIEW\n")
    for sev in Severity:
        if counts[sev]:
            click.echo(f"  {sev.value:<10} {counts[sev]}")
    click.echo()

    for f in findings:
        click.echo(f"[{f.severity.value}] {f.id}  {f.title}")
        click.echo(f"    entry point: {f.entry_point}")
    click.echo(f"\nRun `trustgraph explain <id>` for detail, `trustgraph fix <id>` for a suggested patch.")


@cli.command()
@click.argument("finding_id")
@click.option("--in", "target", type=click.Path(exists=True, file_okay=False), default=".")
def explain(finding_id, target):
    """Show the full attack-path explanation for a finding."""
    findings = _load_findings(Path(target))
    finding = _find(findings, finding_id)

    click.echo(f"Finding: {finding['id']}")
    click.echo(f"Risk: {finding['severity']}\n")
    click.echo(f"Entry point:\n  {finding['entry_point']}\n")
    click.echo(f"Problem:\n  {finding['problem']}\n")
    click.echo(f"Cloud trust:\n  {finding['cloud_trust']}\n")
    click.echo(f"Result:\n  {finding['result']}\n")
    if finding["path"]:
        click.echo("Attack path:")
        click.echo("  " + "\n        ↓\n  ".join(finding["path"]))
        click.echo()
    click.echo("Recommended remediation:")
    for i, step in enumerate(finding["remediation"], 1):
        click.echo(f"  {i}. {step}")


@cli.command()
@click.argument("finding_id")
@click.option("--in", "target", type=click.Path(exists=True, file_okay=False), default=".")
def fix(finding_id, target):
    """Show a concrete before/after patch for a finding, where one is mechanical."""
    from trustgraph.remediation.suggest import suggest_patch

    findings = _load_findings(Path(target))
    finding = _find(findings, finding_id)
    click.echo(f"Finding: {finding['id']} -- {finding['title']}\n")
    for i, step in enumerate(finding["remediation"], 1):
        click.echo(f"  {i}. {step}")

    # suggest_patch needs the raw objects, which aren't in the serialized
    # finding -- for the mechanical rules we can reconstruct a patch preview
    # from evidence alone.
    ev = finding["evidence"]
    if finding["rule_id"] == "overpermissioned-token":
        extra = ev["extra_scopes"]
        before = "\n".join([f"  {s}: write" for s in ["id-token", *extra]])
        click.echo(f"\npermissions:\n{before}\n\n->\n\npermissions:\n  id-token: write\n  contents: read")
    elif finding["rule_id"] == "unpinned-action":
        click.echo(f"\n- uses: {ev['uses']}@{ev.get('ref', '')}\n+ uses: {ev['uses']}@<full-40-char-commit-sha>  # {ev.get('ref', '')}")
    else:
        click.echo("\n(No mechanical patch preview for this rule -- see remediation steps above.)")


def _load_findings(target: Path) -> list[dict]:
    path = target / STATE_DIR / "findings.json"
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
