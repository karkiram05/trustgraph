"""Tests for parser coverage gaps and CLI hardening against hostile repos.

The scanner reads repositories it doesn't control, so these cover what a
malicious or merely odd repo can throw at it: symlinks out of the target,
terminal escape sequences, oversized files, malformed inputs.
"""
import json
import os

import pytest
from click.testing import CliRunner

from trustgraph.cli.main import cli
from trustgraph.detections.base import Severity
from trustgraph.detections.engine import run_detections
from trustgraph.graph.builder import build_graph, load_resource_access
from trustgraph.parsers._io import MAX_FILE_BYTES
from trustgraph.parsers.github_actions import parse_workflow


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def scan_findings(wf_path):
    wf = parse_workflow(wf_path)
    graph = build_graph([wf], [], [], repo_name="org/repo")
    return run_detections([wf], [], graph, repo_name="org/repo")


# --- parser coverage ------------------------------------------------------

def test_unpinned_reusable_workflow_is_flagged(tmp_path):
    wf = write(tmp_path / "w.yml", """
on: push
jobs:
  call:
    uses: other-org/shared/.github/workflows/build.yml@v1
""")
    findings = scan_findings(wf)
    assert len(findings) == 1
    assert findings[0].title == "Unpinned third-party reusable workflow: other-org/shared/.github/workflows/build.yml"
    assert findings[0].evidence["kind"] == "reusable-workflow"


def test_local_reusable_workflow_and_local_action_are_ignored(tmp_path):
    wf = write(tmp_path / "w.yml", """
on: push
jobs:
  call:
    uses: ./.github/workflows/build.yml
  steps-job:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/setup
""")
    assert scan_findings(wf) == []


def test_docker_tag_is_flagged_and_digest_is_pinned(tmp_path):
    digest = "sha256:" + "a" * 64
    wf = write(tmp_path / "w.yml", f"""
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine:3.20
      - uses: docker://alpine@{digest}
""")
    findings = scan_findings(wf)
    assert len(findings) == 1
    assert findings[0].evidence == {
        "uses": "docker://alpine", "ref": "3.20", "elevated_context": False,
        "job": "build", "kind": "docker",
    }


def test_elevation_is_per_job_not_per_workflow(tmp_path):
    # The deploy job requests an OIDC token but only uses a pinned action.
    # The lint job uses an unpinned third-party action but has no id-token,
    # so it can't mint that credential: MEDIUM, not HIGH.
    sha = "b" * 40
    wf = write(tmp_path / "w.yml", f"""
on: push
permissions: {{}}
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@{sha}
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/linter@v2
""")
    findings = scan_findings(wf)
    assert [(f.severity, f.evidence["job"]) for f in findings] == [(Severity.MEDIUM, "lint")]


def test_unpinned_action_in_the_oidc_job_is_still_elevated(tmp_path):
    wf = write(tmp_path / "w.yml", """
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: some-org/deployer@v1
""")
    findings = scan_findings(wf)
    assert [f.severity for f in findings] == [Severity.HIGH]


def test_non_mapping_steps_do_not_crash_the_parser(tmp_path):
    wf = write(tmp_path / "w.yml", """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - "just a string"
      - uses: actions/checkout@v4
""")
    assert len(parse_workflow(wf).jobs[0].steps) == 1


def test_reference_back_into_the_scanned_repo_is_not_third_party(tmp_path):
    wf = write(tmp_path / "w.yml", """
on: push
jobs:
  shared:
    uses: Org/Repo/.github/workflows/shared.yml@main
  other:
    uses: other-org/repo/.github/workflows/shared.yml@main
""")
    findings = scan_findings(wf)  # scanned as org/repo
    assert [f.evidence["uses"] for f in findings] == ["other-org/repo/.github/workflows/shared.yml"]


def test_same_org_different_repo_is_still_flagged(tmp_path):
    wf = write(tmp_path / "w.yml", """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: org/other-repo@v1
""")
    assert len(scan_findings(wf)) == 1


# --- hostile-repo hardening -----------------------------------------------

def test_oversized_workflow_is_refused(tmp_path):
    target = tmp_path / "repo"
    big = "# padding\n" * (MAX_FILE_BYTES // 10 + 1)
    write(target / ".github" / "workflows" / "big.yml", "on: push\njobs: {}\n" + big)
    result = CliRunner().invoke(cli, ["scan", str(target)])
    assert result.exit_code != 0
    assert "input limit" in result.output


def test_symlinked_state_dir_is_refused(tmp_path):
    target = tmp_path / "repo"
    write(target / ".github" / "workflows" / "w.yml", "on: push\njobs: {}\n")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.symlink(elsewhere, target / ".trustgraph")
    result = CliRunner().invoke(cli, ["scan", str(target)])
    assert result.exit_code != 0
    assert "symlink" in result.output
    assert list(elsewhere.iterdir()) == []


def test_symlinked_findings_file_is_refused(tmp_path):
    target = tmp_path / "repo"
    write(target / ".github" / "workflows" / "w.yml", "on: push\njobs: {}\n")
    victim = write(tmp_path / "victim.txt", "do not overwrite")
    (target / ".trustgraph").mkdir()
    os.symlink(victim, target / ".trustgraph" / "findings.json")
    result = CliRunner().invoke(cli, ["scan", str(target)])
    assert result.exit_code != 0
    assert victim.read_text() == "do not overwrite"


def test_workflow_symlink_pointing_outside_target_is_skipped(tmp_path):
    target = tmp_path / "repo"
    write(target / ".github" / "workflows" / "real.yml", "on: push\njobs: {}\n")
    outside = write(tmp_path / "secret.yml", "on: push\njobs: {}\n")
    os.symlink(outside, target / ".github" / "workflows" / "link.yml")
    result = CliRunner().invoke(cli, ["scan", str(target)])
    assert result.exit_code == 0
    assert "Scanned 1 workflow(s)" in result.output
    assert "Skipping" in result.output


def test_terminal_escape_sequences_are_neutralised(tmp_path):
    target = tmp_path / "repo"
    write(target / ".github" / "workflows" / "w.yml", """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: "evil-org/x\\u001b[2Jcleared@v1"
""")
    result = CliRunner().invoke(cli, ["scan", str(target)])
    assert result.exit_code == 0
    assert "\x1b" not in result.output
    assert "evil-org/x?[2Jcleared" in result.output


def test_malformed_yaml_gives_a_clean_error(tmp_path):
    target = tmp_path / "repo"
    write(target / ".github" / "workflows" / "w.yml", "on: [push\njobs: {")
    result = CliRunner().invoke(cli, ["scan", str(target)])
    assert result.exit_code != 0
    assert "Traceback" not in result.output


def test_resources_json_must_be_a_list_of_role_resource_objects(tmp_path):
    bad = write(tmp_path / "resources.json", json.dumps({"role": "x"}))
    with pytest.raises(ValueError):
        load_resource_access(bad)


def test_yaml_alias_bomb_does_not_blow_up(tmp_path):
    # 516 bytes that logically expand to 10**8 list entries. safe_load keeps
    # aliases as shared references and the parser skips non-mapping steps,
    # so this must stay fast and small.
    lines = ["on: push", 'a0: &a0 ["x","x","x","x","x","x","x","x","x","x"]']
    for i in range(1, 9):
        lines.append(f"a{i}: &a{i} [" + ",".join([f"*a{i - 1}"] * 10) + "]")
    lines += ["jobs:", "  build:", "    runs-on: ubuntu-latest", "    steps: *a8"]
    target = tmp_path / "repo"
    write(target / ".github" / "workflows" / "bomb.yml", "\n".join(lines) + "\n")
    result = CliRunner().invoke(cli, ["scan", str(target)])
    assert result.exit_code == 0
    assert "No findings" in result.output
