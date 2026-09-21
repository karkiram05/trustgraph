import json

from click.testing import CliRunner

from tests.conftest import EXAMPLES_DIR
from trustgraph.cli.main import cli


def test_scan_vulnerable_project_reports_findings(tmp_path):
    runner = CliRunner()
    # Copy example into tmp so we don't leave .trustgraph/ artifacts in the repo.
    import shutil
    target = tmp_path / "vulnerable-project"
    shutil.copytree(EXAMPLES_DIR / "vulnerable-project", target)

    result = runner.invoke(cli, ["scan", str(target), "--repo-name", "my-org/vulnerable-project"])
    assert result.exit_code == 0
    assert "CRITICAL" in result.output
    assert (target / ".trustgraph" / "findings.json").exists()


def test_scan_reaches_same_findings_from_permission_policy_alone(tmp_path):
    # Same example, but delete the hand-typed resources.json first -- if the
    # permission-policy + known-resources.json auto-derivation actually
    # works, the CRITICAL findings for the reachable S3 bucket and RDS
    # instance should still show up, computed rather than asserted.
    import shutil
    target = tmp_path / "vulnerable-project-auto"
    shutil.copytree(EXAMPLES_DIR / "vulnerable-project", target)
    (target / "resources.json").unlink()

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(target), "--repo-name", "my-org/vulnerable-project"])
    assert result.exit_code == 0
    assert "CRITICAL" in result.output
    assert "permission polic" in result.output

    findings = json.loads((target / ".trustgraph" / "findings.json").read_text())
    critical_paths = [f["path"] for f in findings if f["severity"] == "CRITICAL" and f["path"]]
    assert any("prod-customer-data-s3-bucket" in "".join(p) for p in critical_paths)
    assert any("prod-rds-database" in "".join(p) for p in critical_paths)


def test_scan_hardened_project_is_clean(tmp_path):
    import shutil
    target = tmp_path / "hardened-project"
    shutil.copytree(EXAMPLES_DIR / "hardened-project", target)

    result = runner_invoke = CliRunner().invoke(cli, ["scan", str(target), "--repo-name", "my-org/my-repo"])
    assert result.exit_code == 0
    assert "No findings" in result.output


def test_explain_and_fix_after_scan(tmp_path):
    import shutil
    target = tmp_path / "vulnerable-project"
    shutil.copytree(EXAMPLES_DIR / "vulnerable-project", target)

    runner = CliRunner()
    scan_result = runner.invoke(cli, ["scan", str(target), "--repo-name", "my-org/vulnerable-project"])
    assert scan_result.exit_code == 0

    findings = json.loads((target / ".trustgraph" / "findings.json").read_text())
    first_id = findings[0]["id"]

    explain_result = runner.invoke(cli, ["explain", first_id, "--in", str(target)])
    assert explain_result.exit_code == 0
    assert "Attack path:" in explain_result.output
    assert "Recommended remediation:" in explain_result.output

    fix_result = runner.invoke(cli, ["fix", first_id, "--in", str(target)])
    assert fix_result.exit_code == 0


def test_explain_unknown_id_errors_cleanly(tmp_path):
    import shutil
    target = tmp_path / "vulnerable-project"
    shutil.copytree(EXAMPLES_DIR / "vulnerable-project", target)

    runner = CliRunner()
    runner.invoke(cli, ["scan", str(target), "--repo-name", "my-org/vulnerable-project"])
    result = runner.invoke(cli, ["explain", "TG-999", "--in", str(target)])
    assert result.exit_code != 0


def test_scan_without_scan_first_errors_cleanly(tmp_path):
    target = tmp_path / "nothing-scanned-yet"
    target.mkdir()
    (target / ".github").mkdir()
    (target / ".github" / "workflows").mkdir(parents=True)

    result = CliRunner().invoke(cli, ["explain", "TG-001", "--in", str(target)])
    assert result.exit_code != 0


def test_symlinked_permission_policy_outside_target_is_skipped(tmp_path):
    import shutil
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
    target = tmp_path / "proj"
    shutil.copytree(EXAMPLES_DIR / "vulnerable-project", target)
    (target / "resources.json").unlink()
    (target / "permission-policies" / "production-deploy-role.json").unlink()
    (target / "permission-policies" / "production-deploy-role.json").symlink_to(outside)

    result = CliRunner().invoke(cli, ["scan", str(target), "--repo-name", "my-org/vulnerable-project"])
    assert result.exit_code == 0
    assert "Skipping" in result.output
    assert "permission polic" not in result.output
