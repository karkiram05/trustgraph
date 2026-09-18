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
