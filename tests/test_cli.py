"""
Tests for CLI Commands
작성자: 최진호
작성일: 2026-10-04
"""

from pathlib import Path

from typer.testing import CliRunner

from iron_laws.cli import app

runner = CliRunner()


def test_cli_rules_command():
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "IL-101" in result.output
    assert "IL-301" in result.output
    assert "오철칙" in result.output


def test_cli_init_command(tmp_path: Path):
    result = runner.invoke(app, ["init", str(tmp_path)])
    assert result.exit_code == 0
    config_file = tmp_path / ".iron-laws.yml"
    assert config_file.exists()
    assert "fail_on" in config_file.read_text()


def test_cli_check_command_clean(tmp_path: Path):
    (tmp_path / "clean.py").write_text("x = 10\n")
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 0
    assert "PASS" in result.output


def test_cli_check_command_fail(tmp_path: Path):
    (tmp_path / "fail.py").write_text("password = 'MyHardcodedPassword123!'\n")
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 1


def test_cli_check_uses_fail_on_from_config_when_option_omitted(tmp_path: Path):
    (tmp_path / ".iron-laws.yml").write_text("fail_on: CRITICAL\n")
    (tmp_path / "svc.py").write_text("try:\n    run()\nexcept Exception: pass\n")
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 0


def test_cli_check_option_overrides_config_fail_on(tmp_path: Path):
    (tmp_path / ".iron-laws.yml").write_text("fail_on: CRITICAL\n")
    (tmp_path / "svc.py").write_text("try:\n    run()\nexcept Exception: pass\n")
    result = runner.invoke(app, ["check", str(tmp_path), "--fail-on", "HIGH"])
    assert result.exit_code == 1


def test_cli_check_rejects_unknown_fail_on_value(tmp_path: Path):
    result = runner.invoke(app, ["check", str(tmp_path), "--fail-on", "SEVERE"])
    assert result.exit_code == 2


def test_cli_reports_invalid_config_instead_of_ignoring_it(tmp_path: Path):
    (tmp_path / ".iron-laws.yml").write_text("fail_on: [unclosed\n")
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 2
    assert "설정 오류" in result.output


def test_cli_reports_unknown_config_key(tmp_path: Path):
    (tmp_path / ".iron-laws.yml").write_text("fail_one: HIGH\n")
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 2


def test_cli_init_generates_config_that_matches_defaults(tmp_path: Path):
    runner.invoke(app, ["init", str(tmp_path)])
    from iron_laws.core.config import IronLawsConfig, load_config

    assert load_config(tmp_path)[0] == IronLawsConfig()
