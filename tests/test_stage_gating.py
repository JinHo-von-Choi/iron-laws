"""
오철칙 프로젝트 단계(stage)별 차단 시험: 단계마다 막는 지적, 설정 지문 하위 호환, 독립 검증기 재계산, 훅·미리보기·init·정책 완화 감지
작성자: 최진호
작성일: 2026-11-28
"""

import json
import subprocess
from pathlib import Path

from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.agent_hook import policy_changes
from iron_laws.core.config import IronLawsConfig
from iron_laws.core.gating import blocks, stage_policy
from iron_laws.core.scanner import AuditScanner
from iron_laws.evidence.verifier import verify_report

runner = CliRunner()
LEAK = 'import logging\nTOKEN = input()\nprint("token", TOKEN)\n'  # AI-112(민감정보 출력, HIGH)


def test_stage_unset_keeps_config_hash_and_report_config():
    config = IronLawsConfig()
    assert "stage" not in json.loads(config.hash_json())  # 단계를 쓰지 않는 프로젝트의 지문은 1.13.0과 같다
    assert "stage" not in config.report_dump()
    assert "stage" in json.loads(IronLawsConfig(stage="launch").hash_json())


def test_each_stage_blocks_its_categories():
    def b(stage, rule, sev, conf, layer):
        return blocks(rule, sev, conf, layer, stage_policy(stage, "HIGH"), "HIGH")

    assert b("prototype", "IL-101", "CRITICAL", "CONFIRMED", "STANDARD")
    assert b("prototype", "IL-504", "CRITICAL", "CONFIRMED", "STANDARD")
    assert not b("prototype", "AI-112", "HIGH", "CONFIRMED", "AI_CODE")
    assert not b("prototype", "IL-525", "MEDIUM", "REVIEW", "AI_CODE")
    assert b("launch", "IL-525", "MEDIUM", "REVIEW", "AI_CODE")
    assert b("launch", "AI-112", "HIGH", "CONFIRMED", "AI_CODE")
    assert not b("launch", "AI-112", "HIGH", "REVIEW", "AI_CODE")  # launch는 확정 지적만 심각도로 막는다
    assert not b("launch", "ARC-207", "MEDIUM", "CONFIRMED", "ARCHITECTURE")
    assert b("production", "ARC-207", "MEDIUM", "CONFIRMED", "ARCHITECTURE")
    assert b("production", "AI-112", "HIGH", "REVIEW", "AI_CODE")
    assert blocks("AI-112", "HIGH", "REVIEW", "AI_CODE", None, "HIGH")  # 단계가 없으면 fail_on만 본다


def _project(tmp_path: Path, stage: str | None) -> Path:
    root = tmp_path / (stage or "none")
    root.mkdir()
    (root / "app.py").write_text(LEAK, encoding="utf-8")
    if stage:
        (root / ".iron-laws.yml").write_text(f"stage: {stage}\n", encoding="utf-8")
    return root


def test_report_records_policy_and_verifier_agrees(tmp_path: Path):
    plain = AuditScanner(_project(tmp_path, None)).scan()
    assert not plain.summary.is_passed and "stage_policy" not in plain.metadata
    proto = AuditScanner(_project(tmp_path, "prototype")).scan()
    assert proto.summary.is_passed
    assert proto.metadata["stage_policy"]["stage"] == "prototype" and proto.metadata["stage_advisory_count"] >= 1
    for report in (plain, proto):
        result = verify_report(report.model_dump(mode="json"))
        assert result.ok, result.problems  # 검증기가 보고서의 정책만으로 같은 통과 판정을 낸다


def test_hook_uses_project_stage(tmp_path: Path):
    payload = lambda root: json.dumps({"hook_event_name": "PostToolUse", "cwd": str(root), "tool_input": {"file_path": "app.py"}})  # noqa: E731
    assert runner.invoke(app, ["hook", "claude-code"], input=payload(_project(tmp_path, None))).exit_code == 2
    assert runner.invoke(app, ["hook", "claude-code"], input=payload(_project(tmp_path, "prototype"))).exit_code == 0


def test_stage_preview_lists_newly_blocked(tmp_path: Path):
    root = _project(tmp_path, "prototype")
    result = runner.invoke(app, ["stage", "preview", "launch", str(root)])
    assert result.exit_code == 0, result.output
    assert "새로 막히는 지적 1건" in result.output and "AI-112" in result.output
    assert runner.invoke(app, ["stage", "preview", "beta", str(root)]).exit_code == 2


def test_init_stage_and_existing_yaml(tmp_path: Path):
    assert runner.invoke(app, ["init", str(tmp_path), "--stage", "launch"]).exit_code == 0
    assert "stage: launch" in (tmp_path / ".iron-laws.yml").read_text(encoding="utf-8")
    other = tmp_path / "other"
    other.mkdir()
    (other / ".iron-laws.yaml").write_text("fail_on: LOW\n", encoding="utf-8")
    runner.invoke(app, ["init", str(other)])
    assert not (other / ".iron-laws.yml").exists()  # .yaml이 있어도 새로 만들지 않는다
    assert runner.invoke(app, ["init", str(tmp_path / "x"), "--stage", "beta"]).exit_code == 2


def test_lowering_stage_is_reported_as_weakening(tmp_path: Path):
    def git(*args):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    config = tmp_path / ".iron-laws.yml"
    config.write_text("stage: production\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "c")
    config.write_text("stage: prototype\n", encoding="utf-8")
    assert any("단계를 production에서 prototype로 낮췄습니다" in n for n in policy_changes(config, tmp_path))


def test_launch_blocks_missing_ci_and_readiness_table(tmp_path: Path):
    from iron_laws.architecture.ops import readiness

    root = tmp_path / "svc"
    root.mkdir()
    (root / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n\n@app.route('/items')\ndef items():\n    return 'x'\n", encoding="utf-8")
    (root / ".iron-laws.yml").write_text("stage: prototype\n", encoding="utf-8")
    assert AuditScanner(root).scan().summary.is_passed  # OPS-101(LOW)은 prototype에서 막지 않는다
    (root / ".iron-laws.yml").write_text("stage: launch\n", encoding="utf-8")
    assert not AuditScanner(root).scan().summary.is_passed
    states = {r["rule_id"]: r["state"] for r in readiness(root)}
    assert states["OPS-101"] == "지적 있음" and states["OPS-102"] == "점검함·지적 없음"
    cli = tmp_path / "cli"
    cli.mkdir()
    (cli / "main.py").write_text("import sys\nprint(sys.argv)\n", encoding="utf-8")
    assert {r["rule_id"]: r["state"] for r in readiness(cli)}["OPS-101"] == "해당 없음(웹 라우트 없음)"
