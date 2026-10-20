"""
사용자 명세 대조 검사 시험
작성자: 최진호
작성일: 2026-10-20
"""

import textwrap
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.custom_spec import example_results
from iron_laws.core.spec_review import review_spec

runner = CliRunner()

PROJECT_WITH_ESC = textwrap.dedent(
    """
    import subprocess
    from flask import request
    from mylib import esc

    def handler():
        cmd = request.args["d"]
        subprocess.run(esc(cmd), shell=True, check=True)
    """
).strip() + "\n"

PROJECT_WITH_PARAM = textwrap.dedent(
    """
    import subprocess

    def handler(cmd):
        subprocess.run(cmd, shell=True, check=True)
    """
).strip() + "\n"

PROJECT_WITH_WRAPPER = textwrap.dedent(
    """
    import subprocess
    from flask import request

    def run_cmd(command):
        return subprocess.run(command, shell=True, check=True)

    def handler():
        cmd = request.args["d"]
        run_cmd(cmd)
    """
).strip() + "\n"

WRAPPER_SINK_SPEC = {
    "version": 1,
    "sinks": [
        {
            "id": "run-cmd",
            "family": "command",
            "languages": ["python"],
            "callee": r"(^|\.)run_cmd\b",
            "arg": 0,
            "positive": textwrap.dedent(
                """
                from flask import request
                def h():
                    run_cmd(request.args["d"])
                """
            ).strip(),
            "negative": textwrap.dedent(
                """
                def h():
                    run_cmd("ls")
                """
            ).strip(),
        }
    ],
}

SANITIZER_SPEC = {
    "version": 1,
    "sanitizers": [
        {
            "id": "esc",
            "family": "command",
            "context": "shell",
            "languages": ["python"],
            "name": r"(^|\.)esc\b",
            "positive": textwrap.dedent(
                """
                import subprocess
                from flask import request
                def h():
                    cmd = request.args["d"]
                    subprocess.run(cmd, shell=True, check=True)
                """
            ).strip(),
            "negative": textwrap.dedent(
                """
                import subprocess
                from flask import request
                from mylib import esc
                def h():
                    cmd = request.args["d"]
                    subprocess.run(esc(cmd), shell=True, check=True)
                """
            ).strip(),
        }
    ],
}

SOURCE_SPEC = {
    "version": 1,
    "sources": [
        {
            "id": "cmd-src",
            "family": "command",
            "languages": ["python"],
            "pattern": r"\bcmd\b",
            "positive": textwrap.dedent(
                """
                import subprocess
                def h(cmd):
                    subprocess.run(cmd, shell=True, check=True)
                """
            ).strip(),
            "negative": textwrap.dedent(
                """
                import subprocess
                def h():
                    other = "ls"
                    subprocess.run(other, shell=True, check=True)
                """
            ).strip(),
        }
    ],
}

TWO_SINKS_SPEC = {
    "version": 1,
    "sinks": [
        {
            "id": "wrapper-a",
            "family": "command",
            "languages": ["python"],
            "callee": r"(^|\.)wrapper_a\b",
            "arg": 0,
            "positive": textwrap.dedent(
                """
                from flask import request
                def h():
                    wrapper_a(request.args["d"])
                """
            ).strip(),
            "negative": textwrap.dedent(
                """
                from flask import request
                def h():
                    wrapper_b(request.args["d"])
                """
            ).strip(),
        },
        {
            "id": "wrapper-b",
            "family": "command",
            "languages": ["python"],
            "callee": r"(^|\.)wrapper_b\b",
            "arg": 0,
            "positive": textwrap.dedent(
                """
                from flask import request
                def h():
                    wrapper_b(request.args["d"])
                """
            ).strip(),
            "negative": textwrap.dedent(
                """
                from flask import request
                def h():
                    wrapper_a(request.args["d"])
                """
            ).strip(),
        },
    ],
}

CODE_FAMILY_SPEC = {
    "version": 1,
    "sinks": [
        {
            "id": "code-sink",
            "family": "code",
            "languages": ["python"],
            "callee": r"(^|\.)eval_cmd\b",
            "arg": 0,
            "positive": textwrap.dedent(
                """
                from flask import request
                def h():
                    eval_cmd(request.args["d"])
                """
            ).strip(),
            "negative": textwrap.dedent(
                """
                def h():
                    eval_cmd("ls")
                """
            ).strip(),
        }
    ],
}


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _write_spec(path: Path, data: dict) -> Path:
    path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return path


def test_정제_함수_명세는_사라진_지적과_원인을_드러낸다(tmp_path: Path):
    root = tmp_path / "proj"
    _write(root / "app.py", PROJECT_WITH_ESC)
    spec = _write_spec(tmp_path / "spec.yml", SANITIZER_SPEC)

    result = review_spec(root, spec)

    assert result.verdict == "review"
    assert len(result.lost_findings) == 1
    lost = result.lost_findings[0]
    assert lost["rule_id"] == "IL-504"
    assert lost["family"] == "command"
    assert lost["cause"] == ["sanitizers.esc"]
    assert any("선언한 정제 함수" in item for item in result.review)


def test_소스_명세는_지적을_늘릴_뿐_탐지를_줄이지_않는다(tmp_path: Path):
    root = tmp_path / "proj"
    _write(root / "app.py", PROJECT_WITH_PARAM)
    spec = _write_spec(tmp_path / "spec.yml", SOURCE_SPEC)

    result = review_spec(root, spec)

    assert result.verdict == "ok"
    assert result.lost_findings == []
    assert [item["rule_id"] for item in result.new_findings] == ["IL-504"]
    assert result.blocking == []


def test_점검이_끝까지_되지_않으면_비교를_믿을_수_없다(tmp_path: Path):
    root = tmp_path / "proj"
    _write(root / "app.py", PROJECT_WITH_ESC)
    (root / "missing.py").symlink_to(tmp_path / "없는파일.py")
    spec = _write_spec(tmp_path / "spec.yml", SANITIZER_SPEC)

    result = review_spec(root, spec)

    assert result.verdict == "blocked"
    assert any("끝까지 되지 않아" in item for item in result.blocking)


def test_대조는_계열이_없는_명세_항목을_한계로_밝힌다(tmp_path: Path):
    root = tmp_path / "proj"
    _write(root / "app.py", PROJECT_WITH_PARAM)
    spec = _write_spec(tmp_path / "spec.yml", CODE_FAMILY_SPEC)

    result = review_spec(root, spec)

    assert any("code 계열" in item for item in result.limitations)


def test_예제_검증은_항목마다_격리한다(tmp_path: Path):
    spec = _write_spec(tmp_path / "spec.yml", TWO_SINKS_SPEC)

    results = example_results(spec)

    by_name = {(name, form): ok for name, form, ok, _why in results}
    assert by_name[("sinks.wrapper-a", "positive")] is True
    assert by_name[("sinks.wrapper-a", "negative")] is True
    assert by_name[("sinks.wrapper-b", "positive")] is True
    assert by_name[("sinks.wrapper-b", "negative")] is True


def test_예제_검증은_항목당_한_번_점검한다(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from iron_laws.core import scanner as scanner_module

    calls: list[int] = []
    original = scanner_module.AuditScanner.scan

    def counted(self):
        calls.append(1)
        return original(self)

    monkeypatch.setattr(scanner_module.AuditScanner, "scan", counted)
    spec = _write_spec(tmp_path / "spec.yml", TWO_SINKS_SPEC)

    example_results(spec)

    assert len(calls) == 2


def test_spec_check는_저장소가_없으면_예제_판정만_한다(tmp_path: Path):
    spec = _write_spec(tmp_path / "spec.yml", SANITIZER_SPEC)

    result = runner.invoke(app, ["spec", "check", str(spec)])

    assert result.exit_code == 0


def test_spec_check_대조는_탐지_감소를_확인_필요로_알린다(tmp_path: Path):
    root = tmp_path / "proj"
    _write(root / "app.py", PROJECT_WITH_ESC)
    spec = _write_spec(tmp_path / "spec.yml", SANITIZER_SPEC)

    result = runner.invoke(app, ["spec", "check", str(spec), "--against", str(root)])

    assert result.exit_code == 1
    assert "확인 필요" in result.output


def test_spec_check_대조는_감소가_없으면_통과한다(tmp_path: Path):
    root = tmp_path / "proj"
    _write(root / "app.py", PROJECT_WITH_PARAM)
    spec = _write_spec(tmp_path / "spec.yml", SOURCE_SPEC)

    result = runner.invoke(app, ["spec", "check", str(spec), "--against", str(root)])

    assert result.exit_code == 0
    assert "탐지 감소 없음" in result.output


def test_spec_check_대조는_산출물로_저장한다(tmp_path: Path):
    root = tmp_path / "proj"
    _write(root / "app.py", PROJECT_WITH_ESC)
    spec = _write_spec(tmp_path / "spec.yml", SANITIZER_SPEC)
    out = tmp_path / "review.json"

    result = runner.invoke(app, ["spec", "check", str(spec), "--against", str(root), "--format", "json", "--output", str(out)])

    assert result.exit_code == 1
    data = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert data["verdict"] == "review"
    assert data["lost_findings"][0]["rule_id"] == "IL-504"


def _scan_with_spec(root: Path, spec: Path | None, ledger_spec_points: bool = False):
    from iron_laws.core.config import IronLawsConfig, Policies
    from iron_laws.core.scanner import AuditScanner

    config = IronLawsConfig(
        policies=Policies(
            custom_spec=str(spec) if spec else None,
            ledger_include_spec_points=ledger_spec_points,
        )
    )
    return AuditScanner(root, config).scan()


def test_명세_지문이_장부_실행_식별자에_반영된다(tmp_path: Path):
    root = tmp_path / "proj"
    _write(root / "app.py", PROJECT_WITH_PARAM)
    spec = _write_spec(tmp_path / "spec.yml", SOURCE_SPEC)
    other = _write_spec(tmp_path / "other.yml", SANITIZER_SPEC)

    base = _scan_with_spec(root, None)
    first = _scan_with_spec(root, spec)
    second = _scan_with_spec(root, other)

    assert base.coverage_ledger.digests["spec"] == ""
    assert first.coverage_ledger.digests["spec"] != ""
    assert first.coverage_ledger.run_id != base.coverage_ledger.run_id
    assert first.coverage_ledger.run_id != second.coverage_ledger.run_id
    assert first.metadata["custom_spec"]["digest"] == first.coverage_ledger.digests["spec"]


def test_선언한_정제_함수는_근거_종류가_달라진다(tmp_path: Path):
    root = tmp_path / "proj"
    _write(root / "app.py", PROJECT_WITH_ESC)
    spec = _write_spec(tmp_path / "spec.yml", SANITIZER_SPEC)

    report = _scan_with_spec(root, spec)

    point = next(p for p in report.coverage_ledger.points if p.callee == "subprocess.run")
    assert point.state == "evidence_met"
    assert point.evidence_kind == "declared_sanitizer"
    assert "esc" in point.reason
    assert any("선언한 정제 함수" in item for item in report.coverage_ledger.limitations)


def test_장부는_사용자_명세_싱크를_보지_않는다_기본값(tmp_path: Path):
    root = tmp_path / "proj"
    _write(root / "app.py", PROJECT_WITH_WRAPPER)
    spec = _write_spec(tmp_path / "spec.yml", WRAPPER_SINK_SPEC)

    without = _scan_with_spec(root, spec)
    with_points = _scan_with_spec(root, spec, ledger_spec_points=True)

    assert all(p.callee != "run_cmd" for p in without.coverage_ledger.points)
    assert any(p.callee == "run_cmd" for p in with_points.coverage_ledger.points)
