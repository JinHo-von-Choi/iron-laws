"""
오철칙 신뢰 지표와 상한 정책 시험: 미검증 (규칙, 언어) 조합의 '지적 없음'은 통과 근거가 아니며, 상한을 넘으면 통과가 아니라 재검토다.
- analysis_unknown_rate: 계약 범위 안 보안 관심 지점 중 해석 미확정·미지원·예산 초과의 비율
- unverified_rule_language_rate: 이번 점검에 적용된 (규칙, 언어) 조합 중 양성·음성 시험이 모두 있지 않은 조합의 비율
두 지표는 분모가 다르며 섞어 쓰지 않는다. 표본은 구현자가 직접 만들었다.
작성자: 최진호
작성일: 2026-10-05
"""
# iron-laws: ignore-file[IL-101] 시험 입력으로 쓰는 무효 합성 비밀값이다

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.scanner import AuditScanner
from iron_laws.evidence.verifier import verify_report

cli = CliRunner()
CLEAN_PY = "def add(a, b):\n    return a + b\n"
UNRESOLVED_PY = "import os\n\ndef run(cmd):\n    os.system(cmd)\n"


def _project(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


def test_the_report_carries_both_rates_with_their_own_denominators(tmp_path: Path):
    report = AuditScanner(_project(tmp_path / "p", {"a.py": UNRESOLVED_PY, "b.py": CLEAN_PY})).scan()
    s = report.summary
    assert s.analysis_unknown_rate == 1.0  # 범위 안 관심 지점은 os.system 하나이고 해석 미확정이다
    assert s.evaluated_rule_language_pairs and 0 < s.unverified_rule_language_pairs <= s.evaluated_rule_language_pairs
    assert s.unverified_rule_language_rate == round(s.unverified_rule_language_pairs / s.evaluated_rule_language_pairs, 4)
    assert report.schema_version == "1.4"
    assert verify_report(report.model_dump(mode="json")).ok


def test_a_project_without_interest_points_has_no_unknown_rate(tmp_path: Path):
    report = AuditScanner(_project(tmp_path / "p", {"b.py": CLEAN_PY})).scan()
    assert report.summary.analysis_unknown_rate is None


def test_each_finding_carries_the_grade_of_its_rule_and_language_pair(tmp_path: Path):
    report = AuditScanner(_project(tmp_path / "p", {"a.py": "import os\nfrom flask import request\n\ndef f():\n    os.system('ls ' + request.args['d'])\n", "a.js": "const password = \"Zq9xKm2LpQw8RtYu\";\n"})).scan()
    grades = {(v.rule_id, v.file_path.suffix): v.verification_grade for v in report.violations}
    assert grades[("IL-504", ".py")] == "verified"
    assert any(suffix == ".js" for _rule, suffix in grades)
    assert all(v.verification_grade in ("verified", "unverified") for v in report.violations if v.file_path.suffix in (".py", ".js"))


def test_a_pass_with_unverified_pairs_never_prints_a_bare_pass(tmp_path: Path):
    project = _project(tmp_path / "p", {"b.py": CLEAN_PY})
    console = cli.invoke(app, ["check", str(project)])
    assert console.exit_code == 0
    flat = re.sub(r"[│\s]+", "", console.stdout)  # 표 셀이 줄바꿈되어도 문구를 확인한다
    assert "합격" in console.stdout and "미검증" in console.stdout and "포함" in console.stdout  # 판정 칸은 좁아 줄바꿈되므로 낱말로 확인한다
    assert "미검증조합의'지적없음'은통과근거가아닙니다" in flat
    markdown = cli.invoke(app, ["audit", str(project), "--format", "markdown"]).stdout
    assert "통과 (PASS) · 단, 미검증" in markdown


def test_the_unknown_gate_turns_a_pass_into_a_review(tmp_path: Path):
    project = _project(tmp_path / "p", {"a.py": UNRESOLVED_PY})
    assert cli.invoke(app, ["check", str(project)]).exit_code == 0
    gated = cli.invoke(app, ["check", str(project), "--max-analysis-unknown-rate", "0.5"])
    assert gated.exit_code == 1
    assert "신뢰 지표 상한 초과" in gated.stdout + gated.stderr
    lenient = cli.invoke(app, ["check", str(project), "--max-analysis-unknown-rate", "1.0"])
    assert lenient.exit_code == 0  # 상한 이하이면 그대로 통과한다


def test_the_unverified_gate_uses_the_rule_language_denominator(tmp_path: Path):
    project = _project(tmp_path / "p", {"b.py": CLEAN_PY})
    report = AuditScanner(project).scan()
    rate = report.summary.unverified_rule_language_rate
    assert rate is not None and 0 < rate < 1
    assert cli.invoke(app, ["check", str(project), "--max-unverified-rule-language-rate", str(rate)]).exit_code == 0  # 같으면 넘지 않은 것이다
    assert cli.invoke(app, ["check", str(project), "--max-unverified-rule-language-rate", str(max(rate - 0.01, 0))]).exit_code == 1


def test_a_gate_exceeded_report_is_not_a_pass_for_the_independent_verifier(tmp_path: Path):
    project = _project(tmp_path / "p", {"a.py": UNRESOLVED_PY})
    scanner = AuditScanner(project, gates={"max_analysis_unknown_rate": 0.5})
    report = scanner.scan()
    assert report.summary.gate_exceeded and not report.summary.is_passed
    data = report.model_dump(mode="json")
    assert verify_report(data).ok
    forged = json.loads(json.dumps(data))
    forged["summary"]["is_passed"] = True
    codes = {p.code for p in verify_report(forged).problems}
    assert "pass.gate_exceeded_passed" in codes
    wrong_rate = json.loads(json.dumps(data))
    wrong_rate["summary"]["analysis_unknown_rate"] = 0.0
    assert {"trust.unknown_rate_mismatch", "trust.gate_mismatch"} & {p.code for p in verify_report(wrong_rate).problems}
    hidden = json.loads(json.dumps(data))
    hidden["summary"]["gate_exceeded"] = []
    assert "trust.gate_mismatch" in {p.code for p in verify_report(hidden).problems}


def test_a_1_3_report_is_still_readable_by_the_verifier(tmp_path: Path):
    report = AuditScanner(_project(tmp_path / "p", {"b.py": CLEAN_PY})).scan()
    data = report.model_dump(mode="json")
    data["schema_version"] = "1.3"
    for key in ("analysis_unknown_rate", "evaluated_rule_language_pairs", "unverified_rule_language_pairs", "unverified_rule_language_rate", "gates", "gate_exceeded"):
        data["summary"].pop(key, None)
    for v in data["violations"]:
        v.pop("verification_grade", None)
    assert verify_report(data).ok


def test_changing_the_support_manifest_changes_the_ruleset_fingerprint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    scanner = AuditScanner(_project(tmp_path / "p", {"b.py": CLEAN_PY}))
    before = scanner._ruleset_info()["hash"]
    monkeypatch.setattr(AuditScanner, "_support_manifest_digest", staticmethod(lambda: "0" * 16))
    assert scanner._ruleset_info()["hash"] != before


def test_metrics_record_both_trust_rates_without_paths(tmp_path: Path):
    project = _project(tmp_path / "p", {"a.py": UNRESOLVED_PY})
    metrics = tmp_path / "m.jsonl"
    assert cli.invoke(app, ["check", str(project), "--metrics", str(metrics)]).exit_code == 0
    trust = json.loads(metrics.read_text().splitlines()[0])["trust"]
    assert trust["analysis_unknown_rate"] == 1.0 and trust["unverified_rule_language_pairs"] > 0
    assert str(project) not in metrics.read_text()
