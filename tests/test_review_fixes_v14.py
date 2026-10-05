"""
오철칙 외부 검토에서 확인된 결함의 회귀 시험: 독립 검증기의 열 대조와 신뢰 지표 위조, 부채 표시의 복제 구분, 파일럿 설치 시간 합산,
상한 초과만이 실패 원인일 때의 문구, 정규화 투영의 계약 경로 제외.
작성자: 최진호
작성일: 2026-10-05
"""
# iron-laws: ignore-file[IL-101] 시험 입력으로 쓰는 무효 합성 비밀값이다

import json
from pathlib import Path

from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.canonical import canonical_projection
from iron_laws.core.contract import load_contract
from iron_laws.core.pilot import PilotStore, assign, record_review, summarize
from iron_laws.core.scanner import AuditScanner
from iron_laws.evidence.verifier import verify_report
from iron_laws.verify.debt_delta import compare
from tests.test_stage2_contract import FLASK, _scan

cli = CliRunner()
SWALLOWED = "from flask import request\n\ndef run():\n    try:\n        return int(request.args['n'])\n    except Exception:\n        pass\n"


def _codes(data: dict) -> set[str]:
    return {p.code for p in verify_report(data).problems}


def test_the_verifier_rejects_a_finding_moved_to_another_call_on_the_same_line(tmp_path: Path):
    report = _scan(tmp_path, {"a.py": FLASK + "def f():\n    a = request.args['a']\n    os.system('ok'); os.system('x ' + a)\n"})
    data = report.model_dump(mode="json")
    assert verify_report(data).ok
    first, second = sorted((p for p in data["coverage_ledger"]["points"] if p["family"] == "command"), key=lambda p: p["column"])
    first["finding_ids"], second["finding_ids"] = second["finding_ids"], []
    first["finding"], second["finding"] = True, False
    first["evidence_kind"], second["evidence_kind"] = "finding", "closed_value"
    assert "point.finding_other_call" in _codes(data)


def test_zeroing_the_trust_counters_does_not_hide_a_gate_overrun(tmp_path: Path):
    project = tmp_path / "p"
    project.mkdir()
    (project / "b.py").write_text("def add(a, b):\n    return a + b\n")
    data = AuditScanner(project, gates={"max_unverified_rule_language_rate": 0.1}).scan().model_dump(mode="json")
    assert not data["summary"]["is_passed"] and verify_report(data).ok
    forged = json.loads(json.dumps(data))
    forged["summary"].update({"evaluated_rule_language_pairs": 0, "unverified_rule_language_pairs": 0, "unverified_rule_language_rate": None, "gate_exceeded": [], "is_passed": True})
    assert "trust.pairs_missing" in _codes(forged)


def test_a_gate_overrun_does_not_skip_the_finding_count_checks(tmp_path: Path):
    project = tmp_path / "p"
    project.mkdir()
    (project / "a.py").write_text("import os\n\ndef run(cmd):\n    os.system(cmd)\n")
    data = AuditScanner(project, gates={"max_analysis_unknown_rate": 0.5}).scan().model_dump(mode="json")
    assert data["summary"]["gate_exceeded"] and verify_report(data).ok
    forged = json.loads(json.dumps(data))
    forged["summary"]["total_violations"] = 7
    assert "summary.total_mismatch" in _codes(forged)


def test_a_failed_build_is_not_relabelled_as_a_review_when_a_gate_is_also_exceeded(tmp_path: Path):
    project = tmp_path / "p"
    project.mkdir()
    (project / "a.py").write_text("import os\nfrom flask import request\n\ndef f():\n    os.system('ls ' + request.args['d'])\n    os.system(input())\n")
    result = cli.invoke(app, ["check", str(project), "--max-unverified-rule-language-rate", "0"])
    flat = result.stdout
    assert result.exit_code == 1 and "불합격" in flat and "재검토 (신뢰" not in flat
    clean = tmp_path / "c"
    clean.mkdir()
    (clean / "b.py").write_text("def add(a, b):\n    return a + b\n")
    only_gate = cli.invoke(app, ["check", str(clean), "--max-unverified-rule-language-rate", "0"])
    assert only_gate.exit_code == 1 and "재검토" in only_gate.stdout


def test_the_projection_ignores_the_contract_file_location(tmp_path: Path):
    contracts = []
    for name in ("one", "two"):
        base = tmp_path / name
        base.mkdir()
        (base / "a.py").write_text("def f():\n    return 1\n")
        (base / "contract.yml").write_text("version: 1\nmode: report\n")
        loaded, _digest = load_contract(base / "contract.yml")
        contracts.append(AuditScanner(base, contract=loaded, contract_path=base / "contract.yml", contract_source=str(base / "contract.yml")).scan().model_dump(mode="json"))
    assert contracts[0]["coverage_ledger"]["contract_source"] != contracts[1]["coverage_ledger"]["contract_source"]  # 제외하지 않으면 달라지는 값이다
    assert canonical_projection(contracts[0]) == canonical_projection(contracts[1])


def _scan_files(root: Path, files: dict[str, str]):
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    return AuditScanner(root).scan()


def test_a_copy_that_leaves_the_original_in_place_is_not_a_move(tmp_path: Path):
    before = _scan_files(tmp_path / "b", {"old.py": SWALLOWED})
    after = _scan_files(tmp_path / "a", {"old.py": "from flask import request\n\ndef run():\n    return int(request.args['n'])\n", "new.py": SWALLOWED})
    delta = compare(before, after).to_dict()
    assert delta["totals"]["moved"] == 0 and delta["habits"]["swallowed_exception"]["resolved"] >= 1 and delta["habits"]["swallowed_exception"]["resolved"] == delta["habits"]["swallowed_exception"]["new"]


def test_setup_minutes_are_summed_per_team_and_belong_to_the_tool_condition(tmp_path: Path):
    store = PilotStore(tmp_path / "s.jsonl")
    arms = {}
    for i in range(4):
        arm = assign(store, "a", f"pr-{i}", "small", 1)["arm"]
        arms[i] = arm
        record_review(store, f"pr-{i}", 10, setup_minutes=20 if arm == "bundle" else 25)
    result = summarize(store)
    bundle_total = 20 * sum(1 for a in arms.values() if a == "bundle")
    assert result["checks"]["setup_within_30_minutes"] is (bundle_total <= 30)  # 팀 합계로 본다. baseline 조건의 기록은 합산하지 않는다
    assert bundle_total > 30 and result["checks"]["setup_within_30_minutes"] is False
