"""
오철칙 기준 팩 시험: 팩 무결성, 대응표 확인 상태의 자동 해제, 보고서 1.5의 기준 항목과 독립 검증기 대조
작성자: 최진호
작성일: 2026-10-12
"""

import json
from pathlib import Path

from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.scanner import AuditScanner
from iron_laws.evidence.verifier import verify_report
from iron_laws.reporters.json_reporter import generate_json_report
from iron_laws.standards.pack_registry import PackItem, StandardPack, all_packs

runner = CliRunner()


def test_shipped_packs_are_consistent():
    ids = [p.id for p in all_packs()]
    assert ids[0] == "mois-2021-impl" and {"owasp-top10-2025", "owasp-asi-2026", "cwe-top25-2025", "nis-ai-2025"} <= set(ids)
    for pack in all_packs():
        assert pack.sha256 == pack.content_sha256()
        assert {i for ids_ in pack.mapping.values() for i in ids_} <= {i.id for i in pack.items}
    assert next(p for p in all_packs() if p.id == "mois-2021-impl").mapping_verified
    assert len(next(p for p in all_packs() if p.id == "cwe-top25-2025").items) == 25


def test_verified_mapping_reverts_when_edition_or_content_changes():
    pack = StandardPack(id="x", title="x", edition="2025", items=[PackItem(id="A", name="a")], mapping={"IL-501": ["A"]})
    pack.verified_edition, pack.verified_sha256 = "2025", pack.content_sha256()
    assert pack.mapping_verified
    pack.edition = "2026"
    assert not pack.mapping_verified
    pack.edition = "2025"
    pack.mapping["IL-504"] = ["A"]
    assert not pack.mapping_verified


def _report(tmp_path: Path) -> dict:
    (tmp_path / "app.py").write_text("import os\nfrom flask import request\n\ndef run():\n    os.system('ls ' + request.args['d'])\n", encoding="utf-8")
    return json.loads(generate_json_report(AuditScanner(tmp_path).scan()))


def test_report_carries_pack_refs_and_verifier_accepts_them(tmp_path: Path):
    data = _report(tmp_path)
    assert data["schema_version"] == "1.6"
    finding = next(v for v in data["violations"] if v["rule_id"] == "IL-504")
    refs = {(r["pack_id"], r["item_id"]): r["mapping_verified"] for r in finding["standards"]}
    assert refs[("mois-2021-impl", "1-5")] is True
    assert refs[("owasp-top10-2025", "A05")] is True and ("cwe-top25-2025", "CWE-78") in refs
    assert finding["gov_standard"]["clause_id"].startswith("구현단계 1-5")  # 하위 호환 필드는 그대로 둔다
    assert {p["id"] for p in data["metadata"]["standard_packs"]} >= {"owasp-top10-2025", "cwe-top25-2025"}
    assert verify_report(data).ok


def test_verifier_rejects_mapping_state_that_differs_from_the_pack(tmp_path: Path):
    data = _report(tmp_path)
    finding = next(v for v in data["violations"] if v["rule_id"] == "IL-504")
    next(r for r in finding["standards"] if r["pack_id"] == "owasp-top10-2025")["mapping_verified"] = False
    result = verify_report(data)
    assert not result.ok and any(p.code == "standards.verified_mismatch" for p in result.problems)


def test_verifier_reports_malformed_standards_instead_of_crashing(tmp_path: Path):
    data = _report(tmp_path)
    next(v for v in data["violations"] if v["rule_id"] == "IL-504")["standards"] = ["invalid"]
    result = verify_report(data)
    assert not result.ok and any(p.code == "standards.shape" for p in result.problems)
    data = _report(tmp_path)
    data["metadata"]["standard_packs"] = "invalid"
    result = verify_report(data)
    assert not result.ok and any(p.code == "standards.shape" for p in result.problems)


def test_coverage_by_standard_pack():
    result = runner.invoke(app, ["coverage", "--standard", "owasp-asi-2026"])
    assert result.exit_code == 0 and "ASI05" in result.output and "사람이 이 판본으로 확인함" in result.output
    assert runner.invoke(app, ["coverage", "--standard", "nope"]).exit_code == 2
