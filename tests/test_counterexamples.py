"""
오철칙 처리된 반례 시험: tests/counterexamples/<번호>/case.yml의 기대 판정을 고정한다(docs/COUNTEREXAMPLES.md)
작성자: 최진호
작성일: 2026-10-12
"""

import shutil
from pathlib import Path

import pytest
import yaml

from iron_laws.core.scanner import AuditScanner

ROOT = Path(__file__).parent / "counterexamples"
CASES = sorted(p for p in ROOT.iterdir() if (p / "case.yml").is_file())


@pytest.mark.parametrize("case_dir", CASES, ids=[p.name for p in CASES])
def test_counterexample_holds(tmp_path: Path, case_dir: Path):
    case = yaml.safe_load((case_dir / "case.yml").read_text(encoding="utf-8"))
    assert case["expected"] in ("flagged", "clean") and case.get("rule") and case.get("file")
    work = tmp_path / "case"
    shutil.copytree(case_dir, work, ignore=shutil.ignore_patterns("case.yml"))
    hits = [v for v in AuditScanner(work).scan().violations if v.rule_id == case["rule"] and v.file_path.as_posix() == case["file"] and v.confidence.value == "CONFIRMED"]
    if case["expected"] == "flagged":
        assert hits, case.get("note")
        if case.get("line"):
            assert any(v.line_number == case["line"] for v in hits)
    else:
        assert not hits, case.get("note")
