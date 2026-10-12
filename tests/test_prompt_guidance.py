"""
오철칙 수정 지시문 시험: 우회 수정 금지 목록과 규칙별 반례가 지시문에 들어간다
작성자: 최진호
작성일: 2026-10-12
"""

from pathlib import Path

from iron_laws.core.scanner import AuditScanner
from iron_laws.reporters.prompt import generate_fix_prompt


def test_prompt_forbids_bypass_and_shows_counter_example(tmp_path: Path):
    (tmp_path / "app.py").write_text("import os\nfrom flask import request\n\ndef run():\n    os.system('ls ' + request.args['d'])\n", encoding="utf-8")
    text = generate_fix_prompt(AuditScanner(tmp_path).scan(), 10)
    assert "iron-laws: ignore" in text and "skip" in text  # 억제 주석·테스트 skip으로 가리기 금지
    assert "이렇게 고치지 마세요" in text and "인자 배열" in text
