"""
산출물 비교 측정기 시험
작성자: 최진호
작성일: 2026-10-20
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))

import artifact_ab  # noqa: E402


def test_안내물마다_서로_다른_지시문이_만들어진다(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from tests import regression_corpus

    monkeypatch.setattr(regression_corpus, "SUPPORTED", regression_corpus.SUPPORTED[:2])
    cases = artifact_ab.prepare(tmp_path)

    assert cases
    for case in cases:
        texts = {
            variant: (tmp_path / "prompts" / f"{case['name']}.{variant}.txt").read_text(encoding="utf-8")
            for variant in artifact_ab.VARIANTS
        }
        assert len(set(texts.values())) == len(artifact_ab.VARIANTS)
        for text in texts.values():
            assert "--- app.py" in text
            assert "```python" in text


def test_수정_지시문_안내물은_금지_목록을_담는다(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from tests import regression_corpus

    monkeypatch.setattr(regression_corpus, "SUPPORTED", regression_corpus.SUPPORTED[:1])
    cases = artifact_ab.prepare(tmp_path)

    text = (tmp_path / "prompts" / f"{cases[0]['name']}.fix_prompt.txt").read_text(encoding="utf-8")

    assert "iron-laws: ignore" in text
    assert "이렇게 고치지 마세요" in text
