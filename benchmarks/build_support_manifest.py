"""
지원 범위 행렬의 시험 현황 자료(support_fixtures.json)를 시험 사례에서 만든다.

사용법:
    uv run python benchmarks/build_support_manifest.py          # 파일을 갱신한다
    uv run python benchmarks/build_support_manifest.py --check  # 최신인지만 확인한다 (CI용)

규칙마다 어떤 언어로 양성(지적해야 함)·음성(지적하면 안 됨) 사례가 몇 건 있는지 센다.
작성자: 최진호
작성일: 2026-10-04
"""

import importlib
import json
import sys
from collections import defaultdict
from pathlib import Path

from iron_laws.engine.languages import EXTENSION_TO_LANG
from iron_laws.engine.source import detect_kind

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "src" / "iron_laws" / "standards" / "data" / "support_fixtures.json"
CASE_SOURCES = [
    ("tests.test_rule_cases", "CASES"),
    ("tests.test_ai_arch_typing_cases", "CASES"),
    ("tests.test_regressions", "CASES"),
    ("tests.test_review_rules", "CASES"),
    ("tests.test_review_findings", "FLOW_CASES"),
    ("tests.test_ai_attack_cases", "CASES"),
    ("tests.test_performance_cases", "CASES"),
]
ALIASES = {"tsx": "typescript"}


def language_of(filename: str) -> str | None:
    """구문 분석 언어 이름. 언어가 없는 파일(설정·문서·템플릿)은 kind:종류로 구분한다."""
    lang = EXTENSION_TO_LANG.get(Path(filename).suffix.lower())
    if lang is None:
        return f"kind:{detect_kind(Path(filename))}"
    return ALIASES.get(lang.value, lang.value)


def build() -> dict[str, dict[str, dict[str, int]]]:
    sys.path.insert(0, str(ROOT))
    counts: dict[str, dict[str, dict[str, int]]] = defaultdict(lambda: defaultdict(lambda: {"positive": 0, "negative": 0}))
    for module_name, attr in CASE_SOURCES:
        cases = getattr(importlib.import_module(module_name), attr)
        for _name, rule_id, files, expected in cases:
            languages = {language_of(f) for f in files}
            for lang in languages:
                positive = any(lines for path, lines in expected.items() if language_of(path) == lang)
                counts[rule_id][lang]["positive" if positive else "negative"] += 1
    return {rule: {lang: dict(c) for lang, c in sorted(langs.items())} for rule, langs in sorted(counts.items())}


def main() -> int:
    rendered = json.dumps(build(), ensure_ascii=False, indent=1, sort_keys=True) + "\n"
    if "--check" in sys.argv:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
        if current != rendered:
            print("support_fixtures.json이 최신이 아닙니다. `uv run python benchmarks/build_support_manifest.py`로 갱신하십시오.")
            return 1
        return 0
    TARGET.write_text(rendered, encoding="utf-8")
    print(f"갱신: {TARGET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
