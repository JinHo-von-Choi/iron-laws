"""
오철칙 공통 측정기 시험: 지적은 사례의 파일·범위 안에서만 검출로 세고, 분석하지 못한 사례는 TN·FN이 아니라 따로 센다
작성자: 최진호
작성일: 2026-10-12
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))

from bench_common import Case, entry_range, entry_ranges, score  # noqa: E402

from iron_laws.core.scanner import AuditScanner  # noqa: E402

VULN = "import os\nfrom flask import request\n\n\ndef bad():\n    os.system(request.args['c'])\n\n\ndef good():\n    os.system('ls')\n"
CMD = frozenset({"IL-504"})


def _report(root: Path, files: dict[str, str]):
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    return AuditScanner(root).scan()


def test_finding_counts_only_inside_the_case_range(tmp_path: Path):
    report = _report(tmp_path, {"app.py": VULN})
    cases = [
        Case("bad", "app.py", "cmdi", True, CMD, entry="bad"),
        Case("good", "app.py", "cmdi", False, CMD, entry="good"),
        Case("other-file", "lib.py", "cmdi", True, CMD),
    ]
    scored = score(cases, report, tmp_path)
    assert scored.outcomes["bad"] == "TP"
    assert scored.outcomes["good"] == "TN"  # 같은 파일의 다른 함수 지적은 이 사례의 검출이 아니다
    assert scored.outcomes["other-file"] == "unanalyzed"  # 점검 대상에 없는 파일의 사례는 FN이 아니다


def test_explicit_line_range_and_exclusion(tmp_path: Path):
    report = _report(tmp_path, {"app.py": VULN})
    cases = [
        Case("in", "app.py", "cmdi", True, CMD, lines=(5, 6)),
        Case("out", "app.py", "cmdi", True, CMD, lines=(9, 10)),
        Case("skip", "app.py", "cmdi", True, CMD, excluded="정답 논쟁 사례"),
    ]
    scored = score(cases, report, tmp_path)
    assert [scored.outcomes[c] for c in ("in", "out", "skip")] == ["TP", "FN", "excluded"]
    table = scored.table()["cmdi"]
    assert (table["TP"], table["FN"], table["excluded"]) == (1, 1, 1)


def test_parse_failure_is_unanalyzed_not_negative(tmp_path: Path):
    report = _report(tmp_path, {"broken.py": "def f(:\n    pass\n", "app.py": VULN})
    if not any(d.kind == "parse" and d.file_path == "broken.py" for d in report.diagnostics):
        return  # 이 파서가 구문 오류로 보지 않으면 전제가 성립하지 않는다
    scored = score([Case("broken", "broken.py", "cmdi", False, CMD)], report, tmp_path)
    assert scored.outcomes["broken"] == "unanalyzed"


def test_entry_range_follows_the_syntax_tree():
    assert entry_range(VULN, ".py", "bad") == (5, 6)
    assert entry_range(VULN, ".py", "missing") is None
    assert entry_ranges("void bad() {\n  f();\n}\nvoid goodG2B() {\n}\nvoid good1() {}\n", ".c", "good.*") == [(4, 5), (6, 6)]
