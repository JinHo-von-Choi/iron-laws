"""
CWEval 측정 스크립트의 사례 추출 시험(평가 세트 없이 합성 파일로 확인한다).
작성자: 최진호
작성일: 2026-11-10
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.cweval import collect_cases, python_unsafe_source, summarize  # noqa: E402

TEST_FILE = '''"""CWE-078"""
import os
import subprocess

import pytest
from cwe_078_0_task import get_ls_result


def get_ls_result_unsafe(dir_path):
    return subprocess.check_output(f'ls -l {dir_path}', shell=True)


def get_ls_result_safe(dir_path):
    return subprocess.check_output(['ls', '-l', dir_path])


pytest_params = 'a'


@pytest.mark.parametrize(pytest_params, [1])
def test_get_ls_result(a):
    assert get_ls_result(a)
'''


def test_python_extraction_keeps_the_unsafe_function_and_drops_tests_and_the_safe_one(tmp_path: Path):
    path = tmp_path / "cwe_078_0_test.py"
    path.write_text(TEST_FILE, encoding="utf-8")
    source = python_unsafe_source(path)
    assert source is not None
    assert "get_ls_result_unsafe" in source and "import subprocess" in source
    assert "_safe" not in source and "pytest" not in source and "cwe_078_0_task" not in source and "def test_" not in source


def test_cases_pair_unsafe_and_safe_references_per_language(tmp_path: Path):
    folder = tmp_path / "benchmark" / "core"
    (folder / "py").mkdir(parents=True)
    (folder / "js").mkdir(parents=True)
    (folder / "py" / "cwe_078_0_test.py").write_text(TEST_FILE, encoding="utf-8")
    (folder / "py" / "cwe_078_0_task.py").write_text("def f(x):\n    # BEGIN SOLUTION\n    return x\n", encoding="utf-8")
    (folder / "js" / "cwe_022_0_js_task.js").write_text("function f(){\n // BEGIN SOLUTION\n return 1;\n}\n", encoding="utf-8")
    cases = collect_cases(tmp_path, ["py", "js"])
    assert sorted((c["lang"], c["cwe"], c["kind"]) for c in cases) == [("js", 22, "safe"), ("py", 78, "safe"), ("py", 78, "unsafe")]  # JS는 취약 파일이 없으면 안전 사례만 낸다
    safe_py = next(c for c in cases if c["lang"] == "py" and c["kind"] == "safe")
    assert "BEGIN SOLUTION" not in safe_py["source"] and "return x" in safe_py["source"]


def test_summary_counts_detections_and_false_positives():
    rows = [
        {"lang": "py", "kind": "unsafe", "same_cwe": ["IL-504"], "same_cwe_confirmed": ["IL-504"], "other_rules": []},
        {"lang": "py", "kind": "unsafe", "same_cwe": [], "same_cwe_confirmed": [], "other_rules": ["IL-301"]},
        {"lang": "py", "kind": "safe", "same_cwe": ["IL-504"], "same_cwe_confirmed": [], "other_rules": []},
    ]
    assert summarize(rows)["py"] == {
        "unsafe_cases": 2, "unsafe_detected_same_cwe": 1, "unsafe_detected_confirmed": 1, "unsafe_only_other_cwe": 1,
        "safe_cases": 1, "safe_flagged_same_cwe": 1, "safe_flagged_confirmed": 0,
    }
