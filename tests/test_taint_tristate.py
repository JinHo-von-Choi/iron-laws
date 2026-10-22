"""
오철칙 함수 간 해석의 판정 불가 처리, 이름 바인딩, 작업 프로세스 수와 무관한 결과 시험
작성자: 최진호
작성일: 2026-10-11
"""

import os
from pathlib import Path

import pytest

from iron_laws.core import scanner
from iron_laws.core.config import IronLawsConfig, Limits
from iron_laws.core.scanner import AuditScanner
from tests.helpers import lines_of, scan_files

CHAIN = "".join(f"def h{i}(x):\n    return h{i + 1}(x)\n\n" for i in range(1, 6)) + "def h6(x):\n    return x\n"
VIEW_HEAD = "import os\nfrom flask import request\n"


def test_helper_chain_deeper_than_limit_keeps_the_finding(tmp_path: Path):
    files = {
        "app/__init__.py": "",
        "app/util.py": CHAIN,
        "app/views.py": VIEW_HEAD + "from app.util import h1\n\ndef deep():\n    os.system(h1(request.args['d']))\n",
    }
    assert lines_of(scan_files(tmp_path, files), "IL-504", "app/views.py") == [6]


def test_same_file_chain_deeper_than_limit_keeps_the_finding(tmp_path: Path):
    files = {"views.py": VIEW_HEAD + CHAIN + "\ndef deep():\n    os.system(h1(request.args['d']))\n"}
    assert lines_of(scan_files(tmp_path, files), "IL-504", "views.py") == [22]


def test_imported_name_is_not_replaced_by_a_same_named_method(tmp_path: Path):
    files = {
        "app/__init__.py": "",
        "app/util.py": "def passthru(x):\n    return x\n",
        "app/views.py": VIEW_HEAD
        + "from app.util import passthru\n\nclass Box:\n    def passthru(self, x):\n        return 'ls'\n\n"
        + "def run():\n    os.system(passthru(request.args['s']))\n",
    }
    assert lines_of(scan_files(tmp_path, files), "IL-504", "app/views.py") == [10]


def test_name_bound_by_both_import_and_local_def_checks_both(tmp_path: Path):
    files = {
        "app/__init__.py": "",
        "app/util.py": "def pick(x):\n    return x\n",
        "app/views.py": VIEW_HEAD
        + "from app.util import pick\n\ndef pick(x):\n    return 'ls'\n\n"
        + "def run():\n    os.system(pick(request.args['s']))\n",
    }
    assert lines_of(scan_files(tmp_path, files), "IL-504", "app/views.py") == [9]


def test_module_level_rebinding_is_not_resolved_to_the_def(tmp_path: Path):
    files = {
        "views.py": VIEW_HEAD + "def name(x):\n    return 'ls'\n\nname = lambda x: x\n\n"
        + "def run():\n    os.system(name(request.args['r']))\n",
    }
    assert lines_of(scan_files(tmp_path, files), "IL-504", "views.py") == [9]


def test_clean_helper_still_clears_the_call(tmp_path: Path):
    files = {"views.py": VIEW_HEAD + "def name(x):\n    return 'ls'\n\ndef run():\n    os.system(name(request.args['r']))\n"}
    assert lines_of(scan_files(tmp_path, files), "IL-504", "views.py") == []


def _project(root: Path) -> None:
    root.joinpath("app").mkdir(parents=True)
    root.joinpath("app/__init__.py").write_text("")
    root.joinpath("app/util.py").write_text(CHAIN + "\ndef name():\n    return 'ls'\n")
    for i in range(12):
        root.joinpath(f"app/v{i}.py").write_text(
            VIEW_HEAD
            + "from app.util import h1, h2, name\n\n"
            + f"def a{i}():\n    os.system(h1(request.args['d']))\n\n"
            + f"def b{i}():\n    os.system(h2(name()))\n\n"
            + f"def c{i}():\n    os.system(name())\n"
        )


def _outcome(root: Path, workers: int, monkeypatch) -> tuple:
    monkeypatch.setattr(scanner, "MAX_WORKERS", workers)
    monkeypatch.setattr(scanner, "PARALLEL_MIN_FILES", 2)
    monkeypatch.setattr(os, "cpu_count", lambda: 8)
    report = AuditScanner(root, IronLawsConfig(limits=Limits(max_cross_file_lookups=3))).scan()
    findings = sorted((v.rule_id, v.file_path.as_posix(), v.line_number) for v in report.violations)
    points = sorted((p.path, p.line, p.state) for p in report.coverage_ledger.points)
    limits = sorted(d.message for d in report.diagnostics if d.kind == "analysis_limit")
    return findings, points, limits


@pytest.mark.skipif(not hasattr(os, "fork"), reason="병렬 점검은 fork를 쓴다")
def test_results_do_not_depend_on_worker_count(tmp_path: Path, monkeypatch):
    _project(tmp_path)
    serial = _outcome(tmp_path, 1, monkeypatch)
    assert serial[0] and serial[2]
    assert _outcome(tmp_path, 2, monkeypatch) == serial
    assert _outcome(tmp_path, 4, monkeypatch) == serial


@pytest.mark.skipif(not hasattr(os, "fork"), reason="병렬 점검은 fork를 쓴다")
def test_configured_worker_count_and_parallel_threshold_are_used(tmp_path: Path, monkeypatch):
    _project(tmp_path)
    monkeypatch.setattr(os, "cpu_count", lambda: 8)
    config = IronLawsConfig(limits=Limits(max_cross_file_lookups=3, max_workers=2, parallel_min_files=2))
    report = AuditScanner(tmp_path, config).scan()
    serial = _outcome(tmp_path, 1, monkeypatch)
    findings = sorted((v.rule_id, v.file_path.as_posix(), v.line_number) for v in report.violations)
    assert findings == serial[0]  # 설정한 작업 프로세스 수로 나눠도 결과는 같다
