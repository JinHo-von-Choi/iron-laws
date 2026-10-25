"""
Python 위험 모듈의 별칭과 가져온 이름: import os as o, from os import system으로 부른 호출도 같은 위험 호출로 찾는다
작성자: 최진호
작성일: 2026-10-26
"""

from pathlib import Path

import pytest

from iron_laws.core.scanner import AuditScanner
from iron_laws.engine.ast_tools import iter_calls
from iron_laws.engine.source import SourceFile


def scan(tmp_path: Path, code: str):
    (tmp_path / "app.py").write_text("from flask import request\n" + code, encoding="utf-8")
    report = AuditScanner(tmp_path).scan()
    findings = sorted(v.line_number for v in report.violations if v.rule_id == "IL-504")
    points = sorted((p.line, p.callee) for p in report.coverage_ledger.points if p.family == "command")
    return findings, points


@pytest.mark.parametrize("imports, call, callee", [
    ("import os as o", 'o.system("ls " + request.args["d"])', "os.system"),
    ("from os import system", 'system("ls " + request.args["d"])', "os.system"),
    ("from subprocess import check_output as co", 'co("ls " + request.args["d"], shell=True)', "subprocess.check_output"),
    ("import subprocess as sp", 'sp.run("ls " + request.args["d"], shell=True)', "subprocess.run"),
    ("import os", 'getattr(os, "system")("ls " + request.args["d"])', "os.system"),
    ("import os", '__import__("os").system("ls " + request.args["d"])', "os.system"),
    ("import importlib", 'importlib.import_module("os").system("ls " + request.args["d"])', "os.system"),
])
def test_aliased_command_calls_are_found_and_counted(tmp_path, imports, call, callee):
    findings, points = scan(tmp_path, f"{imports}\n\ndef handler():\n    {call}\n")
    assert findings == [5]
    assert points == [(5, callee)]


def test_rebound_name_is_not_treated_as_the_module_function(tmp_path):
    findings, points = scan(tmp_path, "from os import system\n\ndef handler(system):\n    system('ls ' + request.args['d'])\n")
    assert findings == [] and points == []


def test_other_modules_keep_their_short_names():
    src = SourceFile(Path("a.py"), "from flask import request\nimport json as j\n\ndef f():\n    request.args.get('x')\n    j.loads('{}')\n")
    assert [c.callee for c in iter_calls(src)] == ["request.args.get", "j.loads"]


def test_function_stored_in_a_variable_is_found(tmp_path):
    findings, points = scan(tmp_path, "import os as o\n\ndef handler():\n    run = o.system\n    run('ls ' + request.args['d'])\n")
    assert findings == [6] and points == [(6, "os.system")]


def test_non_constant_getattr_name_is_left_alone():
    src = SourceFile(Path("a.py"), "import os\n\ndef f(name):\n    getattr(os, name)('ls')\n")
    assert [c.callee for c in iter_calls(src)] == ["getattr(os,name)", "getattr"]
