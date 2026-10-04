"""
오철칙 실프로젝트(asyncpg 기반 대형 저장소) 감리에서 확인한 오탐 보정 회귀 시험
작성자: 최진호
작성일: 2026-10-04
"""

from pathlib import Path

import pytest

from iron_laws.core.models import Confidence
from tests.helpers import lines_of, scan_files

PLACEHOLDER_BUILDER = '''from flask import request

async def f(conn):
    docs = await conn.fetch("SELECT 1", request.args["q"])
    placeholders = []
    for i, (a, b) in enumerate(docs):
        idx = i * 2 + 1
        placeholders.append(f"(x = ${idx})")
    where = " OR ".join(placeholders)
    return await conn.fetch(f"SELECT * FROM t WHERE {where}")
'''

CASES = [
    ("enumerate-index-is-not-tainted", PLACEHOLDER_BUILDER, "IL-501", []),
    (
        "range-index-is-not-tainted",
        'from flask import request\n\nasync def f(conn):\n    n = request.args["n"]\n    parts = []\n    for i in range(int(n)):\n        parts.append(f"${i}")\n    return await conn.fetch("SELECT " + ",".join(parts))\n',
        "IL-501",
        [],
    ),
    (
        "len-inside-fstring-is-not-tainted",
        'from flask import request\n\nasync def f(conn):\n    params = [request.args["a"]]\n    clauses = []\n    clauses.append(f"a = ${len(params)}")\n    return await conn.fetch("SELECT * FROM t WHERE " + " AND ".join(clauses), *params)\n',
        "IL-501",
        [],
    ),
    (
        "source-words-inside-a-string-literal-are-data",
        'import os\n\nEXAMPLE = \'name = request.args["n"]\'\n\ndef f(path):\n    with open(path, "w") as fh:\n        fh.write(EXAMPLE)\n    os.system("ls " + EXAMPLE)\n',
        "IL-504",
        [],
    ),
    (
        "source-inside-fstring-interpolation-is-code",
        'import os\nfrom flask import request\n\ndef f():\n    os.system(f"ls {request.args[\'d\']}")\n',
        "IL-504",
        [5],
    ),
    (
        "real-injection-still-confirmed",
        'from flask import request\n\nasync def g(conn):\n    name = request.args["n"]\n    return await conn.fetch(f"SELECT * FROM t WHERE n = {name}")\n',
        "IL-501",
        [5],
    ),
    (
        "enumerate-value-still-tainted",
        'from flask import request\n\nasync def g(conn):\n    names = request.args.getlist("n")\n    for i, name in enumerate(names):\n        await conn.fetch(f"SELECT * FROM t WHERE n = {name}")\n',
        "IL-501",
        [6],
    ),
]


@pytest.mark.parametrize(("name", "code", "rule", "expected"), CASES, ids=[c[0] for c in CASES])
def test_refinement_cases(tmp_path: Path, name, code, rule, expected):
    violations = [v for v in scan_files(tmp_path, {"a.py": code}) if v.confidence is Confidence.CONFIRMED]
    assert lines_of(violations, rule, "a.py") == expected, name
