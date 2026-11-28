"""
오철칙 운영 기본기 규칙(OPS-101~103)의 양성·음성 사례 시험
작성자: 최진호
작성일: 2026-11-28
"""

from pathlib import Path

import pytest

from tests.helpers import lines_of

FLASK = "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/items')\ndef items():\n    return 'x'\n"
EXPRESS = "const express = require('express');\nconst app = express();\napp.get('/items', (req, res) => res.send('x'));\n"
CI_TEST = "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pytest -q\n"
CI_LINT = "jobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ruff check .\n"
DOCKER = "FROM python:3.12-slim\nCOPY . /app\nCMD [\"python\", \"/app/app.py\"]\n"

# (사례 이름, 규칙 ID, {파일: 내용}, 기대 위치 {파일: [줄 번호]}) - 빈 dict는 지적 없음을 뜻한다
CASES: list[tuple[str, str, dict[str, str], dict[str, list[int]]]] = [
    ("ops101-python-no-ci", "OPS-101", {"app.py": FLASK}, {"app.py": [5]}),
    ("ops101-js-no-ci", "OPS-101", {"server.js": EXPRESS}, {"server.js": [3]}),
    ("ops101-ci-runs-tests", "OPS-101", {"app.py": FLASK, ".github/workflows/ci.yml": CI_TEST}, {}),
    ("ops101-ci-without-tests", "OPS-101", {"app.py": FLASK, ".github/workflows/ci.yml": CI_LINT}, {".github/workflows/ci.yml": [1]}),
    ("ops101-cli-without-routes", "OPS-101", {"cli.py": "import sys\nprint(sys.argv)\n"}, {}),
    ("ops102-python-orm-no-migrations", "OPS-102", {"app.py": FLASK + "from sqlalchemy import create_engine\n"}, {"app.py": [7]}),
    ("ops102-js-prisma-no-migrations", "OPS-102", {"server.js": "const { PrismaClient } = require('@prisma/client');\n" + EXPRESS}, {"server.js": [1]}),
    ("ops102-alembic-present", "OPS-102", {"app.py": FLASK + "from sqlalchemy import create_engine\n", "migrations/versions/001_init.py": "revision = '001'\n"}, {}),
    ("ops102-no-db", "OPS-102", {"app.py": FLASK}, {}),
    ("ops103-docker-without-health", "OPS-103", {"app.py": FLASK, "Dockerfile": DOCKER}, {"Dockerfile": [1]}),
    ("ops103-health-route", "OPS-103", {"app.py": FLASK + "\n@app.route('/health')\ndef health():\n    return 'ok'\n", "Dockerfile": DOCKER}, {}),
    ("ops103-dockerfile-healthcheck", "OPS-103", {"app.py": FLASK, "Dockerfile": DOCKER + "HEALTHCHECK CMD curl -f http://localhost:8000/ || exit 1\n"}, {}),
    ("ops103-no-container", "OPS-103", {"server.js": EXPRESS}, {}),
    ("ops103-compose-healthcheck", "OPS-103", {"app.py": FLASK, "Dockerfile": DOCKER, "docker-compose.yml": "services:\n  web:\n    build: .\n    healthcheck:\n      test: curl -f http://localhost:8000/\n"}, {}),
    ("ops103-compose-db-healthcheck-only", "OPS-103", {"app.py": FLASK, "Dockerfile": DOCKER, "docker-compose.yml": "services:\n  web:\n    build: .\n  db:\n    image: postgres:16\n    healthcheck:\n      test: pg_isready\n"}, {"Dockerfile": [1]}),
    ("ops103-sample-yaml-is-not-evidence", "OPS-103", {"app.py": FLASK, "Dockerfile": DOCKER, "data/samples/compose-example.yml": "services:\n  db:\n    healthcheck:\n      test: pg_isready\n"}, {"Dockerfile": [1]}),
]


@pytest.mark.parametrize(("case_id", "rule_id", "files", "expected"), CASES, ids=[c[0] for c in CASES])
def test_operations_case(tmp_path: Path, case_id: str, rule_id: str, files: dict[str, str], expected: dict[str, list[int]]):
    from iron_laws.core.scanner import AuditScanner

    for rel, content in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    violations = AuditScanner(tmp_path).scan().violations
    actual = {path: lines_of(violations, rule_id, path) for path in files}
    actual = {p: ls for p, ls in actual.items() if ls}
    assert actual == expected, f"{case_id}: 기대 {expected}, 실제 {actual}"
