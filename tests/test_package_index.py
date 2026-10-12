"""
오철칙 오프라인 패키지 색인과 의존성 이름 점검(AI-111) 시험
- 색인이 완전하고 이름이 없으면 확인 필요(MEDIUM), 철자 유사는 HIGH, 둘이 겹치면 한 지적으로 합친다.
- 최근 게시 판정은 실행 날짜가 아니라 색인 수집 시각 기준이다.
- 작업공간·로컬 경로·Git 의존과 사설 패키지 패턴은 공개 색인 점검에서 뺀다.
작성자: 최진호
작성일: 2026-10-12
"""

import json
from pathlib import Path

from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.config import IronLawsConfig, Policies
from iron_laws.core.scanner import AuditScanner
from iron_laws.deps.package_index import build_index, load_index

runner = CliRunner()
NPM = ["express", "lodash", "left-pad", {"name": "fresh-lib", "created": "2026-09-20T10:00:00Z"}, {"name": "old-lib", "created": "2019-01-01"}]
PYPI = ["requests", "flask", "Django", "typing_extensions"]


def _index(tmp: Path, complete: bool = True) -> Path:
    tmp.mkdir(parents=True, exist_ok=True)
    out = tmp / "index"
    (tmp / "npm.json").write_text(json.dumps(NPM), encoding="utf-8")
    (tmp / "pypi.txt").write_text("\n".join(PYPI) + "\n", encoding="utf-8")
    build_index("npm", tmp / "npm.json", out, "시험용 npm 이름 목록", "2026-10-01T00:00:00Z", complete)
    build_index("pypi", tmp / "pypi.txt", out, "시험용 PyPI 이름 목록", "2026-10-01T00:00:00Z", complete)
    return out


def _scan(root: Path, files: dict[str, str], index: Path | None, private: list[str] | None = None):
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    policies = Policies(package_index=str(index) if index else None, private_packages=private or [])
    report = AuditScanner(root, IronLawsConfig(policies=policies)).scan()
    return [v for v in report.violations if v.rule_id == "AI-111"], report


def _names(found) -> list[str]:
    return sorted(v.message.split("은(는)")[0].removeprefix("패키지 ") for v in found if "은(는)" in v.message and v.message.startswith("패키지 "))


def test_index_round_trip_normalizes_names(tmp_path: Path):
    index = load_index(str(_index(tmp_path)))
    assert index.usable("pypi").knows("typing-extensions") and index.usable("pypi").knows("django")
    assert index.usable("npm").is_new("fresh-lib") == 11  # 수집 시각(10-01) 기준 게시 후 날 수
    assert index.usable("npm").is_new("old-lib") is None


def test_missing_new_and_typosquat_are_one_finding_each(tmp_path: Path):
    files = {
        "package.json": json.dumps({"dependencies": {"express": "4.19.2", "lodahs": "1.0.0", "ai-made-up-helper": "1.0.0", "fresh-lib": "1.0.0", "old-lib": "1.0.0"}}, indent=2),
        "package-lock.json": "{}",
    }
    found, _ = _scan(tmp_path / "p", files, _index(tmp_path))
    by_name = {name: v for v in found for name in _names([v])}
    assert set(by_name) == {"lodahs", "ai-made-up-helper", "fresh-lib"}
    assert by_name["lodahs"].severity.value == "HIGH" and "색인" in by_name["lodahs"].message  # 철자 유사 + 색인에 없음을 한 지적으로
    assert by_name["ai-made-up-helper"].severity.value == "MEDIUM"
    assert "11일 전" in by_name["fresh-lib"].message
    assert all(v.confidence.value == "REVIEW" for v in by_name.values())


def test_requirements_and_pyproject_names(tmp_path: Path):
    files = {
        "requirements.txt": "requests==2.32.3\nTyping_Extensions==4.12.2\nflask-made-up==1.0\n-e ./local\ngit+https://example.com/x.git\n",
        "pyproject.toml": '[project]\nname = "app"\ndependencies = ["Django>=5", "llm-hallucinated-pkg"]\n[tool.poetry.dependencies]\npython = "^3.12"\nlocalpkg = { path = "../localpkg" }\n',
    }
    found, _ = _scan(tmp_path / "p", files, _index(tmp_path))
    assert _names(found) == ["flask-made-up", "llm-hallucinated-pkg"]


def test_excluded_specs_and_private_patterns_are_not_public_names(tmp_path: Path):
    deps = {"@acme/ui": "1.0.0", "acme-core": "1.0.0", "local": "file:../local", "ws": "workspace:*", "gitdep": "github:me/gitdep", "real": "npm:lodash@4.17.21"}
    files = {"package.json": json.dumps({"dependencies": deps}, indent=2), "package-lock.json": "{}"}
    found, _ = _scan(tmp_path / "p", files, _index(tmp_path), private=["@acme/*", "acme-*"])
    assert _names(found) == []


def test_lock_file_transitive_names_are_checked_only_with_an_index(tmp_path: Path):
    lock = {"name": "app", "lockfileVersion": 3, "packages": {"": {"dependencies": {"express": "4.19.2"}}, "node_modules/express": {"version": "4.19.2"}, "node_modules/phantom-dep": {"version": "0.0.1"}}}
    files = {"package.json": json.dumps({"dependencies": {"express": "4.19.2"}}), "package-lock.json": json.dumps(lock, indent=2)}
    with_index, _ = _scan(tmp_path / "a", files, _index(tmp_path))
    assert [v.file_path.as_posix() for v in with_index if "phantom-dep" in v.message] == ["package-lock.json"]
    without_index, _ = _scan(tmp_path / "b", files, None)
    assert not any("phantom-dep" in v.message for v in without_index)


def test_incomplete_or_tampered_index_is_undeterminable_not_clean(tmp_path: Path):
    files = {"requirements.txt": "llm-hallucinated-pkg==1.0\n"}
    found, report = _scan(tmp_path / "a", files, _index(tmp_path / "i1", complete=False))
    assert _names(found) == []
    assert any(d.kind == "package_index" and "pypi" in d.message for d in report.diagnostics)
    tampered = _index(tmp_path / "i2")
    (tampered / "pypi.tsv.gz").write_bytes(b"x")
    load_index.cache_clear()
    found, report = _scan(tmp_path / "b", files, tampered)
    assert _names(found) == []
    assert any(d.kind == "package_index" and "sha256" in d.message for d in report.diagnostics)


def test_cli_index_build_and_audit_option(tmp_path: Path):
    (tmp_path / "names.txt").write_text("requests 2011-05-01\n", encoding="utf-8")
    result = runner.invoke(app, ["index", "build", "--ecosystem", "pypi", "--source", str(tmp_path / "names.txt"), "--out", str(tmp_path / "idx"),
                                 "--source-name", "시험", "--collected-at", "2026-10-01T00:00:00Z", "--complete"])
    assert result.exit_code == 0, result.output
    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.32.3\nmade-up-pkg==1.0\n", encoding="utf-8")
    result = runner.invoke(app, ["audit", str(project), "--format", "json", "--limit", "0", "--package-index", str(tmp_path / "idx")])
    data = json.loads(result.stdout)
    messages = [v["message"] for v in data["violations"] if v["rule_id"] == "AI-111"]
    assert any("made-up-pkg" in m for m in messages) and not any("패키지 requests" in m for m in messages)
    missing = runner.invoke(app, ["audit", str(project), "--package-index", str(tmp_path / "nothing")])
    assert missing.exit_code == 2


def test_import_names_are_checked_only_with_a_module_index(tmp_path: Path):
    out = _index(tmp_path / "i")
    (tmp_path / "mods.txt").write_text("yaml PyYAML\nrequests requests\nflask Flask\n", encoding="utf-8")
    files = {
        "app/__init__.py": "",
        "app/util.py": "x = 1\n",
        "app/main.py": "import os\nimport yaml\nfrom app import util\nfrom . import util as u2\nimport ai_invented_helper\nfrom flask import Flask\n",
        "web/index.js": "const fs = require('fs');\nimport path from 'node:path';\nimport express from 'express';\nimport { thing } from 'made-up-lib';\nimport ui from '@acme/ui';\nimport local from './local';\n",
    }
    found, _ = _scan(tmp_path / "p1", files, out, private=["@acme/*"])
    assert not any("import 이름" in v.message and v.file_path.as_posix() == "app/main.py" for v in found)  # 모듈 색인이 없으면 Python import는 판정하지 않는다
    assert [v.line_number for v in found if "import 이름" in v.message and v.file_path.as_posix() == "web/index.js"] == [4]
    build_index("pypi-modules", tmp_path / "mods.txt", out, "시험용 모듈 매핑", "2026-10-01T00:00:00Z", True)
    found, _ = _scan(tmp_path / "p2", files, out, private=["@acme/*"])
    assert [v.line_number for v in found if "import 이름" in v.message and v.file_path.as_posix() == "app/main.py"] == [5]
