"""
오철칙 구조 계약 시험(`.iron-laws.yml`의 architecture): 계약이 있으면 폴더 이름 추정 대신 계약으로 의존 방향을 판정한다.
작성자: 최진호
작성일: 2026-11-10
"""

from pathlib import Path

from iron_laws.core.scanner import AuditScanner


def project(root: Path, files: dict[str, str], config: str = "") -> Path:
    for rel, text in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    if config:
        (root / ".iron-laws.yml").write_text(config, encoding="utf-8")
    return root


def messages(root: Path, rule: str = "ARC-207") -> list[tuple[str, str]]:
    report = AuditScanner(root).scan()
    return [(v.file_path.as_posix(), v.message) for v in report.violations if v.rule_id == rule]


LAYERS = """architecture:
  layers:
    - {name: handlers, paths: ["app/handlers/**"]}
    - {name: logic, paths: ["app/logic/**"]}
    - {name: store, paths: ["app/store/**"]}
"""
UNCONVENTIONAL = {
    "app/handlers/h.py": "from app.logic import l\n\ndef h():\n    return l.run()\n",
    "app/logic/l.py": "from app.store import s\n\ndef run():\n    return s.get()\n",
    "app/store/s.py": "def get():\n    return 1\n",
}


def test_contract_layers_catch_upward_import_where_names_give_no_hint(tmp_path: Path):
    files = {**UNCONVENTIONAL, "app/store/s.py": "from app.handlers import h\n\ndef get():\n    return h.h()\n"}
    root = project(tmp_path, files, LAYERS)
    found = messages(root)
    assert any(path == "app/store/s.py" and "store 계층이 위 계층인 handlers 계층" in text for path, text in found), found
    assert messages(project(tmp_path / "no-contract", files)) == []  # 폴더 이름만으로는 계층을 알 수 없다


def test_downward_imports_pass_under_the_contract(tmp_path: Path):
    assert messages(project(tmp_path, UNCONVENTIONAL, LAYERS)) == []


def test_contract_replaces_folder_name_inference(tmp_path: Path):
    files = {  # 이름만 보면 core(서비스)가 cli(표현)를 부르는 위반이지만, 계약은 core를 위 계층으로 선언했다
        "core/engine.py": "from cli import helpers\n\ndef run():\n    return helpers.fmt()\n",
        "cli/helpers.py": "def fmt():\n    return 1\n",
        "api/routes.py": "from core import engine\n\ndef route():\n    return engine.run()\n",
    }
    inferred = messages(project(tmp_path / "a", files))
    assert any(path == "core/engine.py" for path, _ in inferred), inferred
    contract = "architecture:\n  layers:\n    - {name: core, paths: ['core/**']}\n    - {name: cli, paths: ['cli/**']}\n"
    assert not any(path == "core/engine.py" for path, _ in messages(project(tmp_path / "b", files, contract)))


def test_forbidden_import_reports_the_reason(tmp_path: Path):
    files = {"domain/m.py": "from infra import db\n\ndef m():\n    return db.q()\n", "infra/db.py": "def q():\n    return 1\n"}
    config = "architecture:\n  forbidden:\n    - {from: 'domain/**', to: 'infra/**', reason: 도메인은 인프라를 몰라야 한다}\n"
    found = messages(project(tmp_path, files, config))
    assert len(found) == 1 and "도메인은 인프라를 몰라야 한다" in found[0][1] and found[0][0] == "domain/m.py"


def test_independent_modules_must_not_import_each_other(tmp_path: Path):
    files = {
        "plugins/a/x.py": "from plugins.b import y\n\ndef x():\n    return y.y()\n",
        "plugins/b/y.py": "def y():\n    return 1\n",
        "plugins/b/z.py": "from plugins.b import y\n\ndef z():\n    return y.y()\n",
    }
    config = "architecture:\n  independent:\n    - ['plugins/a/**', 'plugins/b/**']\n"
    found = messages(project(tmp_path, files, config))
    assert [path for path, _ in found] == ["plugins/a/x.py"]  # 같은 묶음 안(b → b)은 금지가 아니다


def test_strict_reports_dependencies_on_files_outside_every_layer(tmp_path: Path):
    files = {**UNCONVENTIONAL, "app/logic/l.py": "from app.store import s\nfrom app import extra\n\ndef run():\n    return s.get() + extra.v\n", "app/extra.py": "v = 1\n"}
    assert messages(project(tmp_path / "loose", files, LAYERS)) == []
    found = messages(project(tmp_path / "strict", files, LAYERS + "  strict: true\n"))
    assert len(found) == 1 and "어느 계층에도 속하지 않는" in found[0][1]


def test_layer_kind_enables_driver_and_framework_import_checks(tmp_path: Path):
    files = {"app/handlers/h.py": "import sqlite3\n\ndef h():\n    return sqlite3\n", "app/store/s.py": "from flask import request\n\ndef g():\n    return request\n"}
    plain = "architecture:\n  layers:\n    - {name: handlers, paths: ['app/handlers/**']}\n    - {name: store, paths: ['app/store/**']}\n"
    assert messages(project(tmp_path / "plain", files, plain)) == []
    typed = "architecture:\n  layers:\n    - {name: handlers, paths: ['app/handlers/**'], kind: presentation}\n    - {name: store, paths: ['app/store/**'], kind: data}\n"
    found = messages(project(tmp_path / "typed", files, typed))
    assert len(found) == 2 and any("DB 라이브러리" in text for _, text in found) and any("웹 프레임워크" in text for _, text in found)
