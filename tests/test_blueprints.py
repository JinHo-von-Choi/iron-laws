"""
오철칙 구조 틀(init --stack) 시험: 미리보기는 파일을 만들지 않고, --write는 없는 것만 만들며, 지침 절은 다시 실행해도 하나이고,
틀의 구조 계약이 별칭 import(@/…)까지 판정한다
작성자: 최진호
작성일: 2026-11-28
"""

import json
from pathlib import Path

from typer.testing import CliRunner

from iron_laws.blueprints import BLUEPRINTS, MARK_START, detect
from iron_laws.cli import app
from iron_laws.core.config import IronLawsConfig
from iron_laws.core.scanner import AuditScanner
from tests.helpers import lines_of

runner = CliRunner()


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    return root


def test_preview_writes_nothing(tmp_path: Path):
    result = runner.invoke(app, ["init", str(tmp_path), "--stack", "fastapi"])
    assert result.exit_code == 0, result.output
    assert "app/services" in result.output and "[ARC-207]" in result.output
    assert list(tmp_path.iterdir()) == []


def test_write_keeps_existing_files_and_replaces_only_its_section(tmp_path: Path):
    _write(tmp_path, {"CLAUDE.md": "# 팀 규칙\n- 커밋은 작게\n", ".iron-laws.yml": "fail_on: MEDIUM\n"})
    assert runner.invoke(app, ["init", str(tmp_path), "--stack", "fastapi", "--write"]).exit_code == 0
    assert runner.invoke(app, ["init", str(tmp_path), "--stack", "fastapi", "--write"]).exit_code == 0
    guide = (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")
    assert guide.startswith("# 팀 규칙\n- 커밋은 작게\n") and guide.count(MARK_START) == 1
    config = (tmp_path / ".iron-laws.yml").read_text(encoding="utf-8")
    assert config.startswith("fail_on: MEDIUM\n") and config.count("architecture:") == 1  # 두 번째 실행은 계약을 다시 더하지 않는다
    assert (tmp_path / "app" / "services").is_dir() and not (tmp_path / "AGENTS.md").exists()


def test_detect_stack_from_code(tmp_path: Path):
    assert detect(_write(tmp_path / "n", {"package.json": json.dumps({"dependencies": {"next": "15.0.0"}})})) == "nextjs"
    assert detect(_write(tmp_path / "f", {"main.py": "from fastapi import FastAPI\n"})) == "fastapi"
    assert detect(_write(tmp_path / "x", {"main.py": "print(1)\n"})) is None
    assert runner.invoke(app, ["init", str(tmp_path / "x"), "--stack", "auto"]).exit_code == 2


def test_nextjs_contract_catches_alias_imports(tmp_path: Path):
    root = _write(tmp_path, {
        "tsconfig.json": '{"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["./*"]}}}\n',
        "components/UserCard.tsx": 'import { findUser } from "@/server/db/users";\nexport function UserCard() { return findUser(1); }\n',
        "server/db/users.ts": "export function findUser(id: number) { return id; }\n",
        "app/page.tsx": 'import { UserCard } from "@/components/UserCard";\nexport default function Page() { return UserCard(); }\n',
    })
    config = IronLawsConfig(architecture=BLUEPRINTS["nextjs"].contract())
    violations = AuditScanner(root, config=config).scan().violations
    assert lines_of(violations, "ARC-207", "components/UserCard.tsx") == [1]  # 화면 부품이 별칭으로 DB 코드를 부른다
    assert lines_of(violations, "ARC-207", "app/page.tsx") == []
    result = runner.invoke(app, ["init", str(root), "--stack", "nextjs"])
    assert "먼저 고칠 것: components/UserCard.tsx:1" in result.output
