"""
검사 범위의 분모: 외부 파일 목록과 분석한 파일을 대조해 상태를 붙이고, 사유 없이 빠진 파일은 숨기지 않는다
작성자: 최진호
작성일: 2026-10-26
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.build_manifest import classify
from iron_laws.core.scanner import AuditScanner
from iron_laws.evidence.verifier import verify_report
from iron_laws.reporters.markdown import generate_markdown_report

cli = CliRunner()
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git이 필요하다")


def repo(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    files = {
        "app.py": "import os\nfrom flask import request\n\ndef a():\n    os.system('ls ' + request.args['d'])\n\ndef b():\n    os.system('ls ' + request.args['e'])\n",
        "node_modules/lib/index.js": "module.exports = 1\n",
        "notes.xyz": "memo\n",
        "util.py": "def helper(x):\n    return x + 1\n",
        "gone.py": "x = 1\n",
    }
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    (root / "big.py").write_text("x = 1\n" * 400_000, encoding="utf-8")
    for args in (["init", "-q"], ["add", "-A", "-f"], ["-c", "user.email=t@e", "-c", "user.name=t", "commit", "-q", "-m", "init"]):
        subprocess.run(["git", "-C", str(root), *args], check=True)
    (root / "gone.py").unlink()
    return root


@needs_git
def test_git_listing_gives_every_file_a_reason(tmp_path: Path):
    root = repo(tmp_path)
    report = AuditScanner(root, build_manifest="git").scan()
    coverage = report.metadata["file_coverage"]
    assert coverage["source"] == "git" and coverage["listed"] == 6
    assert coverage["counts"] == {"analyzed": 2, "excluded": 1, "missing": 1, "skipped": 1, "unsupported": 1}
    assert coverage["unexplained"] == [] and report.summary.scan_status == "complete"
    assert "skipped:파일 크기 한도 초과" in coverage["examples"]
    assert verify_report(report.model_dump(mode="json")).ok


@needs_git
def test_unexplained_files_are_reported_and_can_block(tmp_path: Path, monkeypatch):
    root = repo(tmp_path)
    original = AuditScanner._read_sources
    monkeypatch.setattr(AuditScanner, "_read_sources", lambda self: [s for s in original(self) if s.path.name != "app.py"])
    warned = AuditScanner(root, build_manifest="git").scan()
    assert warned.metadata["file_coverage"]["unexplained"] == ["app.py"]
    assert warned.summary.scan_status != "incomplete"
    assert any(d.kind == "coverage" and d.severity == "warning" for d in warned.diagnostics)
    blocked = AuditScanner(root, build_manifest="git", require_full_coverage=True).scan()
    assert blocked.summary.scan_status == "incomplete"
    assert verify_report(blocked.model_dump(mode="json")).ok


def test_listing_failure_is_not_silently_treated_as_checked(tmp_path: Path):
    root = tmp_path / "plain"
    root.mkdir()
    (root / "a.py").write_text("x = 1\n", encoding="utf-8")
    soft = AuditScanner(root, build_manifest="file:" + str(tmp_path / "missing.txt")).scan()
    assert "file_coverage" not in soft.metadata
    assert any(d.kind == "coverage" for d in soft.diagnostics) and soft.summary.scan_status == "complete"
    hard = AuditScanner(root, build_manifest="file:" + str(tmp_path / "missing.txt"), require_full_coverage=True).scan()
    assert hard.summary.scan_status == "incomplete"


def test_user_list_handles_outside_and_duplicate_paths(tmp_path: Path):
    root = tmp_path / "plain"
    root.mkdir()
    (root / "a.py").write_text("x = 1\n", encoding="utf-8")
    listing = tmp_path / "list.txt"
    listing.write_text(f"# 빌드 도구가 준 목록\na.py\n./a.py\n{root / 'a.py'}\n../elsewhere.py\n", encoding="utf-8")
    coverage = AuditScanner(root, build_manifest=f"file:{listing}").scan().metadata["file_coverage"]
    assert coverage["listed"] == 2 and coverage["counts"] == {"analyzed": 1, "outside_root": 1}


def test_classify_marks_files_in_excluded_parent_directories(tmp_path: Path):
    (tmp_path / "build" / "gen").mkdir(parents=True)
    (tmp_path / "build" / "gen" / "x.py").write_text("x = 1\n", encoding="utf-8")
    coverage = classify(tmp_path, "file:t", ["build/gen/x.py"], set(), {}, lambda p: "build" if p.name == "build" else None, lambda p: True)
    assert coverage.counts == {"excluded": 1} and "excluded:build" in coverage.examples


@needs_git
def test_verifier_catches_inconsistent_or_hidden_coverage(tmp_path: Path, monkeypatch):
    root = repo(tmp_path)
    data = AuditScanner(root, build_manifest="git").scan().model_dump(mode="json")
    tampered = json.loads(json.dumps(data))
    tampered["metadata"]["file_coverage"]["counts"]["analyzed"] += 1
    assert "coverage.count_mismatch" in {p.code for p in verify_report(tampered).problems}
    hidden = json.loads(json.dumps(data))
    hidden["metadata"]["file_coverage"]["counts"]["analyzed"] -= 1
    hidden["metadata"]["file_coverage"]["counts"]["unexplained"] = 1
    hidden["metadata"]["file_coverage"]["unexplained"] = ["app.py"]
    assert "coverage.unexplained_hidden" in {p.code for p in verify_report(hidden).problems}


@needs_git
def test_markdown_shows_repeated_sinks_and_file_coverage(tmp_path: Path):
    root = repo(tmp_path)
    text = generate_markdown_report(AuditScanner(root, build_manifest="git").scan())
    assert "| command | `os.system` | 2 |" in text
    assert "파일 목록(git) 6개와 대조" in text


@needs_git
def test_cli_require_full_coverage_exit_code(tmp_path: Path):
    root = repo(tmp_path)
    assert cli.invoke(app, ["check", str(root), "--build-manifest", "git", "--require-full-coverage", "--fail-on", "CRITICAL"]).exit_code in (0, 1)
    assert cli.invoke(app, ["check", str(root), "--build-manifest", "nope", "--require-full-coverage"]).exit_code == 2
