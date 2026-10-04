"""
오철칙 시험 도구: 임시 디렉터리에 파일을 만들고 전체 점검 파이프라인을 실행한다
작성자: 최진호
작성일: 2026-10-04
"""

from pathlib import Path

from iron_laws.core.models import Violation
from iron_laws.core.scanner import AuditScanner


def scan_files(root: Path, files: dict[str, str], config=None) -> list[Violation]:
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return AuditScanner(root, config).scan().violations


def lines_of(violations: list[Violation], rule_id: str, path: str | None = None) -> list[int]:
    return sorted(
        v.line_number
        for v in violations
        if v.rule_id == rule_id and (path is None or v.file_path.as_posix() == path)
    )
