"""
오철칙 Scanner & Audit Engine
작성자: 최진호
작성일: 2026-10-04
"""

import fnmatch
import multiprocessing
import os
import sys
from collections.abc import Generator
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from datetime import UTC, datetime
from pathlib import Path

from iron_laws.core.config import SPECIAL_FILE_PATTERNS, IronLawsConfig, load_config
from iron_laws.core.models import (
    AuditReport,
    AuditSummary,
    Severity,
    Violation,
)
from iron_laws.core.paths import is_test_path, looks_vendored_js
from iron_laws.core.suppress import FileSuppressions, parse_suppressions
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.source import SourceFile
from iron_laws.rules.catalog import get_active_rules

SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}

PARALLEL_MIN_FILES = 300
MAX_WORKERS = 8


def _scan_chunk(config_data: dict, items: list[tuple[str, str, bool]]) -> list[Violation]:
    """작업 프로세스에서 파일 단위 규칙을 실행한다."""
    config = IronLawsConfig(**config_data)
    rules = get_active_rules(
        enabled=config.enabled_rules, disabled=config.disabled_rules, config=config
    )
    violations: list[Violation] = []
    for rel, content, in_test in items:
        src = SourceFile(Path(rel), content, is_test=in_test)
        for rule in rules:
            if src.is_test and not rule.include_tests:
                continue
            if rule.applies_to(src):
                violations.extend(rule.check(src))
        src.release()
    return violations


def looks_minified(content: str) -> bool:
    """줄이 극단적으로 길어 사람이 쓰지 않은 압축·생성 파일로 보이는지 판정한다."""
    if len(content) < 20_000:
        return False
    lines = content.splitlines() or [content]
    longest = max(len(line) for line in lines)
    return longest > 4_000 or len(content) / len(lines) > 400


class AuditScanner:
    def __init__(self, root_path: Path, config: IronLawsConfig | None = None):
        self.root_path = root_path.resolve()
        self.config = config or load_config(self.root_path)
        self._skipped: list[dict[str, str]] = []
        self._all_paths: set[str] = set()
        self.rules = get_active_rules(
            enabled=self.config.enabled_rules,
            disabled=self.config.disabled_rules,
            config=self.config,
        )

    def _relative(self, path: Path) -> Path:
        if self.root_path.is_file():
            return Path(path.name)
        return path.relative_to(self.root_path)

    def _should_exclude(self, path: Path) -> bool:
        rel = self._relative(path)
        rel_posix = rel.as_posix()
        for ex in self.config.excludes:
            if ex in rel.parts:
                return True
            if fnmatch.fnmatch(rel_posix, ex) or fnmatch.fnmatch(rel.name, ex):
                return True
        return False

    def _is_included(self, path: Path) -> bool:
        if path.suffix.lower() in self.config.include_extensions:
            return True
        return any(fnmatch.fnmatch(path.name, pat) for pat in SPECIAL_FILE_PATTERNS)

    def discover_files(self) -> Generator[Path]:
        if self.root_path.is_file():
            yield self.root_path
            return

        for dirpath, dirnames, filenames in os.walk(self.root_path):
            current_dir = Path(dirpath)

            dirnames[:] = [d for d in dirnames if not self._should_exclude(current_dir / d)]

            for fname in filenames:
                fpath = current_dir / fname
                self._all_paths.add(self._relative(fpath).as_posix())
                if self._should_exclude(fpath):
                    continue
                if self._is_included(fpath):
                    yield fpath

    def _load_gitignore(self) -> list[str]:
        base = self.root_path if self.root_path.is_dir() else self.root_path.parent
        gitignore = base / ".gitignore"
        if not gitignore.is_file():
            return []
        try:
            return gitignore.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as e:
            self._skipped.append({"path": ".gitignore", "reason": f"읽기 실패: {e.strerror or e}"})
            return []

    @staticmethod
    def _dedupe(violations: list[Violation]) -> list[Violation]:
        """같은 규칙이 같은 줄에서 여러 번 보고된 경우 하나만 남긴다."""
        seen: set[tuple[str, str, int]] = set()
        unique = []
        for v in violations:
            key = (v.rule_id, v.file_path.as_posix(), v.line_number)
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique

    @staticmethod
    def _apply_suppressions(
        violations: list[Violation], sources: list[SourceFile]
    ) -> tuple[list[Violation], int]:
        table: dict[str, FileSuppressions] = {
            src.path.as_posix(): parse_suppressions(src.lines) for src in sources
        }
        kept = []
        suppressed = 0
        for v in violations:
            rules = table.get(v.file_path.as_posix())
            if rules is not None and rules.covers(v):
                suppressed += 1
            else:
                kept.append(v)
        return kept, suppressed

    def _read_sources(self) -> list[SourceFile]:
        sources: list[SourceFile] = []
        max_bytes = self.config.limits.max_file_bytes
        for file_path in self.discover_files():
            rel_path = self._relative(file_path)
            try:
                if file_path.stat().st_size > max_bytes:
                    self._skipped.append({"path": rel_path.as_posix(), "reason": "파일 크기 한도 초과"})
                    continue
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError as e:
                self._skipped.append({"path": rel_path.as_posix(), "reason": f"읽기 실패: {e.strerror or e}"})
                continue
            if looks_vendored_js(rel_path, content):
                self._skipped.append({"path": rel_path.as_posix(), "reason": "제3자 라이브러리 사본으로 판단"})
                continue
            if looks_minified(content):
                self._skipped.append({"path": rel_path.as_posix(), "reason": "압축·생성된 파일로 판단"})
                continue
            sources.append(SourceFile(rel_path, content, is_test=is_test_path(rel_path)))
        sources.sort(key=lambda f: f.path.as_posix())
        return sources

    def _run_file_rules_serial(self, sources: list[SourceFile]) -> list[Violation]:
        violations: list[Violation] = []
        for src in sources:
            for rule in self.rules:
                if src.is_test and not rule.include_tests:
                    continue
                if rule.applies_to(src):
                    violations.extend(rule.check(src))
            src.release()
        return violations

    def _run_file_rules(self, sources: list[SourceFile]) -> list[Violation]:
        workers = min(os.cpu_count() or 1, MAX_WORKERS)
        parallel_ok = sys.platform.startswith("linux") and len(sources) >= PARALLEL_MIN_FILES
        if not parallel_ok or workers < 2:
            return self._run_file_rules_serial(sources)

        items = [(s.path.as_posix(), s.text, s.is_test) for s in sources]
        size = -(-len(items) // (workers * 4))
        chunks = [items[i : i + size] for i in range(0, len(items), size)]
        config_data = self.config.model_dump(mode="json")
        try:
            with ProcessPoolExecutor(
                max_workers=workers, mp_context=multiprocessing.get_context("fork")
            ) as pool:
                results = pool.map(_scan_chunk, [config_data] * len(chunks), chunks)
                return [v for chunk_result in results for v in chunk_result]
        except BrokenProcessPool:  # iron-laws: ignore[IL-301] 병렬 처리 실패를 점검 제외 목록에 기록하고 순차 처리로 이어간다
            self._skipped.append({"path": "(병렬 처리)", "reason": "작업 프로세스 오류로 순차 처리로 전환"})
            return self._run_file_rules_serial(sources)

    def _run_rules(self, sources: list[SourceFile]) -> list[Violation]:
        violations = self._run_file_rules(sources)

        project = ProjectContext(
            root=self.root_path,
            files=sources,
            config=self.config,
            all_paths=self._all_paths,
            gitignore_patterns=self._load_gitignore(),
        )
        for rule in self.rules:
            violations.extend(rule.check_project(project))
            for src in sources:
                src.release()
        return violations

    def scan(self) -> AuditReport:
        self._skipped = []
        self._all_paths = set()
        sources = self._read_sources()
        violations = self._run_rules(sources)
        violations = self._dedupe(violations)
        violations, suppressed = self._apply_suppressions(violations, sources)
        violations.sort(key=lambda v: (str(v.file_path), v.line_number, v.rule_id))
        files_scanned = len(sources)

        crit = sum(1 for v in violations if v.severity == Severity.CRITICAL)
        high = sum(1 for v in violations if v.severity == Severity.HIGH)
        med = sum(1 for v in violations if v.severity == Severity.MEDIUM)
        low = sum(1 for v in violations if v.severity == Severity.LOW)

        if crit > 0:
            grade = "F"
        elif high > 0:
            grade = "D"
        elif med > 0:
            grade = "B"
        elif low > 0:
            grade = "A-"
        else:
            grade = "A+"

        threshold = SEVERITY_ORDER[self.config.fail_on]
        passed = not any(SEVERITY_ORDER[v.severity] >= threshold for v in violations)

        summary = AuditSummary(
            total_files_scanned=files_scanned,
            total_violations=len(violations),
            suppressed_count=suppressed,
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            is_passed=passed,
            grade=grade,
        )

        now_utc = datetime.now(UTC)
        doc_id = f"AUDIT-{now_utc.strftime('%Y%m%d-%H%M%S')}"

        return AuditReport(
            document_id=doc_id,
            audit_date=now_utc.strftime("%Y-%m-%d"),
            target_path=str(self.root_path),
            summary=summary,
            violations=violations,
            metadata={
                "config": self.config.model_dump(mode="json"),
                "skipped_files": self._skipped,
            },
        )
