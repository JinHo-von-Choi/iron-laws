"""
오철칙 Scanner & Audit Engine
작성자: 최진호
작성일: 2026-10-04
"""

import fnmatch
import hashlib
import multiprocessing
import os
import re
import sys
from collections import Counter
from collections.abc import Generator
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from iron_laws.core.baseline import Baseline, apply_baseline, make_fingerprint
from iron_laws.core.config import (
    SPECIAL_FILE_PATTERNS,
    InputPathError,
    IronLawsConfig,
    load_config,
)
from iron_laws.core.models import (
    AuditReport,
    AuditSummary,
    BaselineStatus,
    Diagnostic,
    Severity,
    Violation,
)
from iron_laws.core.paths import is_test_path, looks_vendored_js
from iron_laws.core.suppress import FileSuppressions, parse_suppressions
from iron_laws.engine import xfile
from iron_laws.engine.ast_tools import iter_functions
from iron_laws.engine.project import ProjectContext, matches_gitignore
from iron_laws.engine.source import SourceFile
from iron_laws.rules.base import BaseRule
from iron_laws.rules.catalog import ALL_RULES, get_active_rules

SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}

NOT_SCANNED_GRADE = "점검 없음"
INCOMPLETE_GRADE = "불완전"
PARALLEL_MIN_FILES = 300
MAX_WORKERS = 8
BINARY_PROBE_BYTES = 8000
SUPPRESS_MARKER = "iron-laws:"


def tool_version() -> str:
    try:
        return version("iron-laws")
    except PackageNotFoundError:  # iron-laws: ignore[IL-301] 설치 메타데이터가 없는 소스 실행에서는 버전을 알 수 없다고 표기한다
        return "0.0.0"


def _check_file(src: SourceFile, rules: list[BaseRule]) -> tuple[list[Violation], list[Diagnostic]]:
    """한 파일에 파일 단위 규칙을 적용한다. 규칙 하나가 실패해도 나머지는 계속하고, 실패는 진단으로 남긴다."""
    violations: list[Violation] = []
    diagnostics: list[Diagnostic] = []
    path = src.path.as_posix()
    for rule in rules:
        if src.is_test and not rule.include_tests:
            continue
        if not rule.applies_to(src):
            continue
        try:
            violations.extend(rule.check(src))
        except Exception as e:  # 규칙 오류가 점검 전체를 막지 않게 하되, 점검이 불완전했음을 보고서에 남긴다
            diagnostics.append(
                Diagnostic(
                    kind="rule_error",
                    severity="error",
                    file_path=path,
                    message=f"{rule.rule_id} 규칙 실행 중 오류로 이 파일의 해당 점검이 이루어지지 않았습니다: {type(e).__name__}: {e}",
                )
            )
    try:
        has_error = src.root is not None and src.root.has_error
    except Exception as e:  # 파서 오류도 점검 불완전으로 기록한다
        has_error = False
        diagnostics.append(Diagnostic(kind="parse", severity="error", file_path=path, message=f"구문 분석 실패: {type(e).__name__}: {e}"))
    if has_error:
        diagnostics.append(
            Diagnostic(kind="parse", severity="warning", file_path=path, message="구문 오류가 있어 이 파일의 분석이 부정확할 수 있습니다")
        )
    return violations, diagnostics


def _scan_chunk(config_data: dict, items: list[tuple[str, str, bool]]) -> tuple[list[Violation], list[Diagnostic]]:
    """작업 프로세스에서 파일 단위 규칙을 실행한다."""
    config = IronLawsConfig(**config_data)
    rules = get_active_rules(
        enabled=config.enabled_rules, disabled=config.disabled_rules, config=config
    )
    violations: list[Violation] = []
    diagnostics: list[Diagnostic] = []
    for rel, content, in_test in items:
        src = SourceFile(Path(rel), content, is_test=in_test)
        found, diags = _check_file(src, rules)
        violations.extend(found)
        diagnostics.extend(diags)
        src.release()
    return violations, diagnostics


def looks_minified(content: str) -> bool:
    """줄이 극단적으로 길어 사람이 쓰지 않은 압축·생성 파일로 보이는지 판정한다."""
    if len(content) < 20_000:
        return False
    lines = content.splitlines() or [content]
    longest = max(len(line) for line in lines)
    return longest > 4_000 or len(content) / len(lines) > 400


def _decode(raw: bytes) -> tuple[str, str | None]:
    """바이트를 문자열로 바꾼다. UTF-8이 아니면 CP949를 시도하고, 어느 쪽도 아니면 깨진 글자를 대체하며 사유를 돌려준다."""
    try:
        return raw.decode("utf-8-sig"), None
    except UnicodeDecodeError:
        pass
    try:
        return raw.decode("cp949"), "UTF-8이 아니어서 CP949로 해석했습니다"
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace"), "인코딩을 알 수 없어 일부 글자를 대체해 읽었습니다"


class AuditScanner:
    def __init__(
        self,
        root_path: Path,
        config: IronLawsConfig | None = None,
        config_path: Path | None = None,
        search_parents: bool = False,
        baseline: Baseline | None = None,
        changed_files: set[str] | None = None,
        changed_since: str | None = None,
        respect_gitignore: bool = False,
    ):
        if not root_path.exists():
            raise InputPathError(f"점검 대상 경로가 없습니다: {root_path}")
        self.root_path = root_path.resolve()
        if config is not None:
            self.config, self.config_source = config, "코드에서 전달"
        else:
            self.config, self.config_source = load_config(self.root_path, config_path, search_parents)
        if respect_gitignore:
            self.config.respect_gitignore = True
        self.fail_on_source = "설정 파일" if self.config_source not in ("기본값", "코드에서 전달") else "기본값"
        self.baseline = baseline
        self.changed_files = changed_files
        self.changed_since = changed_since
        self._skipped: list[dict[str, str]] = []
        self._diagnostics: list[Diagnostic] = []
        self._gitignore_patterns: list[str] = self._load_gitignore() if self.config.respect_gitignore else []
        self._all_paths: set[str] = set()
        self._excluded_files: Counter[str] = Counter()
        self._excluded_dirs: Counter[str] = Counter()
        self._unscanned_ext: Counter[str] = Counter()
        self._cross_file: dict[str, int] = {"resolved_calls": 0, "limit_hits": 0}
        self.rules = get_active_rules(
            enabled=self.config.enabled_rules,
            disabled=self.config.disabled_rules,
            config=self.config,
        )

    # -- 경로 --
    def _repo_relative_prefix(self) -> str:
        """점검 루트가 저장소(.git이 있는 가장 가까운 상위 폴더) 안에서 차지하는 상대 경로. 저장소 밖이면 빈 문자열"""
        base = self.root_path if self.root_path.is_dir() else self.root_path.parent
        for candidate in (base, *base.parents):
            if (candidate / ".git").exists():
                rel = base.relative_to(candidate).as_posix()
                return "" if rel == "." else rel
        return ""

    def _relative(self, path: Path) -> Path:
        if self.root_path.is_file():
            return Path(path.name)
        return path.relative_to(self.root_path)

    def _matching_exclude(self, path: Path) -> str | None:
        rel = self._relative(path)
        rel_posix = rel.as_posix()
        if self.config.respect_gitignore and matches_gitignore(self._gitignore_patterns, rel_posix):
            return "(.gitignore)"
        for ex in self.config.excludes:
            if ex in rel.parts:
                return ex
            if fnmatch.fnmatch(rel_posix, ex) or fnmatch.fnmatch(rel.name, ex):
                return ex
        return None

    def _should_exclude(self, path: Path) -> bool:
        return self._matching_exclude(path) is not None

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

            kept = []
            for d in dirnames:
                pattern = self._matching_exclude(current_dir / d)
                if pattern is None:
                    kept.append(d)
                else:
                    self._excluded_dirs[pattern] += 1
            dirnames[:] = kept

            for fname in filenames:
                fpath = current_dir / fname
                self._all_paths.add(self._relative(fpath).as_posix())
                pattern = self._matching_exclude(fpath)
                if pattern is not None:
                    self._excluded_files[pattern] += 1
                    continue
                if self._is_included(fpath):
                    yield fpath
                else:
                    self._unscanned_ext[fpath.suffix.lower() or "(확장자 없음)"] += 1

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

    def _apply_suppressions(
        self, violations: list[Violation], sources: list[SourceFile]
    ) -> tuple[list[Violation], int]:
        known = {rule_cls.rule_id for rule_cls in ALL_RULES}
        table: dict[str, FileSuppressions] = {}
        for src in sources:
            path = src.path.as_posix()
            if SUPPRESS_MARKER not in src.text:
                continue  # 억제 주석이 있을 수 없는 파일은 구문 분석을 다시 하지 않는다
            sup = parse_suppressions(src)
            table[path] = sup
            for line, problem in sup.problems:
                self._diagnostics.append(Diagnostic(kind="suppression", severity="warning", file_path=path, line=line, message=problem))
            for d in sup.directives:
                for unknown in sorted(d.ids - known):
                    self._diagnostics.append(
                        Diagnostic(kind="suppression", severity="warning", file_path=path, line=d.line, message=f"억제 주석의 규칙 ID가 등록되어 있지 않습니다: {unknown}")
                    )
                if d.expired:
                    self._diagnostics.append(
                        Diagnostic(kind="suppression", severity="warning", file_path=path, line=d.line, message=f"억제가 만료되어 적용되지 않습니다 (until={d.expires}): {', '.join(sorted(d.ids))}")
                    )
            src.release()
        kept = []
        suppressed = 0
        for v in violations:
            rules = table.get(v.file_path.as_posix())
            if rules is not None and rules.covers(v):
                suppressed += 1
            else:
                kept.append(v)
        for path, sup in table.items():
            for d in sup.directives:
                unused = sorted((d.ids & known) - d.used) if not d.expired else []
                if unused:
                    self._diagnostics.append(
                        Diagnostic(kind="suppression", severity="info", file_path=path, line=d.line, message=f"사용되지 않은 억제입니다. 더 이상 필요 없으면 지우십시오: {', '.join(unused)}")
                    )
        return kept, suppressed

    # -- 읽기 --
    def _read_sources(self) -> list[SourceFile]:
        sources: list[SourceFile] = []
        max_bytes = self.config.limits.max_file_bytes
        for file_path in self.discover_files():
            rel_path = self._relative(file_path)
            rel = rel_path.as_posix()
            try:
                if file_path.stat().st_size > max_bytes:
                    self._skipped.append({"path": rel, "reason": "파일 크기 한도 초과"})
                    continue
                raw = file_path.read_bytes()
            except OSError as e:
                self._skipped.append({"path": rel, "reason": f"읽기 실패: {e.strerror or e}"})
                self._diagnostics.append(Diagnostic(kind="read", severity="error", file_path=rel, message=f"파일을 읽지 못해 점검하지 못했습니다: {e.strerror or e}"))
                continue
            if b"\0" in raw[:BINARY_PROBE_BYTES]:
                self._skipped.append({"path": rel, "reason": "이진 파일로 판단"})
                continue
            content, note = _decode(raw)
            if note:
                self._diagnostics.append(Diagnostic(kind="encoding", severity="warning", file_path=rel, message=note))
            if looks_vendored_js(rel_path, content):
                self._skipped.append({"path": rel, "reason": "제3자 라이브러리 사본으로 판단"})
                continue
            if looks_minified(content):
                self._skipped.append({"path": rel, "reason": "압축·생성된 파일로 판단"})
                continue
            sources.append(SourceFile(rel_path, content, is_test=is_test_path(rel_path)))
        sources.sort(key=lambda f: f.path.as_posix())
        return sources

    # -- 규칙 실행 --
    def _run_file_rules_serial(self, sources: list[SourceFile]) -> list[Violation]:
        violations: list[Violation] = []
        for src in sources:
            found, diags = _check_file(src, self.rules)
            violations.extend(found)
            self._diagnostics.extend(diags)
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
                results = list(pool.map(_scan_chunk, [config_data] * len(chunks), chunks))
        except BrokenProcessPool:
            self._skipped.append({"path": "(병렬 처리)", "reason": "작업 프로세스 오류로 순차 처리로 전환"})
            self._diagnostics.append(
                Diagnostic(kind="worker", severity="warning", message="병렬 처리 중 작업 프로세스가 중단되어 순차 처리로 처음부터 다시 점검했습니다. 결과는 완전합니다.")
            )
            return self._run_file_rules_serial(sources)
        violations: list[Violation] = []
        for found, diags in results:
            violations.extend(found)
            self._diagnostics.extend(diags)
        return violations

    def _run_rules(self, sources: list[SourceFile]) -> list[Violation]:
        xfile.set_index(xfile.ProjectIndex.build(sources, self.config.limits.max_cross_file_lookups))
        try:
            violations = self._run_file_rules(sources)
        finally:
            index = xfile.get_index()
            self._cross_file = {
                "resolved_calls": index.resolved if index else 0,
                "limit_hits": index.limit_hits if index else 0,
            }
            xfile.set_index(None)
        if self._cross_file["limit_hits"]:
            self._diagnostics.append(
                Diagnostic(
                    kind="analysis_limit",
                    severity="info",
                    message=f"파일 간·함수 간 분석 한도를 넘어 {self._cross_file['limit_hits']}건은 해석하지 않았습니다. 해당 흐름은 미확인 상태입니다 (limits.max_cross_file_lookups로 조정).",
                )
            )

        project = ProjectContext(
            root=self.root_path,
            files=sources,
            config=self.config,
            all_paths=self._all_paths,
            gitignore_patterns=self._load_gitignore(),
        )
        for rule in self.rules:
            try:
                violations.extend(rule.check_project(project))
            except Exception as e:  # 프로젝트 규칙 오류도 점검 불완전으로 기록한다
                self._diagnostics.append(
                    Diagnostic(kind="rule_error", severity="error", message=f"{rule.rule_id} 프로젝트 단위 점검 중 오류: {type(e).__name__}: {e}")
                )
        for src in sources:
            src.release()
        return violations

    # -- 지문 --
    @staticmethod
    def _fingerprint(violations: list[Violation], sources: list[SourceFile]) -> None:
        """위치(줄 번호)가 아니라 규칙·파일·함수·코드 모양으로 지적을 식별한다. 줄이 밀려도 같은 지적으로 인식된다."""
        by_path = {s.path.as_posix(): s for s in sources}
        occurrences: Counter[tuple[str, str, str, str]] = Counter()
        function_cache: dict[str, list] = {}
        for v in sorted(violations, key=lambda x: (x.file_path.as_posix(), x.line_number, x.rule_id)):
            path = v.file_path.as_posix()
            src = by_path.get(path)
            scope = ""
            if src is not None and src.lang is not None:
                if path not in function_cache:
                    function_cache[path] = [(f.start_line, f.end_line, f.name) for f in iter_functions(src)]
                spans = [(e - s, name) for s, e, name in function_cache[path] if s <= v.line_number <= e]
                scope = min(spans)[1] if spans else ""
            shape = re.sub(r"\s+", " ", v.snippet).strip()
            key = (v.rule_id, path, scope, shape)
            occurrences[key] += 1
            v.scope_name = scope
            v.fingerprint = make_fingerprint(v.rule_id, v.rule_version, path, scope, shape, occurrences[key])
        for src in sources:
            src.release()

    # -- 보고 --
    @staticmethod
    def _grade(crit: int, high: int, med: int, low: int) -> str:
        if crit > 0:
            return "F"
        if high > 0:
            return "D"
        if med > 0:
            return "B"
        if low > 0:
            return "A-"
        return "A+"

    def _ruleset_info(self) -> dict:
        entries = sorted(f"{r.rule_id}:{r.version}" for r in self.rules)
        return {
            "count": len(entries),
            "hash": hashlib.sha256("\n".join(entries).encode()).hexdigest()[:16],
            "rules": [{"id": r.rule_id, "version": r.version} for r in sorted(self.rules, key=lambda r: r.rule_id)],
        }

    def scan(self) -> AuditReport:
        self._skipped = []
        self._diagnostics = []
        self._all_paths = set()
        self._excluded_files = Counter()
        self._excluded_dirs = Counter()
        self._unscanned_ext = Counter()
        sources = self._read_sources()
        files_by_language = Counter((s.lang.value if s.lang else s.kind) for s in sources)
        violations = self._run_rules(sources)
        violations = self._dedupe(violations)
        violations, suppressed = self._apply_suppressions(violations, sources)
        self._fingerprint(violations, sources)

        scope_note: dict | None = None
        if self.changed_files is not None:
            violations = [v for v in violations if v.file_path.as_posix() in self.changed_files]
            scope_note = {
                "mode": "changed-since",
                "ref": self.changed_since,
                "changed_files": len(self.changed_files),
                "note": "변경된 파일의 지적만 표시했습니다. 프로젝트 전체 규칙과 파일 간 영향은 전체 점검으로 정기적으로 대조하십시오.",
            }
        violations.sort(key=lambda v: (str(v.file_path), v.line_number, v.rule_id))
        files_scanned = len(sources)

        summary = AuditSummary(total_files_scanned=files_scanned, suppressed_count=suppressed)
        summary.total_violations = len(violations)
        summary.critical_count = sum(1 for v in violations if v.severity == Severity.CRITICAL)
        summary.high_count = sum(1 for v in violations if v.severity == Severity.HIGH)
        summary.medium_count = sum(1 for v in violations if v.severity == Severity.MEDIUM)
        summary.low_count = sum(1 for v in violations if v.severity == Severity.LOW)
        summary.grade = self._grade(summary.critical_count, summary.high_count, summary.medium_count, summary.low_count)

        if self.baseline is not None:
            self._diagnostics.extend(
                apply_baseline(violations, self.baseline, summary, {r.rule_id: r.version for r in self.rules})
            )

        threshold = SEVERITY_ORDER[self.config.fail_on]
        counted = [
            v
            for v in violations
            if self.baseline is None or v.baseline_status in (BaselineStatus.NEW, BaselineStatus.REVIEW)
        ]
        summary.is_passed = not any(SEVERITY_ORDER[v.severity] >= threshold for v in counted)

        if files_scanned == 0:
            summary.scan_status = "empty"
            summary.grade = NOT_SCANNED_GRADE  # 점검한 파일이 없으면 통과가 아니라 '점검 없음'이다
            summary.is_passed = False
        elif any(d.severity == "error" for d in self._diagnostics):
            summary.scan_status = "incomplete"
            summary.grade = INCOMPLETE_GRADE  # 일부를 점검하지 못했으면 등급과 통과를 확정하지 않는다
            summary.is_passed = False

        now_utc = datetime.now(UTC)
        doc_id = f"AUDIT-{now_utc.strftime('%Y%m%d-%H%M%S')}"
        metadata = {
            "config": self.config.model_dump(mode="json"),
            "config_source": self.config_source,
            "config_hash": hashlib.sha256(self.config.model_dump_json().encode()).hexdigest()[:16],
            "fail_on_source": self.fail_on_source,
            "tool_version": tool_version(),
            "ruleset": self._ruleset_info(),
            "files_by_language": dict(sorted(files_by_language.items())),
            "skipped_files": self._skipped,
            "excluded_summary": {
                "files": dict(self._excluded_files.most_common()),
                "directories": dict(self._excluded_dirs.most_common()),
            },
            "unscanned_by_extension": dict(self._unscanned_ext.most_common(20)),
            "cross_file": self._cross_file,
            "repo_relative_prefix": self._repo_relative_prefix(),
        }
        if scope_note:
            metadata["scope"] = scope_note
        if self.baseline is not None:
            metadata["baseline"] = {"entries": len(self.baseline.entries), "tool_version": self.baseline.tool_version}

        return AuditReport(
            document_id=doc_id,
            audit_date=now_utc.strftime("%Y-%m-%d"),
            target_path=str(self.root_path),
            summary=summary,
            violations=violations,
            diagnostics=self._diagnostics,
            metadata=metadata,
        )
