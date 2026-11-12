"""
점검 대상 파일 고르기와 읽기: 제외 규칙·.gitignore·확장자로 파일을 고르고, 크기·이진·인코딩·압축 여부를 보고 읽는다.
외부 파일 목록(build_manifest)과 분석한 파일을 대조한다. AuditScanner가 이 기능을 물려받는다.
작성자: 최진호
작성일: 2026-11-12
"""


import fnmatch
import os
from collections.abc import Generator
from pathlib import Path

from iron_laws.core.build_manifest import classify, listed_files
from iron_laws.core.config import SPECIAL_FILE_PATTERNS, ConfigError
from iron_laws.core.models import Diagnostic
from iron_laws.core.paths import is_test_path, looks_vendored_js
from iron_laws.engine.project import matches_gitignore
from iron_laws.engine.source import SourceFile

BINARY_PROBE_BYTES = 8000


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
    except UnicodeDecodeError:  # iron-laws: ignore[IL-301] UTF-8이 아니면 다음 인코딩으로 해석을 시도한다
        pass
    try:
        return raw.decode("cp949"), "UTF-8이 아니어서 CP949로 해석했습니다"
    except UnicodeDecodeError:  # iron-laws: ignore[IL-301] CP949도 아니면 다음 단계에서 해석 실패를 진단으로 남긴다
        return raw.decode("utf-8", errors="replace"), "인코딩을 알 수 없어 일부 글자를 대체해 읽었습니다"


class ScanFileReader:
    """AuditScanner의 파일 선택·읽기 부분. root_path·config·confine_root와 집계용 속성은 AuditScanner가 만든다."""

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
                    if self.confine_root is not None and fpath.is_symlink() and not fpath.resolve().is_relative_to(self.confine_root):
                        self._skipped.append({"path": self._relative(fpath).as_posix(), "reason": "허용된 폴더 밖을 가리키는 심볼릭 링크"})
                        continue
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

    def _check_file_coverage(self, sources: list[SourceFile]) -> dict | None:
        """외부 파일 목록과 분석한 파일을 대조한다. 목록이 없거나 대조하지 못하면 진단으로 밝힌다."""
        if self.build_manifest is None:
            return None
        severity = "error" if self.require_full_coverage else "warning"
        if not self.root_path.is_dir():
            self._diagnostics.append(Diagnostic(kind="coverage", severity=severity, message="파일 하나를 점검할 때는 파일 목록 대조를 하지 않습니다"))
            return None
        try:
            source, paths = listed_files(self.root_path, self.build_manifest)
        except ConfigError as e:
            self._diagnostics.append(Diagnostic(kind="coverage", severity=severity, message=f"파일 목록 대조를 하지 못했습니다: {e}"))
            return None
        coverage = classify(
            self.root_path,
            source,
            paths,
            {s.path.as_posix() for s in sources},
            {x["path"]: x["reason"] for x in self._skipped},
            self._matching_exclude,
            self._is_included,
        )
        if coverage.unexplained:
            shown = ", ".join(coverage.unexplained[:5])
            self._diagnostics.append(
                Diagnostic(kind="coverage", severity=severity, message=f"{source} 목록의 파일 {len(coverage.unexplained)}개가 사유 없이 분석되지 않았습니다: {shown}")
            )
        return coverage.as_dict()

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
