"""
검사 범위의 분모: 오철칙 밖에서 얻은 파일 목록(git 추적 파일, tsc·go가 컴파일하는 파일, 사용자가 준 목록)과 실제로 분석한 파일을 대조한다

- 목록의 파일마다 상태를 하나 붙인다: analyzed(분석함), skipped(읽었으나 건너뜀, 사유 포함), excluded(제외 설정, 패턴 포함),
  unsupported(점검하지 않는 확장자), outside_root(점검 폴더 밖), missing(목록에는 있으나 파일이 없음), unexplained(사유 없이 빠짐).
- unexplained는 오철칙이 이유를 대지 못한 누락이다. 0이 아니면 경고하고, 점검 옵션으로 요구하면 점검을 끝내지 못한 것으로 본다.
- 목록을 만드는 도구가 없거나 실패하면 대조하지 않았다고 밝히고, 대조한 것처럼 보이지 않게 한다.
작성자: 최진호
작성일: 2026-10-26
"""

import os
import shutil
import subprocess
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from iron_laws.core.config import ConfigError

SOURCES = ("auto", "git", "tsc", "go")
MAX_LISTED_PATHS = 200
COMMAND_TIMEOUT = 300


@dataclass
class FileCoverage:
    source: str
    listed: int = 0
    counts: dict[str, int] = field(default_factory=dict)
    unexplained: list[str] = field(default_factory=list)
    examples: dict[str, list[str]] = field(default_factory=dict)
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "listed": self.listed,
            "counts": dict(sorted(self.counts.items())),
            "unexplained": self.unexplained[:MAX_LISTED_PATHS],
            "examples": {k: v[:5] for k, v in sorted(self.examples.items())},
            "note": self.note,
        }


def _run(command: list[str], cwd: Path) -> str:
    try:
        done = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as e:
        raise ConfigError(f"파일 목록 명령을 실행하지 못했습니다({command[0]}): {e}") from e
    if done.returncode != 0:
        raise ConfigError(f"파일 목록 명령이 실패했습니다({' '.join(command[:3])}): {done.stderr.strip()[:200]}")
    return done.stdout


def _tool(name: str, root: Path) -> str:
    local = root / "node_modules" / ".bin" / name
    found = str(local) if local.is_file() else shutil.which(name)
    if found is None:
        raise ConfigError(f"{name}을(를) 찾지 못해 파일 목록을 만들 수 없습니다")
    return found


def listed_files(root: Path, source: str) -> tuple[str, list[str]]:
    """(실제로 쓴 목록 종류, 점검 폴더 기준 상대 경로 또는 절대 경로 목록). source가 file:<경로>면 그 파일의 줄 목록을 쓴다."""
    if source == "auto":
        if shutil.which("git") and subprocess.run(["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"], capture_output=True).returncode == 0:
            source = "git"
        else:
            raise ConfigError("auto: git 저장소가 아니어서 파일 목록을 정하지 못했습니다. --build-manifest로 tsc·go·file:<목록>을 주십시오")
    if source == "git":
        return "git", [p for p in _run([_tool("git", root), "-C", str(root), "ls-files", "-z", "--cached"], root).split("\0") if p]
    if source == "tsc":
        out = _run([_tool("tsc", root), "--listFilesOnly", "-p", str(root)], root)
        return "tsc", [line.strip() for line in out.splitlines() if line.strip()]
    if source == "go":
        template = "{{$d := .Dir}}{{range .GoFiles}}{{$d}}/{{.}}\n{{end}}{{range .CgoFiles}}{{$d}}/{{.}}\n{{end}}{{range .TestGoFiles}}{{$d}}/{{.}}\n{{end}}"
        return "go", [line.strip() for line in _run([_tool("go", root), "list", "-f", template, "./..."], root).splitlines() if line.strip()]
    if source.startswith("file:"):
        path = Path(source[5:])
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as e:
            raise ConfigError(f"파일 목록을 읽지 못했습니다: {e}") from e
        return f"file:{path.name}", [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    raise ConfigError(f"알 수 없는 파일 목록 종류: {source} (auto·git·tsc·go·file:<목록>)")


def _exclude_pattern(root: Path, rel: Path, match_exclude: Callable[[Path], str | None]) -> str | None:
    """파일이나 그 상위 폴더 가운데 처음으로 제외 설정에 걸린 패턴. 점검은 제외 폴더 안으로 내려가지 않으므로 상위 폴더도 본다."""
    for depth in range(1, len(rel.parts) + 1):
        pattern = match_exclude(root.joinpath(*rel.parts[:depth]))
        if pattern is not None:
            return pattern
    return None


def classify(
    root: Path,
    source: str,
    paths: list[str],
    analyzed: set[str],
    skipped: dict[str, str],
    match_exclude: Callable[[Path], str | None],
    included: Callable[[Path], bool],
) -> FileCoverage:
    """목록의 파일마다 분석 상태를 붙인다. 경로는 점검 폴더 기준 POSIX 상대 경로로 바꿔 비교한다."""
    result = FileCoverage(source)
    counts: Counter[str] = Counter()
    seen: set[str] = set()
    for raw in paths:
        candidate = Path(raw)
        absolute = candidate if candidate.is_absolute() else root / candidate
        try:
            rel = Path(os.path.relpath(absolute, root))
        except ValueError:  # iron-laws: ignore[IL-301] 다른 드라이브의 경로는 상대 경로가 없으므로 점검 폴더 밖으로 센다
            rel = Path("..") / candidate.name
        key = rel.as_posix()
        if key in seen:
            continue
        seen.add(key)
        if key.startswith("../") or key == "..":
            status = "outside_root"
        elif key in analyzed:
            status = "analyzed"
        elif key in skipped:
            status = "skipped"
        elif not absolute.is_file():
            status = "missing"
        elif pattern := _exclude_pattern(root, rel, match_exclude):
            status = "excluded"
            result.examples.setdefault(f"excluded:{pattern}", []).append(key)
        elif not included(absolute):
            status = "unsupported"
        else:
            status = "unexplained"
            result.unexplained.append(key)
        counts[status] += 1
        if status not in ("excluded", "unexplained"):
            result.examples.setdefault(status if status != "skipped" else f"skipped:{skipped[key]}", []).append(key)
    result.listed = len(seen)
    result.counts = dict(counts)
    return result
