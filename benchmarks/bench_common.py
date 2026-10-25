"""
오철칙 공통 측정기: 사례 정의, 지적과 사례의 대응, 혼동 행렬 집계, 처리 시간 측정 방법

- 사례 = (사례 ID, 파일, 줄 범위 또는 진입 함수, 기대 CWE, 취약/안전, 제외 사유). 지적은 사례의 파일과 범위 안에 있을 때만 그 사례의 검출로 센다.
- 분석하지 못한 사례(점검 폴더에 없는 파일, 건너뛴 파일, 구문 분석 실패, 규칙 실행 오류)는 TN·FN이 아니라 `unanalyzed` 열로 따로 센다.
- 제외 사유가 있는 사례는 점수에 넣지 않고 `excluded` 열로 센다.
- 처리 시간은 같은 장비에서 작업 프로세스 수를 고정하고 3회 반복한 중앙값으로 잰다.
작성자: 최진호
작성일: 2026-10-11
"""

import re
import time
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from statistics import median

from iron_laws.core import scanner
from iron_laws.core.models import AuditReport
from iron_laws.core.scanner import AuditScanner

ANALYSIS_FAILURE_KINDS = {"parse", "rule_error"}


@dataclass(frozen=True)
class Case:
    case_id: str
    path: str  # 점검 폴더 기준 상대 경로(/ 구분)
    category: str
    vulnerable: bool
    rules: frozenset[str]  # 이 사례의 검출로 인정하는 규칙
    cwe: str = ""
    lines: tuple[int, int] | None = None  # 지적을 인정하는 줄 범위(양끝 포함). None이면 파일 전체
    entry: str = ""  # 진입 함수 이름의 정규식(완전 일치). lines가 없으면 맞는 함수들의 줄 범위를 쓴다
    excluded: str = ""  # 비어 있지 않으면 점수에서 뺀다


@dataclass
class Scored:
    rows: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    outcomes: dict[str, str] = field(default_factory=dict)  # 사례 ID → TP/FN/FP/TN/unanalyzed/excluded

    def table(self) -> dict[str, dict[str, float]]:
        out: dict[str, dict[str, float]] = {}
        for category, k in sorted(self.rows.items()):
            tp, fn, fp, tn = k["TP"], k["FN"], k["FP"], k["TN"]
            tpr = tp / (tp + fn) if tp + fn else 0.0
            fpr = fp / (fp + tn) if fp + tn else 0.0
            out[category] = {"TP": tp, "FN": fn, "FP": fp, "TN": tn, "TPR": round(tpr, 4), "FPR": round(fpr, 4)}
            if k["unanalyzed"]:
                out[category]["unanalyzed"] = k["unanalyzed"]
            if k["excluded"]:
                out[category]["excluded"] = k["excluded"]
        return out


def entry_ranges(text: str, ext: str, pattern: str) -> list[tuple[int, int]]:
    """이름이 정규식 pattern에 완전히 맞는 함수들의 줄 범위(구문 트리 기준)"""
    from iron_laws.engine.ast_tools import iter_functions
    from iron_laws.engine.source import SourceFile

    src = SourceFile(Path("case" + ext), text)
    matcher = re.compile(pattern)
    return [
        (fn.node.start_point[0] + 1, fn.node.end_point[0] + 1)
        for fn in iter_functions(src)
        if matcher.fullmatch(fn.name.rsplit("::", 1)[-1].rsplit(".", 1)[-1])
    ]


def entry_range(text: str, ext: str, name: str) -> tuple[int, int] | None:
    found = entry_ranges(text, ext, re.escape(name))
    return found[0] if found else None


def require_commit(root: Path, expected: str) -> None:
    """측정 대상 사본의 커밋이 기대와 다르면 종료코드 2로 끝낸다."""
    import subprocess
    import sys

    try:
        actual = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):  # iron-laws: ignore[IL-301] git 정보가 없으면 실제 커밋을 빈 값으로 두고 바로 아래에서 커밋 불일치로 알린다
        actual = ""
    if not actual.startswith(expected) or not expected:
        print(f"측정 대상 커밋이 다릅니다: 기대 {expected}, 실제 {actual or '(git 정보 없음)'}", file=sys.stderr)
        sys.exit(2)


def require_digest(archive: Path, expected: str) -> None:
    """배포 압축 파일로 받는 데이터셋(Juliet 등)은 sha256으로 고정한다. 다르면 종료코드 2"""
    import hashlib
    import sys

    digest = hashlib.sha256(archive.read_bytes()).hexdigest() if archive.is_file() else ""
    if digest != expected:
        print(f"측정 대상 파일의 sha256이 다릅니다: 기대 {expected}, 실제 {digest or '(파일 없음)'}", file=sys.stderr)
        sys.exit(2)


def _unanalyzed_paths(report: AuditReport) -> set[str]:
    paths = {item["path"] for item in report.metadata.get("skipped_files", []) if isinstance(item, dict) and "path" in item}
    paths |= {d.file_path for d in report.diagnostics if d.kind in ANALYSIS_FAILURE_KINDS and d.file_path}
    return paths


def score(cases: Iterable[Case], report: AuditReport, root: Path | None = None, confirmed_only: bool = True) -> Scored:
    """보고서의 지적을 사례에 대응시켜 범주별 혼동 행렬을 만든다."""
    by_path: dict[str, list] = defaultdict(list)
    for v in report.violations:
        if confirmed_only and v.confidence.value != "CONFIRMED":
            continue
        by_path[v.file_path.as_posix()].append(v)
    unanalyzed = _unanalyzed_paths(report)
    result = Scored()
    for case in cases:
        row = result.rows[case.category]
        if case.excluded:
            row["excluded"] += 1
            result.outcomes[case.case_id] = "excluded"
            continue
        if case.path in unanalyzed or (root is not None and not (root / case.path).is_file()):
            row["unanalyzed"] += 1
            result.outcomes[case.case_id] = "unanalyzed"
            continue
        spans = [case.lines] if case.lines is not None else None
        if spans is None and case.entry and root is not None:
            target = root / case.path
            spans = entry_ranges(target.read_text(encoding="utf-8", errors="replace"), target.suffix, case.entry)
            if not spans:
                row["unanalyzed"] += 1  # 진입 함수를 찾지 못한 사례는 판정하지 않는다
                result.outcomes[case.case_id] = "unanalyzed"
                continue
        hit = any(
            v.rule_id in case.rules and (spans is None or any(a <= v.line_number <= b for a, b in spans))
            for v in by_path.get(case.path, [])
        )
        key = ("TP" if hit else "FN") if case.vulnerable else ("FP" if hit else "TN")
        row[key] += 1
        result.outcomes[case.case_id] = key
    return result


def timed_scan(root: Path, runs: int = 3, workers: int = 1, **scanner_args) -> tuple[AuditReport, float]:
    """작업 프로세스 수를 고정해 runs번 점검하고 마지막 보고서와 처리 시간의 중앙값(초)을 돌려준다."""
    saved = scanner.MAX_WORKERS
    scanner.MAX_WORKERS = workers
    try:
        seconds = []
        report = None
        for _ in range(runs):
            started = time.perf_counter()
            report = AuditScanner(root, **scanner_args).scan()
            seconds.append(time.perf_counter() - started)
    finally:
        scanner.MAX_WORKERS = saved
    assert report is not None
    return report, round(median(seconds), 3)
