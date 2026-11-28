"""
오철칙 에이전트 훅의 세션 함수 색인: 세션을 시작할 때 프로젝트 함수의 지문(ARC-204와 같은 shingle)을 임시 폴더에 남기고,
편집할 때 그 세션에 새로 생긴 함수만 색인의 기존 함수와 대조해 "이미 있는 함수"를 알려 준다.

- 방향은 "새 함수 → 기존 함수"다. 프로젝트 전체 중복 묶음의 첫 함수에 지적을 다는 ARC-204와 달리, 새로 만든 쪽에서 기존 위치를 가리킨다.
- 색인을 만드는 데 시간 상한(INDEX_SECONDS)이 있다. 넘으면 색인 없이 지나가고, 편집 중 중복 알림을 하지 않는다.
- 프로젝트 안에는 아무것도 쓰지 않는다.
작성자: 최진호
작성일: 2026-11-28
"""

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

INDEX_SECONDS = 20.0
MAX_FUNCTIONS = 20000


@dataclass
class DuplicateHint:
    path: str
    name: str
    line: int
    other_path: str
    other_name: str
    other_line: int
    similarity: float

    def text(self) -> str:
        return (
            f"{self.path}:{self.line}의 새 함수 {self.name}이(가) {self.other_path}:{self.other_line}의 {self.other_name}와 거의 같습니다"
            f"(유사도 {self.similarity:.0%}). 새로 만들지 말고 그 함수를 쓰십시오."
        )


def build(root: Path, config) -> dict | None:
    """프로젝트 함수 지문 색인. 시간 상한을 넘거나 함수가 너무 많으면 None"""
    from iron_laws.core.scanner import AuditScanner
    from iron_laws.rules.architecture_duplicates import DuplicateHelperRule

    started = time.monotonic()
    rule = DuplicateHelperRule()
    scanner = AuditScanner(root, config=config)
    functions: list[dict] = []
    for src in scanner._read_sources():
        if src.lang is None or src.is_test:
            continue
        for fn, _tokens, shingles in rule.fingerprints(src, config.limits):
            functions.append({"path": src.path.as_posix(), "name": fn.name, "line": fn.start_line, "lang": src.lang.value, "shingles": sorted(shingles)})
        if time.monotonic() - started > INDEX_SECONDS or len(functions) > MAX_FUNCTIONS:
            logger.debug("함수 색인이 시간·개수 상한을 넘어 편집 중 중복 알림을 하지 않습니다")
            return None
    return {"root": root.as_posix(), "functions": functions}


def save(path: Path, index: dict) -> None:
    try:
        path.write_text(json.dumps(index), encoding="utf-8")
    except OSError as exc:
        logger.debug("함수 색인을 쓰지 못했습니다: %s", exc)


def load(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.debug("함수 색인이 없거나 읽지 못했습니다: %s", exc)
        return None
    return data if isinstance(data, dict) and isinstance(data.get("functions"), list) else None


def new_duplicates(index: dict, target: Path, rel: str, config) -> list[DuplicateHint]:
    """편집한 파일의 함수 가운데 색인에 없던(이번 세션에 새로 생긴) 함수가 색인의 기존 함수와 거의 같으면 알린다"""
    from iron_laws.core.paths import is_test_path
    from iron_laws.engine.source import SourceFile
    from iron_laws.rules.architecture_duplicates import DuplicateHelperRule

    try:
        src = SourceFile(Path(rel), target.read_text(encoding="utf-8", errors="replace"), is_test=is_test_path(Path(rel)))
    except OSError as exc:
        logger.debug("편집한 파일을 읽지 못했습니다: %s", exc)
        return []
    if src.lang is None or src.is_test:
        return []
    known = {(f["path"], f["name"]) for f in index["functions"]}
    threshold = config.limits.duplicate_similarity
    hints: list[DuplicateHint] = []
    for fn, _tokens, shingles in DuplicateHelperRule().fingerprints(src, config.limits):
        if (rel, fn.name) in known:
            continue
        best: tuple[float, dict] | None = None
        for other in index["functions"]:  # iron-laws: ignore[PERF-102] 바깥 반복은 이번 편집으로 새로 생긴 함수 몇 개다
            if other["lang"] != src.lang.value or not (0.5 <= len(shingles) / max(len(other["shingles"]), 1) <= 2):
                continue
            theirs = set(other["shingles"])
            sim = len(shingles & theirs) / len(shingles | theirs)
            if sim >= threshold and (best is None or sim > best[0]):
                best = (sim, other)
        if best is not None:
            sim, other = best
            hints.append(DuplicateHint(rel, fn.name, fn.start_line, other["path"], other["name"], other["line"], sim))
    return hints
