"""
오철칙 승인 의존성 지문: 사람의 검토 승인이 '무엇을 전제로 했는가'를 코드의 구조에서 뽑아 기록한다
승인은 지적 하나가 아니라 그 지적이 성립하는 흐름(입력 유입 → 전파 → 싱크)과 그 주변(호출자·정제 함수·접근 범위)에 대한 판단이다.
이 전제가 바뀌면 관련 승인만 다시 검토한다. 판단은 구문 구조와 호출 요약을 쓰는 보수적 방식이며 의미 동등성을 주장하지 않는다.
작성자: 최진호
작성일: 2026-10-04
"""

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field

from tree_sitter import Node

from iron_laws.core.models import Violation
from iron_laws.engine.ast_tools import (
    CALL_TYPES,
    STRING_TYPES,
    Func,
    iter_calls,
    iter_functions,
    walk,
)
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import SANITIZER_FN_RE, resolve_any

MIN_LITERAL_LENGTH = 3
MAX_CALLEE_DEPTH = 3
MAX_CALLEES = 40


def tokens_digest(src: SourceFile, node: Node) -> str:
    """주석과 공백을 뺀 토큰 열의 해시. 줄 이동·들여쓰기·주석 변경에는 같고, 코드가 바뀌면 달라진다.
    데코레이터는 함수가 외부에 노출되는 방식(라우트 등)을 정하므로 함께 해시한다."""
    if node.parent is not None and node.parent.type == "decorated_definition":
        node = node.parent
    docstrings = _docstring_ranges(src)
    h = hashlib.sha256()
    for n in walk(node):
        if n.child_count == 0 and "comment" not in n.type and not _inside(n, docstrings):
            h.update(src.text_of(n).encode("utf-8", errors="replace"))
            h.update(b"\x1f")
    return h.hexdigest()[:16]


def _docstring_ranges(src: SourceFile) -> list[tuple[int, int]]:
    """값으로 쓰이지 않는 단독 문자열 문장(독스트링)의 범위. 설명 문구가 바뀌어도 동작은 같으므로 지문에서 뺀다."""
    return src.memo("docstring_ranges", lambda: [(n.start_byte, n.end_byte) for n in src._bare_string_statements()])


def _inside(node: Node, ranges: list[tuple[int, int]]) -> bool:
    return any(a <= node.start_byte and node.end_byte <= b for a, b in ranges)


def _function_at(src: SourceFile, line: int) -> Func | None:
    spans = [f for f in iter_functions(src) if f.start_line <= line <= f.end_line]
    return min(spans, key=lambda f: f.length) if spans else None


def _literals(src: SourceFile, fn: Func) -> list[str]:
    values: set[str] = set()
    docstrings = _docstring_ranges(src)
    for n in walk(fn.node):
        if n.type in STRING_TYPES and "interpol" not in n.type and not _inside(n, docstrings):
            text = src.text_of(n)
            if len(text) >= MIN_LITERAL_LENGTH + 2:
                values.add(text)
    return sorted(values)


def build_callers_index(sources: list[SourceFile]) -> dict[tuple[str, str], set[str]]:
    """(경로, 함수 이름) → 그 함수를 부르는 호출자 식별자('경로::함수'). xfile 색인이 설정된 상태에서 호출한다."""
    index: dict[tuple[str, str], set[str]] = defaultdict(set)
    for src in sources:
        if src.lang is None:
            continue
        call_types = CALL_TYPES.get(src.lang, set())
        if not call_types:
            continue
        spans = [(f.start_line, f.end_line, f.name) for f in iter_functions(src)]
        for call in iter_calls(src):
            targets = resolve_any(src, call.callee, len(call.args))
            if not targets:
                continue
            inside = [(e - s, name) for s, e, name in spans if s <= call.line <= e]
            caller = f"{src.path.as_posix()}::{min(inside)[1] if inside else '<module>'}"
            for hsrc, fn in targets:
                index[(hsrc.path.as_posix(), fn.name)].add(caller)
    return index


DYNAMIC_CALLEES = frozenset({"getattr", "__import__", "importlib.import_module", "import_module", "eval", "exec", "globals", "locals", "vars"})


def dynamic_boundaries(src: SourceFile, fn: Func) -> list[str]:
    """함수 안에서 호출 대상을 정적으로 알 수 없는 호출(getattr·eval·호출 결과나 첨자를 다시 호출 등). 영향 범위를 좁힐 수 없는 경계다."""
    found: list[str] = []
    for call in iter_calls(src):
        if not (fn.node.start_byte <= call.node.start_byte and call.node.end_byte <= fn.node.end_byte):
            continue
        function = call.node.child_by_field_name("function")
        shape = function.type if function is not None else ""
        if call.callee in DYNAMIC_CALLEES or shape in ("call", "subscript", "parenthesized_expression", "lambda"):
            found.append(f"{fn.name}:{call.callee or shape}")
    return sorted(set(found))


def dependency_snapshot(by_path: dict[str, SourceFile], violation: Violation, callers: dict[tuple[str, str], set[str]]) -> dict | None:
    """지적 하나의 승인 전제를 담은 지문. 함수를 찾지 못하는 지적(설정 파일 등)은 None"""
    src = by_path.get(violation.file_path.as_posix())
    if src is None or src.root is None:
        return None
    sink = _function_at(src, violation.line_number)
    if sink is None:
        return None
    functions: dict[tuple[str, str], tuple[SourceFile, Func]] = {(src.path.as_posix(), sink.name): (src, sink)}
    for step in violation.evidence:
        step_src = by_path.get(step.file_path)
        if step_src is None or step_src.root is None:
            continue
        fn = _function_at(step_src, step.line)
        if fn is not None:
            functions.setdefault((step_src.path.as_posix(), fn.name), (step_src, fn))
    chain = [
        {"path": path, "name": name, "digest": tokens_digest(fsrc, fn.node)}
        for (path, name), (fsrc, fn) in sorted(functions.items())
    ]
    # 정제·검증 함수: 이름으로 알아본 호출과, 프로젝트에 정의된 경우 그 본문의 지문(의미가 바뀌면 달라진다)
    sanitizers: list[dict] = []
    seen: set[str] = set()
    for (_path, _name), (fsrc, fn) in sorted(functions.items()):
        for call in iter_calls(fsrc):
            if not (fn.node.start_byte <= call.node.start_byte and call.node.end_byte <= fn.node.end_byte):
                continue
            if not SANITIZER_FN_RE.search(call.callee) and not re.search(r"(?i)(?:^|\.)(?:is_?relative_to|startswith|basename|abspath|realpath|resolve)$", call.callee):
                continue
            if call.callee in seen:
                continue
            seen.add(call.callee)
            targets = resolve_any(fsrc, call.callee, len(call.args))
            digest = tokens_digest(targets[0][0], targets[0][1].node) if targets else None
            sanitizers.append({"name": call.callee, "digest": digest})
    # 흐름의 함수가 부르는 프로젝트 함수(정제·변환·검증 도우미 포함)와 그 본문 지문. 본문이 바뀌면 승인 전제가 바뀐 것이다.
    callees: dict[tuple[str, str], str] = {}
    frontier = list(functions.values())
    for _depth in range(MAX_CALLEE_DEPTH):
        next_frontier: list[tuple[SourceFile, Func]] = []
        for fsrc, fn in frontier:
            for call in iter_calls(fsrc):
                if not (fn.node.start_byte <= call.node.start_byte and call.node.end_byte <= fn.node.end_byte):
                    continue
                for tsrc, tfn in resolve_any(fsrc, call.callee, len(call.args)):
                    key = (tsrc.path.as_posix(), tfn.name)
                    if key in functions or key in callees or len(callees) >= MAX_CALLEES:
                        continue
                    callees[key] = tokens_digest(tsrc, tfn.node)
                    next_frontier.append((tsrc, tfn))
        frontier = next_frontier
        if not frontier:
            break
    caller_ids: set[str] = set()
    for path, name in functions:
        caller_ids |= callers.get((path, name), set())
    literals = hashlib.sha256("\x1f".join(_literals(src, sink)).encode()).hexdigest()[:16]
    boundaries: list[str] = []
    for (_path, _name), (fsrc, fn) in sorted(functions.items()):
        boundaries.extend(f"{_path}::{d}" for d in dynamic_boundaries(fsrc, fn))
    return {
        "sink_function": {"path": src.path.as_posix(), "name": sink.name},
        "chain": chain,
        "callers": sorted(caller_ids),
        "sanitizers": sorted(sanitizers, key=lambda s: s["name"]),
        "callees": [{"path": p, "name": n, "digest": d} for (p, n), d in sorted(callees.items())],
        "literals": literals,
        "dynamic_boundaries": sorted(set(boundaries)),
    }


@dataclass
class Premise:
    """승인이 전제한 것 하나와 현재 상태. state: unchanged(전제 유지) / changed(바뀜) / unknown(확인할 수 없음)"""

    key: str
    label: str
    state: str
    reasons: list[str] = field(default_factory=list)
    detail: str = ""


def explain_dependencies(recorded: dict, current: dict | None) -> list[Premise]:
    """기록된 전제와 현재를 항목별로 비교한다. 바뀐 항목만 아니라 유지된 항목도 이유와 함께 돌려줘서 검토자가 '왜 그대로 두는지'를 볼 수 있게 한다."""
    if current is None:
        return [Premise("structure", "승인 당시의 함수 구조", "unknown", ["승인 당시의 함수 구조를 현재 코드에서 확인할 수 없다"])]
    premises: list[Premise] = []
    old_chain = {(c["path"], c["name"]): c["digest"] for c in recorded.get("chain", [])}
    new_chain = {(c["path"], c["name"]): c["digest"] for c in current.get("chain", [])}
    # 파일이 옮겨졌거나 함수가 같은 내용으로 다른 경로로 간 경우는 내용 지문이 같으면 같은 전제다
    old_digests, new_digests = sorted(old_chain.values()), sorted(new_chain.values())
    if old_digests != new_digests:
        changed = [f"{k[1]}()" for k, v in new_chain.items() if v not in old_digests]
        premises.append(Premise("chain", "입력 유입·전파·싱크 흐름의 함수", "changed", ["입력 유입·전파·싱크 흐름의 함수가 바뀌었다: " + (", ".join(changed[:4]) or "구성이 달라졌다")]))
    else:
        premises.append(Premise("chain", "입력 유입·전파·싱크 흐름의 함수", "unchanged", detail=f"흐름의 함수 {len(new_chain)}개의 본문 지문이 승인 당시와 같다"))

    # 같은 이름의 함수라도 다른 파일의 것은 다른 대상이다. 경로와 이름을 함께 비교한다.
    old_callees = {f'{c.get("path", "")}::{c["name"]}': c["digest"] for c in recorded.get("callees", [])}
    new_callees = {f'{c.get("path", "")}::{c["name"]}': c["digest"] for c in current.get("callees", [])}
    callee_reasons: list[str] = []
    for key, digest in new_callees.items():
        if key in old_callees and old_callees[key] != digest:
            callee_reasons.append(f"흐름이 호출하는 함수 {key.rpartition('::')[2]}()({key.rpartition('::')[0]})의 본문이 바뀌었다")
    if set(new_callees) - set(old_callees):
        callee_reasons.append("흐름이 새로 호출하는 함수가 생겼다: " + ", ".join(sorted(set(new_callees) - set(old_callees))[:4]))
    if set(old_callees) - set(new_callees):
        callee_reasons.append("승인 당시 호출하던 함수를 더 이상 호출하지 않는다: " + ", ".join(sorted(set(old_callees) - set(new_callees))[:4]))
    premises.append(
        Premise("callees", "흐름이 호출하는 함수(본문)", "changed" if callee_reasons else "unchanged", callee_reasons, detail=f"호출하는 함수 {len(new_callees)}개의 본문 지문이 같다" if not callee_reasons else "")
    )

    old_callers, new_callers = set(recorded.get("callers", [])), set(current.get("callers", []))
    added = sorted(new_callers - old_callers)
    premises.append(
        Premise("callers", "호출자", "changed" if added else "unchanged", ["새 호출자가 생겼다: " + ", ".join(added[:4])] if added else [], detail=f"호출자 {len(new_callers)}개(경로·이름)가 승인 당시 목록 안에 있다" if not added else "")
    )

    old_sanitizers = {s["name"]: s["digest"] for s in recorded.get("sanitizers", [])}
    new_sanitizers = {s["name"]: s["digest"] for s in current.get("sanitizers", [])}
    sanitizer_reasons: list[str] = []
    if set(old_sanitizers) - set(new_sanitizers):
        sanitizer_reasons.append("승인 당시 있던 정제·검증 호출이 없어졌다: " + ", ".join(sorted(set(old_sanitizers) - set(new_sanitizers))[:4]))
    for name, digest in new_sanitizers.items():
        if name in old_sanitizers and old_sanitizers[name] != digest:
            sanitizer_reasons.append(f"정제·검증 함수 {name}의 본문(의미)이 바뀌었다")
    premises.append(
        Premise("sanitizers", "정제·검증 호출", "changed" if sanitizer_reasons else "unchanged", sanitizer_reasons, detail=f"정제·검증 호출 {len(new_sanitizers)}개가 그대로다" if not sanitizer_reasons else "")
    )

    literals_changed = recorded.get("literals") != current.get("literals")
    premises.append(
        Premise("literals", "접근 범위·질의 틀(문자열 상수)", "changed" if literals_changed else "unchanged", ["싱크 함수의 문자열 상수(접근 범위·질의 틀)가 바뀌었다"] if literals_changed else [], detail="" if literals_changed else "싱크 함수의 문자열 상수 지문이 같다(독스트링 제외)")
    )

    old_boundaries, new_boundaries = set(recorded.get("dynamic_boundaries", [])), set(current.get("dynamic_boundaries", []))
    if new_boundaries - old_boundaries:
        premises.append(Premise("boundaries", "동적 호출 경계", "changed", ["호출 대상을 정적으로 알 수 없는 호출이 새로 생겼다: " + ", ".join(sorted(new_boundaries - old_boundaries)[:4])]))
    elif new_boundaries:
        premises.append(Premise("boundaries", "동적 호출 경계", "unknown", detail="흐름 안에 호출 대상을 정적으로 알 수 없는 호출이 있다(영향 범위를 좁힐 수 없다): " + ", ".join(sorted(new_boundaries)[:4])))
    else:
        premises.append(Premise("boundaries", "동적 호출 경계", "unchanged", detail="흐름 안에 호출 대상을 알 수 없는 동적 호출이 없다"))
    return premises


def compare_dependencies(recorded: dict, current: dict | None) -> list[str]:
    """기록된 전제와 현재를 비교해, 승인을 유지할 수 없는 이유를 돌려준다. 비어 있으면 전제가 같다."""
    return [reason for premise in explain_dependencies(recorded, current) if premise.state == "changed" or (premise.state == "unknown" and premise.key == "structure") for reason in premise.reasons]
