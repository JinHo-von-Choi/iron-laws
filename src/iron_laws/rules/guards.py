"""
오철칙 안전 면제 판정 도구: 검증 분기가 실제로 실행 흐름을 끊는지, 검증한 값이 싱크까지 같은 값인지 확인한다
문자열 속 `return`이나 조건부로만 실행되는 검사, 검사 뒤 재대입을 안전 근거로 인정하지 않기 위한 것이다.
작성자: 최진호
작성일: 2026-10-05
"""

import re

from tree_sitter import Node

from iron_laws.engine.ast_tools import CALL_TYPES, iter_calls, walk
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import CONDITIONAL_TYPES, definitions

TERMINATOR_TYPES = frozenset(
    {"return_statement", "raise_statement", "throw_statement", "continue_statement", "break_statement", "return_expression"}
)
EXIT_CALL_RE = re.compile(r"^(sys\.exit|exit|quit|abort|os\._exit|die|panic|process\.exit|os\.Exit|log\.Fatal\w*|Environment\.Exit)$")
BLOCK_TYPES = frozenset({"block", "statement_block", "compound_statement", "declaration_list"})


def _statements(consequence: Node) -> list[Node]:
    """분기 본문의 문장들. 중괄호 없는 한 문장 본문은 그 문장 자체"""
    if consequence.type in BLOCK_TYPES:
        return [c for c in consequence.named_children if "comment" not in c.type]
    return [consequence]


def terminates(src: SourceFile, consequence: Node | None) -> bool:
    """분기 본문이 최상위 문장으로 실행을 끊는다(return·raise·throw·continue·break 또는 종료 호출).
    문자열이나 주석 속의 단어, 중첩된 조건 안의 return은 인정하지 않는다."""
    if consequence is None:
        return False
    for statement in _statements(consequence):
        if statement.type in TERMINATOR_TYPES:
            return True
        if statement.type == "expression_statement":
            for child in statement.named_children:
                call = _call_of(src, child)
                if call is not None and EXIT_CALL_RE.search(call):
                    return True
    return False


def _call_of(src: SourceFile, node: Node) -> str | None:
    inner = node.named_children[0] if node.type == "await_expression" and node.named_children else node
    if src.lang is None or inner.type not in CALL_TYPES.get(src.lang, set()):
        return None
    index = src.memo("call_by_id", lambda: {c.node.id: c for c in iter_calls(src)})
    call = index.get(inner.id)
    return call.callee if call is not None else None


def executes_unconditionally(node: Node, scope: Node) -> bool:
    """node가 scope 안에서 어떤 분기·반복·예외 처리의 조건도 거치지 않고 실행된다"""
    current = node.parent
    while current is not None and current.id != scope.id:
        if current.type in CONDITIONAL_TYPES:
            return False
        current = current.parent
    return True


def redefined_between(src: SourceFile, scope: Node, name: str, start: int, end: int) -> bool:
    """[start, end) 사이에서 name에 새 값이 대입되는지(증분 대입 포함). 검증한 값이 싱크까지 같은 값인지 본다."""
    for value in definitions(src, scope, name):
        holder = value.parent
        position = holder.start_byte if holder is not None else value.start_byte
        if start <= position < end:
            return True
    return False


def mutated_between(src: SourceFile, scope: Node, name: str, start: int, end: int) -> bool:
    """대입뿐 아니라 `name.update(...)`·`name[...] = ...`처럼 값을 바꾸는 호출·인덱스 대입도 본다."""
    if redefined_between(src, scope, name, start, end):
        return True
    pattern = re.compile(rf"\b{re.escape(name)}\s*(\.(append|extend|insert|update|pop|remove|clear|add|discard|setdefault|replace)\(|\[[^\]]*\]\s*=)")
    for node in walk(scope):
        if node.type in ("expression_statement", "assignment") and start <= node.start_byte < end and pattern.search(src.text_of(node)):
            return True
    return False
