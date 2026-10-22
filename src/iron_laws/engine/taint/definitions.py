"""
오철칙 대입 정의 찾기: 어떤 이름이 어디에 대입돼는지, 그 대입이 실행되는 경로까지 알려 준다
작성자: 최진호
작성일: 2026-10-22
"""

from tree_sitter import Node

from iron_laws.engine.ast_tools import walk
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint.nodes import CONDITIONAL_TYPES
from iron_laws.engine.taint.paths import (
    ASSIGN_TYPES,
    AUGMENTED_TYPES,
    _target_and_value,
    _target_names,
)


def _unconditional(node: Node, scope: Node) -> bool:
    current = node.parent
    while current is not None and current.id != scope.id:
        if current.type in CONDITIONAL_TYPES:
            return False
        current = current.parent
    return True


def reaching_definitions(src: SourceFile, scope: Node, name: str, before: int) -> list[Node]:
    """before 위치의 name에 도달하는 대입 우변들. 무조건 실행되는 마지막 대입 뒤에는 그 이전 대입이 도달하지 못한다."""
    defs = definitions(src, scope, name)
    prior = sorted((d for d in defs if d.end_byte <= before), key=lambda d: d.start_byte)
    if not prior:
        return defs
    last_sure = -1
    for i, d in enumerate(prior):
        holder = d.parent
        if _unconditional(d, scope) and not (holder is not None and holder.type in AUGMENTED_TYPES):
            last_sure = i
    return prior[last_sure:] if last_sure >= 0 else prior


def definitions(src: SourceFile, scope: Node, name: str) -> list[Node]:
    """범위 안에서 name에 대입되는 우변 식들을 반환한다."""
    cache = src.__dict__.setdefault("_defs_cache", {})
    key = scope.id
    if key not in cache:
        table: dict[str, list[Node]] = {}
        for n in walk(scope):
            if n.type in ASSIGN_TYPES:
                left, right = _target_and_value(n)
                if left is None or right is None:
                    continue
                for ident in _target_names(src, left):
                    table.setdefault(ident, []).append(right)
        cache[key] = table
    return cache[key].get(name, [])
