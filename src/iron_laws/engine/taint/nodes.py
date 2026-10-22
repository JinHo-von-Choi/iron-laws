"""
오철칙 구문 노드 종류 표: 흐름 해석기가 각 언어의 구문을 어떻게 부르는지 한곳에 모은다
작성자: 최진호
작성일: 2026-10-22
"""

from dataclasses import dataclass
from enum import StrEnum

from tree_sitter import Node

from iron_laws.engine.ast_tools import NESTING_TYPES

MAX_HELPER_DEPTH = 4  # 도우미 함수를 따라가는 깊이 상한

MUTATING_METHODS = frozenset(
    {"add", "append", "put", "push", "extend", "insert", "offer", "addAll", "putAll", "setdefault", "update", "set", "write", "concat"}
)


CONDITIONAL_TYPES = NESTING_TYPES | {
    "conditional_expression",
    "ternary_expression",
    "catch_clause",
    "except_clause",
    "switch_case",
    "case_clause",
    "match_arm",
    "elif_clause",
    "else_clause",
    "finally_clause",
}


class TaintResult(StrEnum):
    TAINTED = "tainted"
    CLEAN = "clean"
    UNKNOWN = "unknown"  # 깊이·예산 한도로 끝까지 따라가지 못했다. 깨끗하다고 보지 않는다


RETURN_TYPES = {"return_statement", "return_expression"}


DEAD_END_TYPES = {"raise_statement", "throw_statement", "throw_expression"}


IF_TYPES = {"if_statement", "if_expression", "elif_clause", "else_if_clause"}


CHAIN_TYPES = {"elif_clause", "else_if_clause"}


ELSE_TYPES = {"else_clause", "else"}


SWITCH_TYPES = {
    "switch_statement",
    "switch_expression",
    "expression_switch_statement",
    "type_switch_statement",
    "match_expression",
    "match_statement",
    "select_statement",
}


CASE_TYPES = {
    "switch_case",
    "switch_default",
    "switch_block_statement_group",
    "switch_section",
    "case_clause",
    "expression_case",
    "default_case",
    "type_case",
    "communication_case",
    "match_arm",
    "switch_rule",
}


LOOP_TYPES = {
    "for_statement",
    "for_in_statement",
    "for_of_statement",
    "foreach_statement",
    "enhanced_for_statement",
    "while_statement",
    "do_statement",
    "loop_expression",
    "for_expression",
    "while_expression",
}


TRY_TYPES = {"try_statement", "try_expression"}


MARK_SUFFIXES = ("statement", "declaration", "_clause", "_arm", "_case", "_rule", "_section", "block")


SCOPE_ROOT_TYPES = {"module", "program", "source_file", "translation_unit", "compilation_unit"}


STATEMENT_PARENTS = SCOPE_ROOT_TYPES | {"statements", "block", "lambda_literal"}  # 블록·람다 바로 아래의 문장(Kotlin은 문장 노드 이름이 따로 없다)


State = frozenset[str] | None  # None은 이 경로가 끝났음(return·throw)을 뜻한다


@dataclass
class Analysis:
    before: dict[int, frozenset[str]]
    returns: list[tuple[Node, frozenset[str]]]
