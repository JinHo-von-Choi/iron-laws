"""
오철칙 분석 대상 소스 파일 표현
작성자: 최진호
작성일: 2026-10-04
"""

import re
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

from tree_sitter import Node

from iron_laws.engine.languages import Lang, detect_language, get_parser

TEMPLATE_SUFFIXES = {".html", ".htm", ".jinja", ".jinja2", ".j2", ".cshtml", ".razor", ".twig", ".ejs"}
HASH_COMMENT_KINDS = {"shell", "yaml", "env", "properties", "docker", "compose", "actions"}


def detect_kind(rel_path: Path) -> str:
    name = rel_path.name.lower()
    suffix = rel_path.suffix.lower()
    if name == "dockerfile" or name.startswith("dockerfile.") or suffix == ".dockerfile":
        return "docker"
    if name.startswith(("docker-compose", "compose.")) and suffix in {".yml", ".yaml"}:
        return "compose"
    if rel_path.as_posix().find(".github/workflows/") >= 0 and suffix in {".yml", ".yaml"}:
        return "actions"
    if name in (".nvmrc", ".node-version", ".python-version", ".java-version", ".tool-versions"):
        return "version"
    if name == ".env" or name.startswith(".env.") or suffix == ".env":
        return "env"
    if suffix == ".rules":
        return "rules"
    if suffix in {".yml", ".yaml"}:
        return "yaml"
    if suffix == ".json":
        return "json"
    if suffix == ".xml":
        return "xml"
    if suffix in {".properties", ".ini", ".cfg", ".conf"}:
        return "properties"
    if suffix == ".sql":
        return "sql"
    if suffix in {".sh", ".bash"}:
        return "shell"
    if suffix == ".toml":
        return "toml"
    if suffix == ".md":
        return "doc"
    if suffix == ".gradle":
        return "gradle"
    if suffix in TEMPLATE_SUFFIXES:
        return "template"
    if suffix == ".txt":
        return "text"
    if detect_language(rel_path) is not None:
        return "code"
    return "text"


@dataclass(eq=False)
class SourceFile:
    path: Path
    text: str
    is_test: bool = False
    lang: Lang | None = field(init=False)
    kind: str = field(init=False)

    def __post_init__(self) -> None:
        self.lang = detect_language(self.path)
        self.kind = detect_kind(self.path)

    @cached_property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    @cached_property
    def data(self) -> bytes:
        return self.text.encode("utf-8")

    @cached_property
    def root(self) -> Node | None:
        if self.lang is None:
            return None
        return get_parser(self.lang).parse(self.data).root_node

    @cached_property
    def nodes(self) -> list[Node]:
        """구문 트리의 모든 노드를 전위 순서로 한 번만 만들어 모든 규칙이 공유한다."""
        if self.root is None:
            return []
        result: list[Node] = []
        stack = [self.root]
        while stack:
            node = stack.pop()
            result.append(node)
            stack.extend(reversed(node.children))
        return result

    def memo(self, key: str, compute):
        store = self.__dict__.setdefault("_memo", {})
        if key not in store:
            store[key] = compute()
        return store[key]

    def release(self) -> None:
        """메모리 절약을 위해 구문 트리와 파생 캐시를 버린다. 필요하면 다시 파싱한다."""
        for name in ("root", "nodes", "comment_nodes", "code_data", "_memo", "_taint_cache", "_defs_cache", "_events_cache"):
            self.__dict__.pop(name, None)

    def text_of(self, node: Node) -> str:
        return self.data[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def line_of(self, node: Node) -> int:
        return node.start_point[0] + 1

    def text_of_line_window(self, line_number: int, span: int) -> str:
        start = max(0, line_number - 1)
        return "\n".join(self.lines[start : start + span])

    def snippet_at(self, line_number: int) -> str:
        if 1 <= line_number <= len(self.lines):
            return self.lines[line_number - 1].strip()
        return ""

    @cached_property
    def comment_nodes(self) -> list[Node]:
        return [n for n in self.nodes if "comment" in n.type]

    def _bare_string_statements(self) -> list[Node]:
        """파이썬의 독스트링처럼 값으로 쓰이지 않는 단독 문자열 문장은 주석처럼 취급한다."""
        if self.lang is not Lang.PYTHON:
            return []
        return [
            n
            for n in self.nodes
            if n.type == "expression_statement" and len(n.named_children) == 1 and n.named_children[0].type == "string"
        ]

    @cached_property
    def code_data(self) -> bytes | None:
        """구문 분석된 파일의 주석을 공백으로 지운 바이트열. 위치는 원본과 같다."""
        if self.root is None:
            return None
        data = bytearray(self.data)
        for node in [*self.comment_nodes, *self._bare_string_statements()]:
            for i in range(node.start_byte, node.end_byte):
                if data[i] not in (10, 13):
                    data[i] = 32
        return bytes(data)

    def code_of(self, node: Node) -> str:
        """node 범위의 원문에서 주석을 지운 텍스트. 주석에 적힌 낱말이 코드로 오인되지 않게 한다."""
        data = self.code_data
        if data is None:
            return self.text_of(node)
        return data[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    @cached_property
    def code_text(self) -> str:
        """주석을 공백으로 지운 본문. 줄 번호와 위치는 그대로 유지된다."""
        if self.code_data is not None:
            return self.code_data.decode("utf-8", errors="replace")
        if self.kind in HASH_COMMENT_KINDS:
            return "\n".join(re.sub(r"(^|\s)#.*$", r"\1", line) for line in self.lines)
        if self.kind == "sql":
            return "\n".join(re.sub(r"--.*$", "", line) for line in self.lines)
        return self.text

    @cached_property
    def code_text_without_strings(self) -> str:
        """주석과 문자열 리터럴 내용을 공백으로 지운 본문. 줄 번호와 위치는 유지된다."""
        if self.root is None:
            return self.code_text
        data = bytearray(self.code_text.encode("utf-8"))
        string_types = {
            "string",
            "string_literal",
            "interpreted_string_literal",
            "raw_string_literal",
            "verbatim_string_literal",
            "template_string",
            "encapsed_string",
        }
        stack = [self.root]
        while stack:
            node = stack.pop()
            if node.type in string_types:
                for i in range(node.start_byte, node.end_byte):
                    if data[i] not in (10, 13):
                        data[i] = 32
                continue
            stack.extend(node.children)
        return data.decode("utf-8", errors="replace")

    @cached_property
    def code_lines(self) -> list[str]:
        return self.code_text.splitlines()
