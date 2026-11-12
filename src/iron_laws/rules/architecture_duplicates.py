"""
오철칙 중복 함수 규칙(ARC-204): 같은 본문이나 같은 이름의 도우미 함수가 여러 파일에 따로 있는 경우
작성자: 최진호
작성일: 2026-11-12
"""

import re
import zlib
from collections import defaultdict

from tree_sitter import Node

from iron_laws.core.models import Confidence, Severity, Violation
from iron_laws.engine.ast_tools import (
    iter_functions,
)
from iron_laws.engine.languages import Lang
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.source import SourceFile
from iron_laws.rules.architecture_common import (
    ArchRule,
    _is_generated,
)


class DuplicateHelperRule(ArchRule):
    rule_id = "ARC-204"
    name = "동일·유사 함수(중복 헬퍼) 산재 탐지"
    severity = Severity.MEDIUM
    plain = "AI는 새 요청마다 이미 있는 함수를 찾지 않고 비슷한 함수를 새로 만들어, 같은 일을 하는 코드가 여러 파일에 흩어집니다. 한 곳의 버그나 보안 수정이 다른 복사본에는 반영되지 않습니다."
    how_to_fix = "중복된 함수를 하나의 공용 모듈(utils/common)로 모아 한 곳에서 import 해서 쓰세요. 이름만 다른 복사본은 하나를 남기고 호출부를 바꾸세요."
    skip_names = re.compile(r"^(<anonymous>|__init__|__repr__|__str__|__eq__|__hash__|constructor|main|Main|setUp|tearDown|setUpClass|toString|equals|hashCode|init|run|handle|dispatch|render|apply|get|set|build|create|new|default)$")
    trivial = re.compile(r"^(get|set|is|has)[A-Z_]\w*$")
    identifier_types = {"identifier", "property_identifier", "field_identifier", "type_identifier", "variable_name", "name", "shorthand_property_identifier", "shorthand_property_identifier_pattern"}
    BOTTOM_K = 8
    SHINGLE = 5

    def check(self, src: SourceFile) -> list[Violation]:
        return []

    def check_project(self, project: ProjectContext) -> list[Violation]:
        limits = project.config.limits
        funcs = []
        for src in project.source_files():
            if _is_generated(src) or src.root is None:
                continue
            for fn in iter_functions(src):
                if fn.body is None or self.skip_names.match(fn.name) or fn.length < 5:
                    continue
                tokens = self._tokens(src, fn.node)
                if len(tokens) < limits.duplicate_min_nodes:
                    continue
                if self.trivial.match(fn.name) and len(tokens) < limits.duplicate_min_nodes * 2:
                    continue
                # 문자열 hash()는 실행마다 달라져 같은 코드에서 다른 결과가 나온다. 실행과 무관한 해시를 쓴다
                shingles = {zlib.crc32("\x1f".join(tokens[i : i + self.SHINGLE]).encode("utf-8")) for i in range(len(tokens) - self.SHINGLE + 1)}
                funcs.append((src, fn, tokens, shingles))
        if len(funcs) < 2:
            return []

        index: dict[tuple[Lang | None, int], list[int]] = defaultdict(list)
        for i, (src, _, _, shingles) in enumerate(funcs):
            for h in sorted(shingles)[: self.BOTTOM_K]:
                index[(src.lang, h)].append(i)

        parent = list(range(len(funcs)))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        compared: set[tuple[int, int]] = set()
        similarity: dict[tuple[int, int], float] = {}
        for bucket in index.values():
            if len(bucket) < 2 or len(bucket) > 60:
                continue
            for a in range(len(bucket)):
                for b in range(a + 1, len(bucket)):
                    i, j = bucket[a], bucket[b]
                    if (i, j) in compared:
                        continue
                    compared.add((i, j))
                    si, sj = funcs[i][3], funcs[j][3]
                    if not (0.5 <= len(si) / max(len(sj), 1) <= 2):
                        continue
                    if funcs[i][0].path == funcs[j][0].path and (funcs[i][1].node.start_byte <= funcs[j][1].node.start_byte < funcs[i][1].node.end_byte):
                        continue
                    sim = len(si & sj) / len(si | sj)
                    if sim >= limits.duplicate_similarity:
                        similarity[(i, j)] = sim
                        parent[find(i)] = find(j)

        clusters: dict[int, list[int]] = defaultdict(list)
        for i in range(len(funcs)):
            clusters[find(i)].append(i)

        found = []
        for members in clusters.values():
            if len(members) < 2:
                continue
            members.sort(key=lambda k: (str(funcs[k][0].path), funcs[k][1].start_line))
            places = [f"{funcs[k][0].path.as_posix()}:{funcs[k][1].start_line}({funcs[k][1].name})" for k in members]
            first = funcs[members[0]]
            exact = len({tuple(funcs[k][2]) for k in members}) == 1
            same_file = len({funcs[k][0].path for k in members}) == 1
            found.append(
                self.at_node(
                    first[0],
                    first[1].node,
                    f"{'동일한' if exact else '거의 같은'} 함수가 {len(members)}곳에 있습니다: {', '.join(places[:6])}{' …' if len(places) > 6 else ''}. 공용 함수로 통합하십시오.",
                    severity=Severity.MEDIUM if not same_file or len(members) > 2 else Severity.LOW,
                )
            )
        found.extend(self._name_families(funcs, {i for m in clusters.values() if len(m) > 1 for i in m}))
        return found

    def _name_families(self, funcs, clustered: set[int]) -> list[Violation]:
        families: dict[tuple[Lang | None, tuple[str, ...]], list[int]] = defaultdict(list)
        for i, (src, fn, _, _) in enumerate(funcs):
            if self._is_method(fn.node):
                continue
            key = tuple(self._name_tokens(fn.name))
            if len(key) >= 2:
                families[(src.lang, key)].append(i)
        found = []
        for (_, key), members in families.items():
            files = {funcs[i][0].path for i in members}
            if len(files) < 3 or all(i in clustered for i in members):
                continue
            members.sort(key=lambda k: (str(funcs[k][0].path), funcs[k][1].start_line))
            first = funcs[members[0]]
            places = [f"{funcs[k][0].path.as_posix()}:{funcs[k][1].start_line}" for k in members]
            found.append(
                self.at_node(
                    first[0],
                    first[1].node,
                    f"이름이 같은 헬퍼 함수 {'_'.join(key)}이(가) {len(files)}개 파일에 따로 구현되어 있습니다: {', '.join(places[:6])}. 하나로 통합했는지 확인하십시오.",
                    severity=Severity.LOW,
                    confidence=Confidence.REVIEW,
                )
            )
        return found

    @staticmethod
    def _is_method(node: Node) -> bool:
        class_types = {"class_definition", "class_declaration", "class_body", "impl_item", "trait_item", "interface_declaration", "struct_declaration", "class_specifier"}
        current = node.parent
        while current is not None:
            if current.type in class_types:
                return True
            current = current.parent
        return False

    @staticmethod
    def _name_tokens(name: str) -> list[str]:
        spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
        return [t.lower() for t in re.split(r"[_\W]+", spaced) if t]

    def _tokens(self, src: SourceFile, fn_node: Node) -> list[str]:
        tokens: list[str] = []
        stack = [fn_node]
        order: list[Node] = []
        while stack:
            node = stack.pop()
            order.append(node)
            stack.extend(reversed(node.children))
        for node in order:
            if not node.is_named or "comment" in node.type:
                continue
            if node.type in self.identifier_types:
                parent = node.parent
                if parent is not None and parent.type in ("call", "call_expression", "method_invocation", "attribute", "member_expression", "field_expression", "member_access_expression", "selector_expression") and node.next_named_sibling is None and parent.child_by_field_name("function") is not None:
                    tokens.append(src.text_of(node))
                elif parent is not None and parent.type in ("attribute", "member_expression", "field_expression", "member_access_expression", "selector_expression", "method_invocation") and node == parent.children[-1]:
                    tokens.append(src.text_of(node))
                else:
                    tokens.append("ID")
            elif node.type in ("string", "string_literal", "interpreted_string_literal", "raw_string_literal", "template_string", "verbatim_string_literal"):
                tokens.append("STR")
            elif "number" in node.type or node.type in ("integer", "float", "integer_literal", "float_literal", "decimal_integer_literal"):
                tokens.append("NUM")
            else:
                tokens.append(node.type)
        return tokens
