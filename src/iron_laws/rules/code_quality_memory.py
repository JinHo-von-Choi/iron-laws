"""
오철칙 메모리 안전 규칙(C·C++): 버퍼 넘침(IL-514), 해제 뒤 사용(IL-528), 초기화하지 않은 변수(IL-529)
작성자: 최진호
작성일: 2026-11-12
"""

import re

from tree_sitter import Node

from iron_laws.core.models import Confidence, IronLaw, Severity, Violation
from iron_laws.engine.ast_tools import (
    enclosing_function,
    is_literal,
    iter_calls,
    walk,
)
from iron_laws.engine.c_buffers import capacity, current_length, literal_only_buffer, string_length
from iron_laws.engine.languages import C_FAMILY
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import is_tainted
from iron_laws.rules.base import BaseRule
from iron_laws.standards import mois_ref


class MemorySafetyRule(BaseRule):
    version = 3
    rule_id = "IL-514"
    name = "메모리 버퍼 오버플로우·포맷 스트링·정수 오버플로우 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.HIGH
    gov_standard = mois_ref("1-16", "1-17", "1-14")
    plain = "C/C++에서 버퍼 크기를 확인하지 않고 복사하거나 입력을 포맷 문자열로 쓰면 프로그램을 장악당할 수 있습니다."
    how_to_fix = "strcpy/strcat/sprintf 대신 snprintf, strlcpy, std::string을 쓰세요. printf는 항상 printf(\"%s\", 값) 형태로 호출하세요. 크기 계산 전에 오버플로우를 검사하세요."
    languages = frozenset(C_FAMILY)
    unsafe_copy = re.compile(r"^(strcpy|strcat|sprintf|vsprintf|stpcpy|wcscpy|wcscat|swprintf)$")
    string_copy = re.compile(r"^(strcpy|strcat|stpcpy|wcscpy|wcscat)$")

    def _copy_verdict(self, src: SourceFile, call) -> Violation | None:
        """strcpy·strcat: 원본 길이와 목적지의 남은 크기를 상수로 계산할 수 있으면 비교한다.
        넘치면 확정, 들어가면 지적하지 않고, 계산할 수 없으면 확인 필요"""
        callee = call.callee
        dest, source = call.args
        append = callee.endswith("cat")
        room = capacity(src, dest, call.node)
        source_room = capacity(src, source, call.node)
        if room is not None and room[1] < 0:
            return self.at_node(src, call.node, f"{callee}가 목적지 버퍼의 시작보다 {-room[1]}칸 앞부터 씁니다(버퍼 아래쪽 쓰기).")
        if source_room is not None and source_room[1] < 0:
            return self.at_node(src, call.node, f"{callee}가 원본 버퍼의 시작보다 {-source_room[1]}칸 앞부터 읽습니다(버퍼 아래쪽 읽기).")
        length = string_length(src, source, call.node)
        used = current_length(src, dest, call.node) if append else 0
        if room is not None and length is not None and used is not None:
            remaining = room[0] - room[1] - used
            if length + 1 <= remaining:
                return None  # 종료 문자까지 목적지에 들어간다
            return self.at_node(src, call.node, f"{callee}가 {length}자 문자열(종료 문자 포함 {length + 1}칸)을 남은 크기 {remaining}칸인 버퍼에 복사합니다. 길이를 제한하는 함수(snprintf/strlcpy)를 쓰십시오.")
        return self.at_node(
            src, call.node, f"{callee}는 목적지 버퍼 크기를 검사하지 않습니다. 원본 길이나 목적지 크기를 코드에서 정할 수 없으니 넘치지 않는지 확인하고 길이를 제한하는 함수(snprintf/strlcpy)를 쓰십시오.",
            severity=Severity.MEDIUM, confidence=Confidence.REVIEW,
        )
    fmt_funcs = {"printf": 0, "fprintf": 1, "sprintf": 1, "snprintf": 2, "syslog": 1, "vprintf": 0, "dprintf": 1, "wprintf": 0, "err": 1, "warn": 0}
    scanf_funcs = re.compile(r"^(scanf|fscanf|sscanf)$")
    alloc = re.compile(r"^(malloc|alloca|calloc|realloc)$")

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        for call in iter_calls(src):
            callee = call.callee
            if self.string_copy.search(callee) and len(call.args) == 2:
                verdict = self._copy_verdict(src, call)
                if verdict is not None:
                    found.append(verdict)
            elif self.unsafe_copy.search(callee):
                source_arg = call.args[1] if len(call.args) > 1 else None
                if callee in ("sprintf", "vsprintf") and len(call.args) > 2:
                    source_arg = call.args[1]
                fmt_arg = call.args[1] if callee in ("sprintf", "vsprintf", "swprintf") and len(call.args) > 1 else None
                bounded_format = fmt_arg is not None and is_literal(fmt_arg) and not re.search(r"%[^a-zA-Z%]*s|%\[", src.text_of(fmt_arg))
                severity = Severity.LOW if bounded_format else (Severity.HIGH if source_arg is not None and not is_literal(source_arg) else Severity.MEDIUM)
                found.append(self.at_node(src, call.node, f"{callee}는 목적지 버퍼 크기를 검사하지 않습니다. 길이를 제한하는 함수(snprintf/strlcpy)를 쓰십시오.", severity=severity))
            if callee in self.fmt_funcs:
                idx = self.fmt_funcs[callee]
                if len(call.args) > idx and not is_literal(call.args[idx]):
                    arg = call.args[idx]
                    tainted = is_tainted(src, arg, cli=True)
                    if arg.type in ("identifier", "subscript_expression", "field_expression", "call_expression", "pointer_expression", "parenthesized_expression", "cast_expression"):
                        if tainted:
                            found.append(self.at_node(src, call.node, f"{callee}의 포맷 문자열에 외부 입력이 들어갑니다. %n 등으로 메모리를 변조할 수 있습니다.", severity=Severity.CRITICAL))
                        elif not literal_only_buffer(src, arg, call.node):
                            # 리터럴이 아닌 서식 문자열은 그 자체로 약점이다(CWE-134). 리터럴만 복사한 버퍼만 뺀다
                            found.append(self.at_node(src, call.node, f"{callee}의 포맷 문자열이 상수가 아닙니다. 외부 입력이면 메모리 변조가 가능하니 {callee}(\"%s\", 값) 꼴로 쓰십시오.", severity=Severity.HIGH))
            if self.scanf_funcs.search(callee):
                fmt = call.args[0 if callee == "scanf" else 1] if call.args else None
                if fmt is not None and re.search(r"%s|%\[", src.text_of(fmt)) and not re.search(r"%\d+s|%\d+\[", src.text_of(fmt)):
                    found.append(self.at_node(src, call.node, f"{callee}의 %s는 입력 길이를 제한하지 않아 버퍼 오버플로우가 가능합니다. 너비를 지정하십시오(%63s)."))
            if self.alloc.search(callee) and call.args:
                size = call.args[0]
                if size.type == "binary_expression" and re.search(r"[*+]", src.text_of(size)) and not is_literal(size) and is_tainted(src, size, cli=True):
                    found.append(self.at_node(src, call.node, f"{callee}의 크기 계산에 외부 입력이 곱·합으로 쓰여 정수 오버플로우가 가능합니다.", severity=Severity.HIGH))
        return found


class UseAfterFreeRule(BaseRule):
    rule_id = "IL-528"
    name = "해제된 자원 사용 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.HIGH
    gov_standard = mois_ref("5-3")
    plain = "이미 반납(free)한 메모리를 다시 쓰면 프로그램이 예측할 수 없이 동작하고, 공격자가 그 자리를 차지해 실행 흐름을 빼앗을 수 있습니다."
    how_to_fix = "free 직후 포인터를 NULL로 만들고, 해제 뒤에는 그 포인터를 쓰지 마세요. C++에서는 직접 delete 대신 std::unique_ptr, std::vector를 쓰세요."
    languages = frozenset(C_FAMILY)

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        free_calls = [c for c in iter_calls(src) if c.callee in ("free", "kfree", "g_free") and c.args]
        delete_nodes = [n for n in src.nodes if n.type == "delete_expression"]
        events: list[tuple[Node, str, Node]] = [(c.node, src.text_of(c.args[0]).strip(), c.node) for c in free_calls]
        for d in delete_nodes:
            target = d.named_children[-1] if d.named_children else None
            if target is not None:
                events.append((d, src.text_of(target).strip(), d))
        for node, name, free_node in events:
            if not re.fullmatch(r"[A-Za-z_]\w*", name):
                continue
            fn = enclosing_function(node, src.lang)
            if fn is None:
                continue
            use = self._first_use_after(src, fn, name, free_node)
            if use is not None:
                found.append(self.at_node(src, use, f"{name}을(를) 해제한 뒤 다시 사용합니다 (해제 위치: {src.line_of(free_node)}줄)."))
        return found

    @staticmethod
    def _first_use_after(src: SourceFile, fn: Node, name: str, free_node: Node) -> Node | None:
        for n in src.nodes:
            if n.type != "identifier" or n.start_byte < free_node.end_byte or n.end_byte > fn.end_byte:
                continue
            if src.text_of(n) != name:
                continue
            parent = n.parent
            if parent is not None and parent.type == "assignment_expression" and parent.child_by_field_name("left") == n:
                return None  # 다시 대입되면 이후 사용은 새 값이다
            if parent is not None and parent.type == "call_expression" and src.text_of(parent).startswith(("free", "g_free")):
                return n  # 이중 해제
            return n
        return None


class UninitializedVariableRule(BaseRule):
    rule_id = "IL-529"
    name = "초기화되지 않은 변수 사용 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    gov_standard = mois_ref("5-4")
    plain = "값을 넣기 전에 변수를 읽으면 메모리에 남아 있던 임의의 값이 쓰여, 결과가 실행할 때마다 달라지고 정보가 새어 나갑니다."
    how_to_fix = "변수는 선언할 때 반드시 초기값을 주세요. 예: int count = 0; char *p = NULL;"
    languages = frozenset(C_FAMILY)

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        for node in src.nodes:
            if node.type != "declaration":
                continue
            if any(c.type == "storage_class_specifier" and src.text_of(c) in ("static", "extern") for c in node.children):
                continue
            fn = enclosing_function(node, src.lang)
            if fn is None:
                continue
            for child in node.named_children:
                if child.type not in ("identifier", "pointer_declarator"):
                    continue
                name_node = child if child.type == "identifier" else self._declarator_name(child)
                if name_node is None:
                    continue
                name = src.text_of(name_node)
                use = self._first_event(src, fn, name, node)
                if use == "read":
                    found.append(self.at_node(src, node, f"변수 {name}을(를) 초기화하지 않고 선언한 뒤 값을 읽습니다.", confidence=Confidence.REVIEW))
        return found

    @staticmethod
    def _declarator_name(node: Node) -> Node | None:
        for n in walk(node):
            if n.type == "identifier":
                return n
        return None

    @staticmethod
    def _first_event(src: SourceFile, fn: Node, name: str, decl: Node) -> str | None:
        for n in src.nodes:
            if n.type != "identifier" or n.start_byte < decl.end_byte or n.end_byte > fn.end_byte or src.text_of(n) != name:
                continue
            parent = n.parent
            if parent is None:
                return None
            if parent.type == "assignment_expression" and parent.child_by_field_name("left") == n:
                return "write"
            if parent.type == "pointer_expression" and src.text_of(parent).startswith("&"):
                return "write"
            if parent.type in ("argument_list",) and parent.parent is not None and re.match(r"(scanf|fscanf|sscanf|read|fread|memset|memcpy|strcpy|strncpy|fgets|gets|recv)\b", src.text_of(parent.parent)):
                return "write"
            if parent.type in ("update_expression", "init_declarator", "pointer_declarator", "array_declarator"):
                return None
            return "read"
        return None
