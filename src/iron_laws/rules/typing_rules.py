"""
타입 안전성 계열: 타입 검사 회피, any 남용, 무분별한 캐스팅
작성자: 최진호
작성일: 2026-10-04
"""

import json
import re

from iron_laws.core.models import Confidence, IronLaw, RuleLayer, Severity, Violation
from iron_laws.engine.ast_tools import iter_calls, iter_functions
from iron_laws.engine.languages import C_FAMILY, TS_FAMILY, Lang
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.source import SourceFile
from iron_laws.rules.base import BaseRule

MAX_PER_FILE = 20


class TypeRule(BaseRule):
    layer = RuleLayer.AI_CODE
    gov_standard = None
    iron_law = IronLaw.LAW_3
    severity = Severity.MEDIUM
    plain = "타입 검사를 끄거나 any로 덮으면 컴파일러가 잡아 줄 오류가 런타임까지 숨어 있다가 운영 중에 터집니다. AI는 타입 오류를 '해결'하는 대신 억제해 버리는 경우가 많습니다."
    how_to_fix = "any/ignore로 덮지 말고 실제 타입을 정의하세요. 정말 모를 때는 unknown(TS)·object에 타입 가드를 거치거나, 입력 검증(zod, pydantic)으로 경계에서 한 번만 검증하세요."


class TypeScriptSafetyRule(TypeRule):
    rule_id = "TYP-301"
    name = "TypeScript 타입 검사 회피(any, ts-ignore, 강제 캐스팅) 탐지"
    languages = frozenset(TS_FAMILY)
    suppress_re = re.compile(r"@ts-(ignore|nocheck)\b|eslint-disable[^\n]*(no-explicit-any|no-unsafe-\w+|ban-ts-comment)")

    def check(self, src: SourceFile) -> list[Violation]:
        found: list[Violation] = []
        if src.root is None:
            return found
        counts = {"any": 0, "nonnull": 0}
        for node in src.nodes:
            if len(found) >= MAX_PER_FILE:
                break
            if node.type == "predefined_type" and src.text_of(node) == "any":
                parent = node.parent
                if parent is not None and parent.type in ("as_expression", "type_assertion"):
                    found.append(self.at_node(src, node, "as any 캐스팅으로 타입 검사를 우회합니다.", confidence=Confidence.CONFIRMED))
                else:
                    counts["any"] += 1
                    if counts["any"] <= 10:
                        found.append(self.at_node(src, node, "any 타입이 사용됩니다. 구체적인 타입이나 unknown을 쓰십시오.", severity=Severity.LOW))
            elif node.type == "as_expression":
                text = src.text_of(node)
                if re.search(r"\bas\s+unknown\s+as\b", text):
                    found.append(self.at_node(src, node, "as unknown as T 이중 캐스팅으로 타입 검사를 우회합니다."))
            elif node.type == "non_null_expression":
                counts["nonnull"] += 1
                if counts["nonnull"] <= 5:
                    found.append(self.at_node(src, node, "non-null 단언(!)으로 null 가능성을 무시합니다.", severity=Severity.LOW, confidence=Confidence.REVIEW))
        for node in src.comment_nodes:
            if self.suppress_re.search(src.text_of(node)):
                found.append(self.at_node(src, node, "타입/린트 검사를 끄는 주석입니다 (@ts-ignore/@ts-nocheck/eslint-disable)."))
        return found[:MAX_PER_FILE]

    def check_project(self, project: ProjectContext) -> list[Violation]:
        found = []
        for src in project.files:
            if not re.match(r"tsconfig(\..+)?\.json$", src.path.name):
                continue
            text = re.sub(r"//[^\n]*|/\*.*?\*/", "", src.text, flags=re.DOTALL)
            text = re.sub(r",(\s*[}\]])", r"\1", text)
            try:
                data = json.loads(text)
            except json.JSONDecodeError:  # iron-laws: ignore[IL-301] 해석 실패를 LOW 지적으로 보고한다
                found.append(self.at_line(src, 1, f"{src.path.name}을 해석할 수 없어 타입 엄격성 설정을 점검하지 못했습니다.", severity=Severity.LOW))
                continue
            options = (data.get("compilerOptions") or {}) if isinstance(data, dict) else {}
            if options.get("strict") is False or options.get("noImplicitAny") is False:
                found.append(self.at_line(src, 1, "tsconfig에서 strict/noImplicitAny가 꺼져 있어 암묵적 any가 허용됩니다.", confidence=Confidence.CONFIRMED))
            elif "strict" not in options and "extends" not in data and src.path.name == "tsconfig.json":
                found.append(self.at_line(src, 1, "tsconfig에 strict: true가 없어 타입 검사가 느슨합니다.", severity=Severity.LOW, confidence=Confidence.REVIEW))
        return found


class PythonTypingRule(TypeRule):
    rule_id = "TYP-302"
    name = "Python 타입 검사 회피(type: ignore, cast, Any)와 타입 힌트 불일치 탐지"
    languages = frozenset({Lang.PYTHON})
    ignore_re = re.compile(r"#\s*(type:\s*ignore|pyright:\s*ignore|mypy:\s*ignore-errors|pytype:\s*disable)")

    def check(self, src: SourceFile) -> list[Violation]:
        found: list[Violation] = []
        for node in src.comment_nodes:
            text = src.text_of(node)
            if re.search(r"mypy:\s*ignore-errors", text):
                found.append(self.at_node(src, node, "mypy 검사를 파일 전체에서 끕니다.", severity=Severity.HIGH))
            elif self.ignore_re.search(text):
                found.append(self.at_node(src, node, "type: ignore로 타입 오류를 억제합니다. 오류 원인을 고치십시오."))
        for call in iter_calls(src):
            if call.callee in ("cast", "typing.cast"):
                found.append(self.at_node(src, call.node, "typing.cast로 타입을 강제 지정합니다. 타입 가드나 검증으로 대체하십시오.", severity=Severity.LOW, confidence=Confidence.REVIEW))
        any_count = 0
        for fn in iter_functions(src):
            head = src.text_of(fn.node)
            head = head[: head.find(":\n")] if ":\n" in head else head[:200]
            if re.search(r"(?::\s*|->\s*)(typing\.)?Any\b", head):
                any_count += 1
                if any_count <= 5:
                    found.append(self.at_node(src, fn.node, f"함수 {fn.name}의 시그니처에 Any가 쓰였습니다.", severity=Severity.LOW))
        return found[:MAX_PER_FILE]

    def check_project(self, project: ProjectContext) -> list[Violation]:
        total = annotated = 0
        per_file: dict[SourceFile, list[str]] = {}
        for src in project.source_files():
            if src.lang is not Lang.PYTHON:
                continue
            for fn in iter_functions(src):
                params = [p for p in fn.params if src.text_of(p) not in ("self", "cls")]
                if not params and fn.node.child_by_field_name("return_type") is None and fn.length < 3:
                    continue
                total += 1
                has_ann = fn.node.child_by_field_name("return_type") is not None or any(p.type in ("typed_parameter", "typed_default_parameter") for p in params)
                if has_ann:
                    annotated += 1
                elif not fn.name.startswith("_") and not fn.name.startswith("test"):
                    per_file.setdefault(src, []).append(f"{fn.name}:{fn.start_line}")
        found = []
        if total >= 10 and annotated / total >= 0.3:
            for src, names in per_file.items():
                if len(names) >= 3:
                    line = int(names[0].split(":")[1])
                    found.append(self.at_line(src, line, f"프로젝트는 타입 힌트를 쓰는데 이 파일의 함수 {len(names)}개에는 타입 표기가 없습니다 ({', '.join(n.split(':')[0] for n in names[:4])} …).", severity=Severity.LOW, confidence=Confidence.REVIEW))
        for src in project.files:
            if src.kind in ("toml", "properties") and re.search(r"(?m)^\s*ignore_errors\s*=\s*true|^\s*disallow_untyped_defs\s*=\s*false", src.code_text):
                idx = next(i for i, text_line in enumerate(src.code_lines, start=1) if re.search(r"ignore_errors\s*=\s*true|disallow_untyped_defs\s*=\s*false", text_line))
                found.append(self.at_line(src, idx, "mypy 설정에서 오류 무시 또는 타입 없는 함수 허용이 켜져 있습니다.", severity=Severity.MEDIUM))
        return found


class JavaTypingRule(TypeRule):
    rule_id = "TYP-303"
    name = "Java 원시 타입·검사되지 않은 캐스팅 탐지"
    languages = frozenset({Lang.JAVA})
    raw_re = re.compile(r"\b(List|ArrayList|LinkedList|Map|HashMap|TreeMap|Set|HashSet|Collection|Iterator|Optional|Class|Comparable|Queue|Deque|Vector)\s+\w+\s*(?:=|;|,|\))")
    raw_new = re.compile(r"\bnew\s+(ArrayList|HashMap|HashSet|LinkedList|TreeMap)\s*\(")
    suppress_re = re.compile(r'@SuppressWarnings\(\s*(?:\{\s*)?"(?:unchecked|rawtypes)"')

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        for idx, line in enumerate(src.code_lines, start=1):
            if len(found) >= MAX_PER_FILE:
                break
            if self.suppress_re.search(line):
                found.append(self.at_line(src, idx, "@SuppressWarnings로 unchecked/rawtypes 경고를 억제합니다."))
            elif self.raw_re.search(line) and "<" not in line.split("=")[0]:
                found.append(self.at_line(src, idx, "제네릭 타입 인자 없이 원시 타입을 사용합니다. 타입 인자를 지정하십시오."))
            elif self.raw_new.search(line) and "<" not in line[line.find("new") :].split("(")[0]:
                found.append(self.at_line(src, idx, "제네릭 타입 인자 없이 컬렉션을 생성합니다.", severity=Severity.LOW))
        if src.root is not None:
            for node in src.nodes:
                if node.type == "cast_expression" and re.search(r"<[^>]+>", src.text_of(node.child_by_field_name("type") or node)):
                    found.append(self.at_node(src, node, "제네릭 타입으로의 검사되지 않은 캐스팅입니다.", severity=Severity.LOW, confidence=Confidence.REVIEW))
        return found[:MAX_PER_FILE]


class CSharpTypingRule(TypeRule):
    rule_id = "TYP-304"
    name = "C# 타입·널 안전성 회피(dynamic, #nullable disable) 탐지"
    languages = None
    patterns = [
        (re.compile(r"^\s*#nullable\s+disable"), "#nullable disable로 null 안전성 검사를 끕니다.", Severity.MEDIUM),
        (re.compile(r"^\s*#pragma\s+warning\s+disable\s+CS(86\d\d|8\d{3})"), "null 관련 컴파일러 경고를 끕니다.", Severity.MEDIUM),
        (re.compile(r"\bdynamic\s+\w+|\(\s*dynamic\s*\)|<dynamic>"), "dynamic 타입은 컴파일 타임 타입 검사를 건너뜁니다.", Severity.MEDIUM),
        (re.compile(r"(?<=[\w\)\]])!(?=[.\[;,)\s]|$)(?!=)"), "null 허용 억제 연산자(!)로 null 가능성을 무시합니다.", Severity.LOW),
    ]

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.kind == "xml":
            for idx, line in enumerate(src.lines, start=1):
                if re.search(r"<Nullable>\s*disable\s*</Nullable>", line):
                    found.append(self.at_line(src, idx, "프로젝트에서 Nullable 컨텍스트가 비활성화되어 있습니다."))
            return found
        if src.lang is not Lang.CSHARP:
            return found
        nullforgive = 0
        for idx, line in enumerate(src.code_lines, start=1):
            for pattern, message, severity in self.patterns:
                if pattern.search(line):
                    if severity is Severity.LOW:
                        nullforgive += 1
                        if nullforgive > 5:
                            break
                    found.append(self.at_line(src, idx, message, severity=severity, confidence=Confidence.REVIEW if severity is Severity.LOW else Confidence.CONFIRMED))
                    break
        return found[:MAX_PER_FILE]


class SystemsTypingRule(TypeRule):
    rule_id = "TYP-305"
    name = "Go·Rust·C/C++·PHP·JS의 타입 안전성 회피 탐지"
    languages = frozenset({Lang.GO, Lang.RUST, Lang.C, Lang.CPP, Lang.PHP, Lang.JAVASCRIPT})

    def check(self, src: SourceFile) -> list[Violation]:
        found: list[Violation] = []
        if src.root is None:
            return found
        if src.lang is Lang.GO:
            found.extend(self._go(src))
        elif src.lang is Lang.RUST:
            found.extend(self._rust(src))
        elif src.lang in C_FAMILY:
            found.extend(self._c(src))
        elif src.lang is Lang.PHP:
            found.extend(self._php(src))
        elif src.lang is Lang.JAVASCRIPT:
            found.extend(self._js(src))
        return found[:MAX_PER_FILE]

    def _go(self, src: SourceFile) -> list[Violation]:
        found = []
        any_count = 0
        assert src.root is not None
        for node in src.nodes:
            if node.type == "type_assertion_expression":
                parent = node.parent
                checked = parent is not None and (
                    (parent.type == "short_var_declaration" and "," in src.text_of(parent.child_by_field_name("left") or parent))
                    or (parent.type == "expression_list" and parent.parent is not None and parent.parent.type in ("short_var_declaration", "assignment_statement") and "," in src.text_of(parent.parent.child_by_field_name("left") or parent.parent))
                    or (parent.type in ("type_switch_statement",))
                )
                grand = parent.parent if parent is not None else None
                if grand is not None and grand.type in ("short_var_declaration", "assignment_statement") and "," in src.text_of(grand.child_by_field_name("left") or grand):
                    checked = True
                if not checked:
                    found.append(self.at_node(src, node, "comma-ok 없이 타입 단언을 해 실패하면 panic이 발생합니다.", confidence=Confidence.REVIEW))
            elif node.type in ("interface_type",) and src.text_of(node).replace(" ", "") == "interface{}":
                any_count += 1
                if any_count <= 5:
                    found.append(self.at_node(src, node, "interface{} 타입은 컴파일러 타입 검사를 건너뜁니다. 제네릭이나 구체 타입을 쓰십시오.", severity=Severity.LOW))
            elif node.type == "import_spec" and src.text_of(node).strip('"').endswith('"unsafe"') or (node.type == "import_spec" and src.text_of(node) == '"unsafe"'):
                found.append(self.at_node(src, node, "unsafe 패키지를 사용합니다. 메모리 안전성 보장이 사라집니다.", confidence=Confidence.REVIEW))
        return found

    def _rust(self, src: SourceFile) -> list[Violation]:
        found = []
        unwrap = 0
        assert src.root is not None
        for node in src.nodes:
            if node.type == "unsafe_block":
                prev = node.prev_sibling
                before = src.data[max(0, node.start_byte - 200) : node.start_byte].decode("utf-8", "replace")
                if "SAFETY" not in before and not (prev is not None and "comment" in prev.type and "SAFETY" in src.text_of(prev)):
                    found.append(self.at_node(src, node, "unsafe 블록에 // SAFETY: 근거 주석이 없습니다.", confidence=Confidence.REVIEW))
        if not src.is_test:
            for call in iter_calls(src):
                if re.search(r"\.(unwrap|expect)$", call.callee) and not re.search(r"(Mutex|lock|RwLock)", call.callee):
                    unwrap += 1
                    if unwrap <= 8:
                        found.append(self.at_node(src, call.node, ".unwrap()/.expect()는 실패 시 프로세스를 중단시킵니다. ?로 오류를 전파하십시오.", severity=Severity.LOW, confidence=Confidence.REVIEW))
        return found

    def _c(self, src: SourceFile) -> list[Violation]:
        found = []
        assert src.root is not None
        for idx, line in enumerate(src.code_lines, start=1):
            if re.search(r"\b(reinterpret_cast|const_cast)\s*<", line):
                found.append(self.at_line(src, idx, "reinterpret_cast/const_cast로 타입 시스템을 우회합니다.", confidence=Confidence.REVIEW))
        if src.lang is Lang.CPP:
            casts = 0
            for node in src.nodes:
                if node.type == "cast_expression" and "*" in src.text_of(node.child_by_field_name("type") or node):
                    casts += 1
                    if casts <= 5:
                        found.append(self.at_node(src, node, "C 스타일 포인터 캐스트입니다. static_cast 등 명시적 캐스트를 쓰십시오.", severity=Severity.LOW, confidence=Confidence.REVIEW))
        return found

    def _php(self, src: SourceFile) -> list[Violation]:
        found = []
        text = src.code_text
        if "<?php" in text and "declare(strict_types=1)" not in text.replace(" ", "") and iter_functions_exist(src):
            found.append(self.at_line(src, 1, "declare(strict_types=1)이 없어 PHP가 타입을 조용히 변환합니다.", severity=Severity.LOW, confidence=Confidence.REVIEW))
        for idx, line in enumerate(src.code_lines, start=1):
            if re.search(r"(?i)(pass(word)?|hash|token|secret|signature|hmac|nonce)\w*\s*==\s*(?!=)|(?<![=!])==\s*\$\w*(pass(word)?|hash|token|secret|signature|hmac)", line):
                found.append(self.at_line(src, idx, "비밀번호/해시/토큰을 느슨한 비교(==)로 비교합니다. 타입 변환으로 우회될 수 있으니 hash_equals 또는 ===를 쓰십시오.", severity=Severity.HIGH))
        return found

    def _js(self, src: SourceFile) -> list[Violation]:
        found = []
        loose = 0
        for idx, line in enumerate(src.code_lines, start=1):
            if re.search(r"[^=!<>]==[^=]", line) and not re.search(r"==\s*null\b|null\s*==", line):
                loose += 1
                if loose <= 5:
                    found.append(self.at_line(src, idx, "느슨한 동등 비교(==)는 타입을 자동 변환합니다. ===를 쓰십시오.", severity=Severity.LOW, confidence=Confidence.REVIEW))
        return found


def iter_functions_exist(src: SourceFile) -> bool:
    return any(True for _ in iter_functions(src))


TYPING_RULES: list[type[BaseRule]] = [
    TypeScriptSafetyRule,
    PythonTypingRule,
    JavaTypingRule,
    CSharpTypingRule,
    SystemsTypingRule,
]

