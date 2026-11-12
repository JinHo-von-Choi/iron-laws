"""
오철칙 실패를 정상 값으로 바꾸는 코드 규칙: 실패 시 기본값 반환(IL-307), 검증 실패 문구와 조건 불일치(IL-531)
작성자: 최진호
작성일: 2026-11-12
"""

import ast
import re

from tree_sitter import Node

from iron_laws.core.models import Confidence, IronLaw, Severity, Violation
from iron_laws.engine.ast_tools import (
    body_statements,
    has_logging,
    has_throw,
    iter_functions,
    walk_no_nested_functions,
)
from iron_laws.engine.languages import Lang
from iron_laws.engine.python_ast import parse_python
from iron_laws.engine.source import SourceFile
from iron_laws.rules.base import BaseRule
from iron_laws.rules.errors import DEFAULT_VALUE_RE
from iron_laws.standards import mois_ref

IF_TYPES = {"if_statement", "if_expression"}


NULL_GUARD_RE = re.compile(
    r"^\(?\s*(?:!\s*|not\s+)?\w+(?:\.\w+|\[[^\]]*\])*\s*(?:(?:==|!=|is|is\s+not)\s*(?:null|None|nil|undefined)\b)?\s*\)?$"
)


class FailureAsDefaultRule(BaseRule):
    version = 3
    rule_id = "IL-307"
    name = "검증·처리 실패를 null·기본값으로 대체하고 기록하지 않음"
    iron_law = IronLaw.LAW_3
    severity = Severity.MEDIUM
    gov_standard = mois_ref("4-2")
    plain = "검증이나 복호화가 실패했는데 예외 없이 null·false를 돌려주면, 호출한 쪽은 실패를 모른 채 정상처럼 처리를 이어 갑니다. 결제·인증처럼 정확성이 중요한 곳에서는 잘못된 결과가 조용히 쌓이고 원인도 남지 않습니다."
    how_to_fix = "정상 흐름을 벗어나면 예외를 던지세요(복구할 수 있는 경우에만 처리). 던지지 않고 값을 돌려줘야 한다면 실패 사유를 로그로 남기고, 호출한 쪽이 실패를 구분할 수 있게 결과 타입(성공·실패)을 명시하세요."
    # 함수 이름을 snake_case·camelCase 낱말로 나눠 낱말 머리에서만 찾는다(assignment·design의 sign, checkout의 check를 거른다).
    # 짧은 어근은 다른 낱말의 머리가 되기 쉬워 정해진 활용형만 인정한다.
    sensitive_stem = re.compile(
        r"(?:re|pre|un|de|auto|safe|try)?(?:verif|validat|decrypt|decod|encrypt|authenticat|authoriz|pars|token|checksum|permission|credential|charg|refund|settl|transfer|withdraw|deposit|amount|balance|login|otp)"
    )
    sensitive_word = re.compile(r"(?:check(?:s|ed|ing|er)?|sign(?:s|ed|ing|er)?|orders?|pay(?:s|ment|ments|out|outs)?|paid)")
    name_word_re = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
    # signature는 함수 시그니처를 뜻하기도 해서 서명 알고리즘·전달 형식 낱말과 함께 쓰일 때만 민감한 이름으로 본다
    signature_word = re.compile(r"signatures?")
    signature_context = re.compile(r"(?:hmac|jwt|jws|rsa|ecdsa|ed25519|webhook|request|header|payload|message|digest|crypto|sha\d*)")
    or_null = re.compile(r"(?i)(OrNull|_or_none|OrDefault|_or_default|OrEmpty)$")
    return_types = {"return_statement"}

    @staticmethod
    def _allowlist_success_lines(src: SourceFile) -> set[int]:
        """None 반환 계약에서 허용 목록 성공과 뒤따르는 거절 예외가 명시된 경우만 인정한다."""
        if src.lang is not Lang.PYTHON:
            return set()
        tree = parse_python(src).tree
        if tree is None:
            return set()
        lines = set()
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or not isinstance(fn.returns, ast.Constant) or fn.returns.value is not None:
                continue
            for guard, denial in zip(fn.body, fn.body[1:], strict=False):
                if not isinstance(guard, ast.If) or guard.orelse or not isinstance(denial, ast.Raise):
                    continue
                test = guard.test
                if not isinstance(test, ast.Compare) or len(test.ops) != 1 or not isinstance(test.ops[0], ast.In):
                    continue
                allowed = test.comparators[0]
                if not isinstance(allowed, ast.Name) or not re.search(r"(?i)allow|permitted|authorized", allowed.id):
                    continue
                if len(guard.body) == 1 and isinstance(guard.body[0], ast.Return):
                    value = guard.body[0].value
                    if value is None or isinstance(value, ast.Constant) and value.value is None:
                        lines.add(guard.lineno)
        return lines

    def check(self, src: SourceFile) -> list[Violation]:
        found: list[Violation] = []
        if src.root is None or src.lang in (Lang.RUST, Lang.C, Lang.CPP):
            return found
        allowlist_success = self._allowlist_success_lines(src)
        for fn in iter_functions(src):
            if fn.body is None:
                continue
            if self.or_null.search(fn.name):
                found.append(
                    self.at_node(
                        src,
                        fn.node,
                        f"{fn.name}은(는) 실패를 null·기본값으로 돌려주는 API입니다. 호출부가 실패를 구분하지 못합니다.",
                        severity=Severity.LOW,
                        confidence=Confidence.REVIEW,
                    )
                )
            if not self._sensitive_name(fn.name):
                continue
            result_type = fn.node.child_by_field_name("return_type")
            annotation = src.text_of(result_type) if result_type is not None else ""
            analysis_result = not re.search(r"(?i)auth|pay|charge|transfer|token|credential|login|permission", fn.name)
            # 지적 목록의 빈 값이나 지적 하나의 None은 '찾은 것이 없다'는 결과이지 실패 대체가 아니다
            list_result = analysis_result and bool(re.search(r"list\[(?:Violation|Problem)\]", annotation))
            optional_finding = analysis_result and bool(re.fullmatch(r"\s*(?:(?:Violation|Problem)\s*\|\s*None|None\s*\|\s*(?:Violation|Problem)|Optional\[(?:Violation|Problem)\])\s*", annotation))
            for node in walk_no_nested_functions(fn.body, src.lang):
                if node.type in IF_TYPES:
                    if node.start_point[0] + 1 in allowlist_success:
                        continue
                    block = node.child_by_field_name("consequence")
                    if block is not None and (list_result and src.text_of(block).strip() == "return []" or optional_finding and re.fullmatch(r"return(?:\s+None)?\s*(?:#.*)?", src.text_of(block).strip())):
                        continue
                    violation = self._check_branch(src, fn.name, node)
                    if violation is not None:
                        found.append(violation)
        return found

    def _sensitive_name(self, name: str) -> bool:
        words = [w.lower() for w in self.name_word_re.findall(name)]
        if any(self.sensitive_word.fullmatch(w) or self.sensitive_stem.match(w) for w in words):
            return True
        return any(self.signature_word.fullmatch(w) for w in words) and any(self.signature_context.fullmatch(w) for w in words)

    def _check_branch(self, src: SourceFile, fn_name: str, node: Node) -> Violation | None:
        cond = node.child_by_field_name("condition")
        block = node.child_by_field_name("consequence")
        if cond is None or block is None:
            return None
        cond_text = src.text_of(cond).strip().strip("()").strip()
        critical = re.search(r"(?i)auth|pay|charge|transfer|token|credential|login|permission", fn_name)
        explicit_null = re.search(r"\b(?:null|None|nil|undefined)\b", cond_text)
        if NULL_GUARD_RE.match(cond_text) and (not critical or explicit_null):
            return None  # 단순 null 전파 가드는 실패 대체로 보지 않는다
        stmts = body_statements(block) if block.type in ("block", "statement_block", "compound_statement") else [block]
        if len(stmts) != 1 or stmts[0].type not in self.return_types:
            return None
        if not DEFAULT_VALUE_RE.match(src.text_of(stmts[0])) and src.text_of(stmts[0]).strip() not in ("return", "return;"):
            return None
        if has_throw(src, block) or has_logging(src, block):
            return None
        return self.at_node(
            src,
            node,
            f"{fn_name}에서 조건 실패 시 예외나 로그 없이 기본값을 반환합니다. 실패가 정상 결과처럼 전달됩니다.",
            confidence=Confidence.REVIEW,
        )


class ValidationMessageMismatchRule(BaseRule):
    version = 2
    rule_id = "IL-531"
    name = "입력 검증 조건과 오류 메시지의 불일치 의심"
    iron_law = IronLaw.LAW_3
    severity = Severity.LOW
    gov_standard = None
    plain = "허용 범위가 위아래 두 쪽인데 오류 메시지는 한쪽만 알려 주면, 사용자는 왜 거절됐는지 알 수 없고 검증 규칙이 바뀔 때 메시지가 어긋납니다."
    how_to_fix = "검증 조건의 상·하한을 상수로 두고 오류 메시지에도 같은 상수를 써서 조건과 메시지가 함께 바뀌게 하세요. 예: \"최대 횟수는 {MIN} 이상 {MAX} 이하여야 합니다\""
    number_re = re.compile(r"(?<![\w.])(\d[\d_,]*)(?![\w.])")
    one_sided = re.compile(r"이상|이하|초과|미만|at least|at most|minimum|maximum|greater|less")
    two_sided = re.compile(r"사이|범위|between|range|~|이상[^\n]*이하|이하[^\n]*이상|초과[^\n]*미만|미만[^\n]*초과|min[^\n]*max")

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.root is None or src.is_test:
            return found
        for node in src.nodes:
            if node.type not in IF_TYPES:
                continue
            cond = node.child_by_field_name("condition")
            block = node.child_by_field_name("consequence")
            if cond is None or block is None:
                continue
            # 검사기의 발견 목록에 추가하는 경고는 사용자 입력을 거부하는 메시지가 아니다.
            block_text = src.text_of(block)
            if re.search(r"\.append\(.*(?:at_node|at_line|report)\(", block_text, re.DOTALL) and not has_throw(src, block):
                continue
            cond_text = src.text_of(cond)
            numbers = {n.replace("_", "").replace(",", "") for n in self.number_re.findall(cond_text)}
            numbers.discard("0")
            if len(numbers) < 2 or not re.search(r"\|\||&&|\bor\b|\band\b", cond_text):
                continue
            if len(re.findall(r"<=|>=|<|>", cond_text)) < 2:
                continue
            message = re.search(r"[\"'`]([^\"'`\n]{4,})[\"'`]", src.text_of(block))
            if message is None:
                continue
            text = message.group(1)
            message_numbers = {n.replace("_", "").replace(",", "") for n in self.number_re.findall(text)}
            if numbers <= message_numbers or self.two_sided.search(text) or not self.one_sided.search(text):
                continue
            found.append(
                self.at_node(
                    src,
                    node,
                    f"검증 조건은 두 경계({', '.join(sorted(numbers))})를 두는데 오류 메시지는 한쪽만 안내합니다: {text[:40]}",
                    confidence=Confidence.REVIEW,
                )
            )
        return found
