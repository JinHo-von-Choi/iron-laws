"""injection boundaries 규칙."""
import re

from tree_sitter import Node

from iron_laws.core.models import Confidence, IronLaw, Severity, Violation
from iron_laws.engine.ast_tools import (
    is_literal,
    iter_calls,
)
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import (
    expr_has_source,
    is_tainted,
)
from iron_laws.rules.base import BaseRule
from iron_laws.rules.injection_common import (
    ESCAPER_RE,
    SinkRule,
)
from iron_laws.rules.sinks import (
    JAVA,
    PHP,
    Sink,
)
from iron_laws.standards import mois_ref


class SecurityDecisionInputRule(BaseRule):
    version = 2
    rule_id = "IL-512"
    name = "보안기능 결정에 사용되는 부적절한 입력값 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.HIGH
    gov_standard = mois_ref("1-15")
    plain = "쿠키나 요청 값으로 '관리자인지'를 판단하면 사용자가 값을 바꿔 관리자 행세를 할 수 있습니다."
    how_to_fix = "권한과 역할은 서버 세션이나 서명된 토큰에서 읽으세요. 쿠키·파라미터·헤더에 담긴 값으로 권한을 결정하지 마세요."
    decision_re = re.compile(r"(?i)\b(is_?admin|admin|role|roles|permission|privilege|superuser|is_?staff)\b")
    if_types = {"if_statement", "if_expression", "ternary_expression", "conditional_expression"}

    def check(self, src: SourceFile) -> list[Violation]:
        found: list[Violation] = []
        if src.root is None:
            return found
        for node in src.nodes:
            if node.type not in self.if_types:
                continue
            cond = node.child_by_field_name("condition")
            if cond is None:
                continue
            text = src.text_of(cond)
            if not self.decision_re.search(text):
                continue
            if expr_has_source(src, cond) or self._direct_cookie_flag(src, cond):
                found.append(self.at_node(src, node, "요청 값(쿠키·파라미터·헤더)으로 권한 여부를 판단합니다. 서버 측 세션/토큰 정보를 사용하십시오."))
        return found

    def _direct_cookie_flag(self, src: SourceFile, cond: Node) -> bool:
        return is_tainted(src, cond) and bool(re.search(r"(?i)cookie|header|param|query|body", src.text_of(cond)))


class TrustBoundaryRule(SinkRule):
    version = 2
    rule_id = "IL-526"
    name = "신뢰 경계 위반 (검증 없는 입력을 세션에 저장) 탐지"
    severity = Severity.MEDIUM
    gov_standard = None
    plain = "검증하지 않은 사용자 입력을 세션에 넣으면, 나중에 서버가 그 값을 '믿을 수 있는 값'으로 오해해 권한 판단이나 쿼리에 그대로 쓰게 됩니다."
    how_to_fix = "세션에는 서버가 검증·생성한 값만 저장하세요. 사용자 입력은 형식·범위를 검증한 뒤에 저장하세요."
    dynamic_is_finding = False
    tainted_message = "검증되지 않은 외부 입력이 {callee}로 세션에 저장됩니다."
    sinks = [
        Sink.of(JAVA, r"(?i:session\w*(?:\(\))?)\.(setAttribute|putValue)$", None),
        Sink.of(PHP, r"^(session_id)$", None),
    ]

    def check(self, src: SourceFile) -> list[Violation]:
        found = super().check(src)
        if src.lang is Lang.PYTHON and src.root is not None:
            for node in src.nodes:
                if node.type != "assignment":
                    continue
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is not None and right is not None and re.match(r"session\[", src.text_of(left)):
                    if is_tainted(src, right) and not ESCAPER_RE.search(src.text_of(right)):
                        found.append(self.at_node(src, node, "검증되지 않은 외부 입력이 session에 저장됩니다."))
        if src.lang in JS_FAMILY and src.root is not None:
            for node in src.nodes:
                if node.type == "assignment_expression":
                    left = node.child_by_field_name("left")
                    right = node.child_by_field_name("right")
                    if left is not None and right is not None and re.match(r"req\.session\.", src.text_of(left)):
                        if is_tainted(src, right):
                            found.append(self.at_node(src, node, "검증되지 않은 외부 입력이 req.session에 저장됩니다."))
        return found


class NoSqlInjectionRule(BaseRule):
    version = 2
    rule_id = "IL-533"
    name = "NoSQL 삽입($where·연산자 주입) 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.HIGH
    gov_standard = mois_ref("1-1")
    plain = "MongoDB 같은 NoSQL도 받은 값이 검색 조건에 섞이면 공격자가 {\"$ne\": null} 같은 연산자를 넣어 로그인을 우회하거나 $where에 자바스크립트를 넣어 서버에서 실행시킬 수 있습니다."
    how_to_fix = "$where는 쓰지 말고 일반 연산자로 조건을 만드세요. 외부 값은 문자열·숫자로 형 변환·검증한 뒤 쿼리 객체에 넣고, 요청 본문 전체(req.body)를 그대로 쿼리에 넘기지 마세요."
    receiver_re = re.compile(r"(?i)(collection|\bdb\b|\bdb\.\w+|mongo|\bcoll\b|users?\b|accounts?\b|\w*Dao\b|\w*Col\b)|(?-i:\w+Model\b)")
    query_methods = re.compile(r"^(find|findOne|update|updateOne|updateMany|deleteOne|deleteMany|aggregate|count|countDocuments|findOneAndUpdate|findOneAndDelete|find_one|update_one|update_many|delete_one|delete_many|count_documents)$")
    auth_keys = re.compile(r"(?i)(user(name)?|email|pass(word)?|token|key|login|id)\b")

    def check(self, src: SourceFile) -> list[Violation]:
        if src.root is None or src.lang not in (JS_FAMILY | {Lang.PYTHON, Lang.JAVA}):
            return []
        found = []
        for node in src.nodes:
            if node.type in ("pair", "property_assignment", "dictionary_pair") or (node.type == "pair" and src.lang is Lang.PYTHON):
                v = self._where_pair(src, node)
                if v is not None:
                    found.append(v)
        for call in iter_calls(src):
            if "." not in call.callee or not call.args:
                continue
            receiver, method = call.callee.rsplit(".", 1)
            if not self.query_methods.match(method) or not self.receiver_re.search(receiver):
                continue
            arg = call.args[0]
            if is_literal(arg):
                continue
            text = src.text_of(arg)
            if arg.type in ("object", "dictionary"):
                bad = self._tainted_auth_value(src, arg)
                if bad:
                    found.append(self.at_node(src, call.node, f"외부 입력({bad})이 검증 없이 NoSQL 조회 조건 값으로 쓰입니다. 객체가 들어오면 연산자 주입이 가능합니다.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
            elif arg.type in ("identifier", "member_expression", "attribute", "subscript") and is_tainted(src, arg) and not re.search(r"String\(|str\(|parseInt|Number\(", text):
                found.append(self.at_node(src, call.node, f"{call.callee}의 조회 조건 전체가 외부 입력입니다. 연산자 주입이 가능합니다.", confidence=Confidence.REVIEW))
        return found

    def _where_pair(self, src: SourceFile, node: Node) -> Violation | None:
        key = node.child_by_field_name("key")
        value = node.child_by_field_name("value")
        if key is None or value is None or src.text_of(key).strip("\"'") != "$where":
            return None
        if is_literal(value):
            return None
        tainted = is_tainted(src, value)
        return self.at_node(
            src,
            node,
            "$where에 동적으로 만든 문자열이 들어갑니다. 서버에서 자바스크립트로 실행되어 코드 삽입이 가능합니다.",
            severity=Severity.CRITICAL if tainted else Severity.HIGH,
            confidence=Confidence.CONFIRMED if tainted else Confidence.REVIEW,
        )

    def _tainted_auth_value(self, src: SourceFile, obj: Node) -> str:
        for pair in obj.named_children:
            if pair.type not in ("pair", "dictionary_pair"):
                continue
            key = pair.child_by_field_name("key")
            value = pair.child_by_field_name("value")
            if key is None or value is None or is_literal(value):
                continue
            if self.auth_keys.search(src.text_of(key)) and is_tainted(src, value) and not re.search(r"String\(|str\(|parseInt|Number\(|toString\(", src.text_of(value)):
                return src.text_of(value)[:40]
        return ""
