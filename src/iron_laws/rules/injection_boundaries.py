"""injection boundaries 규칙."""
import re

from tree_sitter import Node

from iron_laws.core.models import Confidence, IronLaw, Severity, Violation
from iron_laws.engine.ast_tools import (
    enclosing_function,
    is_literal,
    iter_calls,
)
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import (
    Ctx,
    expr_has_source,
    is_tainted,
)
from iron_laws.engine.xfile_python import imports, qualified_name
from iron_laws.rules.auth_flow import il534_active, login_state_judgments
from iron_laws.rules.base import BaseRule
from iron_laws.rules.injection_common import (
    SinkRule,
)
from iron_laws.rules.sinks import (
    JAVA,
    PHP,
    Sink,
)
from iron_laws.standards import mois_ref

# 2단계 인증의 발송·확인 호출: 동작(send·verify 등)과 인증 수단(sms·otp 등)이 함께 든 이름
FACTOR_CALL = re.compile(
    r"(?i)(?:send|issue|verify|check|confirm|request|validate)\w*(?:sms|otp|totp|mfa|2fa|code|certif|authnum)|"
    r"(?:sms|otp|totp|mfa|2fa|certif|authnum)\w*(?:send|issue|verify|check|confirm|validate)"
)
SESSION_USER = re.compile(
    r"\bHttpSession\b|\bPrincipal\s+\w+|@AuthenticationPrincipal|\bAuthentication\s+\w+\s*[,)]|getSession\(|session\.getAttribute|"
    r"\brequest\.user\b|\bcurrent_user\b|\breq\.user\b|\breq\.session\b|\bsession\["
)
USER_ARG = re.compile(r"(?i)user|member|account|login|phone|mobile|target|(?:^|_)id$|Id$")


class SecurityDecisionInputRule(BaseRule):
    version = 3
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
        found.extend(self._factor_target(src))
        return found

    def _factor_target(self, src: SourceFile) -> list[Violation]:
        """세션의 로그인 사용자를 쓸 수 있는 핸들러가 2단계 인증 대상(발송·확인할 사용자)을 요청 값으로 정하는 경우"""
        found: list[Violation] = []
        for call in iter_calls(src):
            if not FACTOR_CALL.search(call.callee.rsplit(".", 1)[-1]):
                continue
            fn = enclosing_function(call.node, src.lang)
            if fn is None or not SESSION_USER.search(src.text_of(fn)):
                continue
            target = next((a for a in call.args if USER_ARG.search(src.text_of(a)) and not is_literal(a) and is_tainted(src, a)), None)
            if target is None:
                continue
            found.append(
                self.at_node(
                    src,
                    call.node,
                    f"2단계 인증 대상을 요청 값({src.text_of(target)})으로 정합니다. 세션의 로그인 사용자로 정하십시오.",
                    confidence=Confidence.REVIEW,
                    how_to_fix="인증번호 발송·확인 대상은 요청 파라미터가 아니라 1단계 로그인을 마친 세션의 사용자로 정하세요. 1단계가 끝나지 않은 세션은 2단계 요청을 거부하세요.",
                )
            )
        return found

    def _direct_cookie_flag(self, src: SourceFile, cond: Node) -> bool:
        return is_tainted(src, cond) and bool(re.search(r"(?i)cookie|header|param|query|body", src.text_of(cond)))


class TrustBoundaryRule(SinkRule):
    version = 4
    rule_id = "IL-526"
    # 세션에 저장하는 값은 출력 문맥이 정해지지 않았다. HTML·SQL 이스케이프 같은 문맥 정제는 검증이 아니므로 값의 종류를 바꾸는 정제와 검증만 인정한다
    taint_ctx = Ctx.CODE
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
        # IL-534가 켜져 있으면 같은 줄을 IL-534가 더 정확히 지적할 수 있어 프로젝트 단위(check_project)에서 함께 판정한다
        if il534_active(self.config):
            return []
        return self._file_check(src)

    def check_project(self, project: ProjectContext) -> list[Violation]:
        if not il534_active(self.config):
            return []
        taken = {j.key for j in login_state_judgments(project)}
        found: list[Violation] = []
        for src in project.source_files(include_tests=self.include_tests):
            found.extend(v for v in self._file_check(src) if (v.file_path.as_posix(), v.line_number) not in taken)
        return found

    def _file_check(self, src: SourceFile) -> list[Violation]:
        found = super().check(src)
        if src.lang is Lang.PYTHON and src.root is not None:
            found.extend(self._python_session_writes(src))
        if src.lang in JS_FAMILY and src.root is not None:
            for node in src.nodes:
                if node.type == "assignment_expression":
                    left = node.child_by_field_name("left")
                    right = node.child_by_field_name("right")
                    if left is not None and right is not None and re.match(r"req\.session\.", src.text_of(left)):
                        if is_tainted(src, right, ctx=self.taint_ctx):
                            found.append(self.at_node(src, node, "검증되지 않은 외부 입력이 req.session에 저장됩니다."))
        return found


    PY_WEB_SESSIONS = frozenset({"flask.session", "quart.session"})

    def _python_session_object(self, src: SourceFile, obj: Node) -> bool:
        """식이 웹 세션 객체인지: Flask·Quart의 session(import로 확인), Django 요청 객체의 request.session.
        import로 묶이지 않은 이름 session은 예전처럼 세션으로 본다. 다른 모듈에서 가져온 session은 세션이 아니다"""
        text = src.text_of(obj)
        if text == "session":
            return "session" not in imports(src) or qualified_name(src, text) in self.PY_WEB_SESSIONS
        if obj.type != "attribute" or not text.endswith(".session"):
            return False
        return qualified_name(src, text) in self.PY_WEB_SESSIONS or re.fullmatch(r"(?:self\.)?request\.session", text) is not None

    def _python_session_writes(self, src: SourceFile) -> list[Violation]:
        """`session[키] = 값`은 키와 값의 오염을 따로 판정해 어느 쪽인지 문구에 적는다. `session.update(...)`는 인자를 본다"""
        found = []
        for node in src.nodes:
            if node.type == "assignment":
                left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
                if left is None or right is None or left.type != "subscript":
                    continue
                obj, key = left.child_by_field_name("value"), left.child_by_field_name("subscript")
                if obj is None or not self._python_session_object(src, obj):
                    continue
                parts = []
                if key is not None and not is_literal(key) and is_tainted(src, key, ctx=self.taint_ctx):
                    parts.append("키")
                if not is_literal(right) and is_tainted(src, right, ctx=self.taint_ctx):
                    parts.append("값")
                if parts:
                    where = "키와 값으로" if len(parts) == 2 else ("키로" if parts == ["키"] else "값으로")
                    found.append(self.at_node(src, node, f"검증되지 않은 외부 입력이 session의 {where} 저장됩니다."))
        for call in iter_calls(src):
            if not call.callee.endswith(".update") or not call.args:
                continue
            function = call.node.child_by_field_name("function")
            obj = function.child_by_field_name("object") if function is not None else None
            if obj is None or not self._python_session_object(src, obj):
                continue
            if any(not is_literal(a) and is_tainted(src, a, ctx=self.taint_ctx) for a in call.args):
                found.append(self.at_node(src, call.node, "검증되지 않은 외부 입력이 session.update로 세션에 저장됩니다."))
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
