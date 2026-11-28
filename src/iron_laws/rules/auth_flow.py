"""
오철칙 인증 흐름 규칙: 검증 없이 로그인 상태를 만드는 코드(IL-534), 인증 성공 분기 밖의 실패 기록 초기화(IL-535)

- 로그인 상태 저장: 세션에 로그인 사용자를 넣거나(setAttribute·session[...]·req.session.*), 인증 객체를 정하는 코드
  (setAuthentication·login_user·req.login). 비밀번호를 함께 넘기는 서블릿 로그인(request.login)은 컨테이너가 검증하므로 넣지 않는다.
- 검증: 비밀번호 대조·인증 관리자·서명 토큰 검증 호출, 그리고 본문이 그런 호출로 실패 분기를 끊거나 그 결과를 돌려주는 프로젝트 함수
  (서비스 계층의 로그인 메서드, 2단계까지). 그 호출(또는 그 결과를 담은 변수)이 저장 위치를 감싼 if 조건에 있거나,
  저장 앞에서 실패 시 return·throw로 끝나는 if 조건에 있으면 검증된 것으로 본다.
- 라우트 핸들러 안의 저장은 직접 판정하고, 핸들러가 요청 값을 넘기는 도우미(같은 파일·다른 파일, 2단계)의 저장은 확인 필요로 낸다.
  지적의 evidence에 라우트 핸들러, 도우미까지의 호출, 저장 위치를 차례로 남긴다. 검토 의견 요청은 이 사슬의 함수들을 함께 보낸다.
- login_state_judgments와 verified_login_stores는 IL-526이 같은 줄의 중복 지적과, 검증 뒤에 로그인 사용자를 넣는 저장을 거를 때도 쓴다.
작성자: 최진호
작성일: 2026-11-23
"""

import re
from dataclasses import dataclass, field

from tree_sitter import Node

from iron_laws.core.models import Confidence, EvidenceStep, IronLaw, Severity, Violation
from iron_laws.engine.ast_tools import (
    Call,
    enclosing_function,
    iter_calls,
    iter_functions,
    walk,
)
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import is_tainted, param_name, resolve_any
from iron_laws.engine.taint.nodes import if_parts
from iron_laws.rules.base import BaseRule
from iron_laws.rules.guards import _negated, _or_terms
from iron_laws.standards import mois_ref

CREDENTIAL_CHECK = re.compile(
    r"(?i)\b(?:password_?encoder|encoder|passwordHasher|hasher)\.(?:matches|verify)\b|\bcheckpw\b|\bcheck_password(?:_hash)?\b|\bverify_password\b|"
    r"\bbcrypt\.compare(?:Sync)?\b|\bargon2\.verify\b|authenticationManager\.authenticate\b|\bauthenticate\s*\(|\bisPasswordValid\b|"
    r"\b(?:validate|check|verify|match)Password\w*\b|\bpasswordMatches\b|\bjwt\.verify\b|\bJwts\.parser|\bparseClaimsJws\b|\bverifyToken\b|"
    r"\bVerifyHashedPassword\b|\bPasswordSignInAsync\b|\bCheckPasswordAsync\b"
)
LOGIN_KEY = re.compile(r"(?i)login|user|member|auth|account|principal|admin|manager|operator|staff")
JAVA_SESSION_SET = re.compile(r"(?i:session\w*(?:\(\w*\))?)\.(?:setAttribute|putValue)$")
SET_AUTHENTICATION = re.compile(r"(?:^|\.)setAuthentication$")
PY_LOGIN = re.compile(r"(?:^|\.)login_user$")
JS_LOGIN = re.compile(r"^req\.(?:login|logIn)$")
TOKEN_COMPARE = re.compile(r"(?i)(?:token|ticket|nonce|key|code)\w*\s*\)?\s*(?:\.equals(?:IgnoreCase)?\(|===?)|\.equals(?:IgnoreCase)?\(\s*[\w.]*(?:token|ticket|nonce|key|code)")
EXIT_RE = re.compile(r"\b(return|throw|raise|abort)\b")
IF_TYPES = frozenset({"if_statement", "if_expression"})
FAIL_EXIT = re.compile(r"\b(?:throw|raise)\b|\breturn\s*(?:null|None|false|False|nil|undefined)?\s*(?:;|\}|$)")
SUCCESS_NAME = re.compile(r"(?i)success|loginok|afterlogin|onauth|authenticated")


@dataclass
class LoginJudgment:
    src: SourceFile
    node: Node
    severity: Severity
    confidence: Confidence
    message: str
    chain: list[EvidenceStep] = field(default_factory=list)  # 라우트 핸들러 → 도우미 호출 → 로그인 상태 저장

    @property
    def key(self) -> tuple[str, int]:
        return self.src.path.as_posix(), self.src.line_of(self.node)


def _inside(node: Node, outer: Node) -> bool:
    return outer.start_byte <= node.start_byte and node.end_byte <= outer.end_byte


def login_sinks(src: SourceFile, scope: Node) -> list[tuple[Node, Node]]:
    """scope 안의 로그인 상태 저장 (저장 위치 노드, 저장하는 값 노드)"""
    found: list[tuple[Node, Node]] = []
    for call in iter_calls(src):
        if not _inside(call.node, scope) or not call.args:
            continue
        callee = call.callee
        if src.lang in (Lang.JAVA, Lang.KOTLIN):
            if JAVA_SESSION_SET.search(callee) and len(call.args) >= 2 and LOGIN_KEY.search(src.text_of(call.args[0])):
                found.append((call.node, call.args[1]))
            elif SET_AUTHENTICATION.search(callee):  # request.login(아이디, 비밀번호)는 컨테이너가 비밀번호를 확인하므로 저장 위치로 보지 않는다
                found.append((call.node, call.args[0]))
        elif src.lang is Lang.PYTHON:
            if PY_LOGIN.search(callee):
                found.append((call.node, call.args[0]))
            elif callee in ("login", "auth.login", "django.contrib.auth.login") and len(call.args) >= 2:
                found.append((call.node, call.args[1]))
        elif src.lang in JS_FAMILY and JS_LOGIN.search(callee):
            found.append((call.node, call.args[0]))
    for node in walk(scope):
        if node.type not in ("assignment", "assignment_expression"):
            continue
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        if left is None or right is None:
            continue
        text = src.text_of(left)
        if src.lang is Lang.PYTHON and (m := re.match(r"session\[\s*['\"](\w+)", text)) and LOGIN_KEY.search(m.group(1)):
            found.append((node, right))
        elif src.lang in JS_FAMILY and (m := re.match(r"req\.session\.(\w+)", text)) and LOGIN_KEY.search(m.group(1)):
            found.append((node, right))
    return found


def _assigned_names(src: SourceFile, node: Node) -> list[str]:
    if node.type in ("variable_declarator",):
        name = node.child_by_field_name("name")
        return [src.text_of(name)] if name is not None else []
    if node.type in ("assignment", "assignment_expression"):
        left = node.child_by_field_name("left")
        return [src.text_of(left)] if left is not None and left.type == "identifier" else []
    return []


def _verifies(src: SourceFile, fn: Node, depth: int) -> bool:
    """fn 본문이 자격 증명을 확인한다: 검증이 실패하면 실패 값으로 끝내거나(`if (!matches) return null`),
    성공할 때만 값을 돌려주는(`if (matches) return user`) 분기가 있거나, 검증 호출 결과를 돌려준다"""
    for node in walk(fn):
        if node.type in IF_TYPES:
            cond, consequence = if_parts(node)
            if cond is None or consequence is None or not EXIT_RE.search(src.text_of(consequence)):
                continue
            fails = bool(FAIL_EXIT.search(src.text_of(consequence)))
            if any(_is_check(src, t, depth) and (_negated(t) is not None) == fails for t in _or_terms(src, cond)):  # iron-laws: ignore[IL-307] 검증 함수인지 판정한 결과다
                return True
        elif node.type == "return_statement" and _is_check(src, node, depth):
            return True
    return False


def _calls_verifier(src: SourceFile, node: Node, depth: int) -> bool:
    """node 안의 호출 가운데 자격 증명을 확인하는 프로젝트 함수(서비스 계층의 로그인 메서드 등)가 있다"""
    if depth <= 0:  # iron-laws: ignore[IL-307] 따라갈 단계가 남지 않았다는 판정 결과다
        return False
    for call in iter_calls(src):
        if not _inside(call.node, node):
            continue
        for hsrc, fn in resolve_any(src, call.callee, len(call.args), at=call.node):
            if fn.node.id != node.id and _verifies(hsrc, fn.node, depth - 1):  # iron-laws: ignore[IL-307] 검증 함수를 부른다는 판정 결과다
                return True
    return False


def _is_check(src: SourceFile, node: Node, depth: int = 2) -> bool:
    return bool(CREDENTIAL_CHECK.search(src.text_of(node))) or _calls_verifier(src, node, depth)


def _check_vars(src: SourceFile, fn: Node, before: int) -> set[str]:
    """fn 안에서 before 앞에 검증 호출 결과를 담은 변수 이름"""
    names: set[str] = set()
    for node in walk(fn):
        if node.start_byte >= before or node.type not in ("variable_declarator", "assignment", "assignment_expression"):
            continue
        value = node.child_by_field_name("value") or node.child_by_field_name("right")
        if value is not None and _is_check(src, value):
            names.update(_assigned_names(src, node))
    return names


def _mentions(text: str, names: set[str]) -> bool:
    return any(re.search(rf"(?<![\w.]){re.escape(n)}\b", text) for n in names)


def guard_status(src: SourceFile, target: Node, fn: Node, value: Node | None = None) -> str:
    """target(저장·초기화 위치)이 검증에 묶였는지: checked / token / unbound / none"""
    check_vars = _check_vars(src, fn, target.start_byte)
    enclosing: list[Node] = []
    node = target.parent
    while node is not None and node.id != fn.id:
        if node.type in IF_TYPES:
            cond, consequence = if_parts(node)
            if cond is not None and consequence is not None and _inside(target, consequence):
                enclosing.append(cond)
        node = node.parent
    conditions = [src.text_of(c) for c in enclosing]
    if any(_is_check(src, c) or _mentions(src.text_of(c), check_vars) for c in enclosing):
        return "checked"
    for node in walk(fn):
        if node.type not in IF_TYPES or node.end_byte > target.start_byte:
            continue
        cond, consequence = if_parts(node)
        if cond is None or consequence is None:
            continue
        if EXIT_RE.search(src.text_of(consequence)) and (_mentions(src.text_of(cond), check_vars) or _is_check(src, cond)):
            return "checked"
    if value is not None and _mentions(src.text_of(value), check_vars):
        return "checked"
    if any(TOKEN_COMPARE.search(c) for c in conditions):
        return "token"
    before = src.data[fn.start_byte : target.start_byte].decode("utf-8", "replace")
    if CREDENTIAL_CHECK.search(before):
        return "unbound"
    return "none"


def _helpers(src: SourceFile, scope: Node, depth: int = 2) -> list[tuple[SourceFile, Node, frozenset[str], tuple[tuple[SourceFile, Call], ...]]]:
    """scope 안의 호출 가운데 외부 입력을 매개변수로 넘기는 프로젝트 함수 (함수 파일, 함수 노드, 오염된 매개변수, 핸들러에서 그 함수까지의 호출들)"""
    out: list[tuple[SourceFile, Node, frozenset[str], tuple[tuple[SourceFile, Call], ...]]] = []
    work: list[tuple[SourceFile, Node, frozenset[str], tuple[tuple[SourceFile, Call], ...], int]] = [(src, scope, frozenset(), (), 0)]
    seen: set[tuple[str, int]] = set()
    while work:
        fsrc, fnode, seeds, path, level = work.pop()
        if level >= depth:
            continue
        for call in iter_calls(fsrc):
            if not _inside(call.node, fnode) or call.node.id == fnode.id:
                continue
            for hsrc, fn in resolve_any(fsrc, call.callee, len(call.args)):
                key = (hsrc.path.as_posix(), fn.node.start_byte)
                if key in seen or fn.node.id == fnode.id:
                    continue
                params = [p for p in fn.params if hsrc.text_of(p) not in ("self", "cls")]
                tainted = frozenset(
                    name for p, a in zip(params, call.args, strict=False) if (name := param_name(hsrc, p)) and is_tainted(fsrc, a, seeds=seeds)
                )
                if not tainted:
                    continue
                seen.add(key)
                here = (*path, (fsrc, call))
                out.append((hsrc, fn.node, tainted, here))
                work.append((hsrc, fn.node, tainted, here, level + 1))
    return out


def _judge(status: str, route_auth: str, direct: bool) -> tuple[Severity, Confidence, str] | None:
    if status == "checked":
        return None
    if status == "token":
        return (Severity.MEDIUM if route_auth == "yes" else Severity.HIGH), Confidence.REVIEW, (
            "저장된 토큰과 요청 값만 비교한 뒤 로그인 상태를 만듭니다. 토큰의 만료·1회 사용·재인증 확인이 보이지 않습니다."
        )
    if status == "unbound":
        return Severity.HIGH, Confidence.REVIEW, "검증 호출은 있지만 그 결과가 로그인 상태를 만드는 조건으로 쓰이지 않습니다."
    if route_auth == "yes":
        return Severity.MEDIUM, Confidence.REVIEW, "로그인한 사용자가 요청 값으로 다른 사용자의 로그인 상태를 만들 수 있습니다. 관리자 전용 기능인지 확인하십시오."
    if direct and route_auth == "no":
        return Severity.CRITICAL, Confidence.CONFIRMED, "로그인 없이 호출되는 라우트가 요청 값으로 조회한 사용자를 비밀번호·토큰 검증 없이 로그인 상태로 만듭니다."
    return Severity.HIGH, Confidence.REVIEW, "요청 값으로 조회한 사용자를 검증 없이 로그인 상태로 만드는 것으로 보입니다. 이 라우트가 로그인을 요구하는지 확인하십시오."


def _stored(src: SourceFile, node: Node) -> EvidenceStep:
    return EvidenceStep(role="sink", file_path=src.path.as_posix(), line=src.line_of(node), note="로그인 상태 저장")


def login_state_judgments(project: ProjectContext) -> list[LoginJudgment]:
    cached = project.cache.get("login_judgments")
    if cached is not None:
        return cached
    by_path = {f.path.as_posix(): f for f in project.source_files()}
    found: dict[tuple[str, int], LoginJudgment] = {}
    verified: set[tuple[str, int]] = set()
    for route in project.routes():
        src = by_path.get(route.file)
        if src is None or route.node is None:
            continue
        scope = route.node
        handler = EvidenceStep(role="source", file_path=route.file, line=src.line_of(scope), note=f"{route.method} {route.path} 라우트 핸들러")
        for sink, value in login_sinks(src, scope):
            if not is_tainted(src, value):
                continue
            status = guard_status(src, sink, scope, value)
            if status == "checked":
                verified.add((src.path.as_posix(), src.line_of(sink)))
            judged = _judge(status, route.auth, direct=True)
            if judged is not None:
                j = LoginJudgment(src, sink, *judged, chain=[handler, _stored(src, sink)])
                found.setdefault(j.key, j)
        handler_text_before = src.text_of(scope)
        for hsrc, fn, seeds, path in _helpers(src, scope):
            first = path[0][1]
            for sink, value in login_sinks(hsrc, fn):
                if not is_tainted(hsrc, value, seeds=seeds):
                    continue
                status = guard_status(hsrc, sink, fn, value)
                if status in ("none", "token") and CREDENTIAL_CHECK.search(handler_text_before[: first.node.start_byte - scope.start_byte]):
                    status = "checked"
                if status == "checked":
                    verified.add((hsrc.path.as_posix(), hsrc.line_of(sink)))
                judged = _judge(status, route.auth, direct=False)
                if judged is not None:
                    sev, _conf, msg = judged
                    calls = [EvidenceStep(role="propagation", file_path=c_src.path.as_posix(), line=c.line, note=f"{c.callee} 호출") for c_src, c in path]
                    j = LoginJudgment(
                        hsrc, sink, sev if sev is not Severity.CRITICAL else Severity.HIGH, Confidence.REVIEW,
                        f"{route.method} {route.path} 라우트에서 넘어온 값으로: {msg}", chain=[handler, *calls, _stored(hsrc, sink)],
                    )
                    found.setdefault(j.key, j)
    result = sorted(found.values(), key=lambda j: j.key)
    project.cache["login_judgments"] = result
    project.cache["login_verified"] = verified - set(found)
    return result


def verified_login_stores(project: ProjectContext) -> set[tuple[str, int]]:
    """비밀번호 대조·서명 토큰 검증에 묶인 로그인 상태 저장 위치 (파일, 줄). IL-526이 이 줄을 검증 없는 저장으로 내지 않을 때 쓴다"""
    login_state_judgments(project)
    return project.cache["login_verified"]


def il534_active(config) -> bool:
    if config is None:
        return True
    names = {LoginStateRule.rule_id, LoginStateRule.name}
    enabled = config.enabled_rules
    if enabled is not None and not names & set(enabled):
        return False
    return not names & set(config.disabled_rules)


class LoginStateRule(BaseRule):
    rule_id = "IL-534"
    name = "검증 없이 로그인 상태를 만드는 코드 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.CRITICAL
    gov_standard = mois_ref("2-1")
    plain = "로그인 확인 없이 호출되는 주소가 요청에 담긴 아이디로 회원을 찾아 세션에 넣으면, 누구나 아이디만 알면 그 사람으로 로그인됩니다."
    how_to_fix = (
        "로그인 상태는 비밀번호 대조(passwordEncoder.matches 등)나 서명 토큰 검증이 성공한 분기 안에서만 만드세요. "
        "다른 시스템에서 넘어오는 전환은 서명·만료·1회 사용을 확인하는 토큰으로 처리하고, 비밀번호 변경 미루기 같은 부가 기능이 세션을 만들지 않게 하세요."
    )

    def check_project(self, project: ProjectContext) -> list[Violation]:
        found = []
        for j in login_state_judgments(project):
            v = self.at_node(j.src, j.node, j.message, severity=j.severity, confidence=j.confidence)
            v.evidence = list(j.chain)
            found.append(v)
        return found


RESET_CALL = re.compile(r"(?i)^(?:reset|clear|init|initialize)\w*(?:fail|lock|attempt|retry)\w*$|^unlock\w*$")
FAIL_SETTER = re.compile(r"(?i)^set\w*(?:fail|attempt|retry)\w*$")
LOCK_SETTER = re.compile(r"(?i)^set\w*lock\w*$")
CLEARED_VALUE = re.compile(r"""^(?:0|0L|false|False|["']?[N0]["']?)$""")
DEFAULT_FAIL_COLUMN = re.compile(r"(?i)fail|^lock|^locked$|retry|attempt")


class FailResetRule(BaseRule):
    rule_id = "IL-535"
    name = "인증 성공 분기 밖에서 로그인 실패 기록을 초기화하는 코드 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.HIGH
    gov_standard = mois_ref("2-16")
    plain = "비밀번호를 여러 번 틀리면 계정을 잠그더라도, 다른 주소가 실패 횟수와 잠금을 0으로 되돌리면 공격자는 그 주소를 번갈아 불러 무제한으로 비밀번호를 대입할 수 있습니다."
    how_to_fix = "실패 횟수와 잠금 상태는 비밀번호 대조가 성공한 분기, 또는 권한을 확인한 관리자 잠금 해제 기능에서만 초기화하세요."

    def _fail_column(self, name: str) -> bool:
        extra = {c.lower() for c in (self.config.auth.fail_columns if self.config is not None else [])}
        return bool(DEFAULT_FAIL_COLUMN.search(name)) or name.lower() in extra

    def _resets(self, project: ProjectContext, src: SourceFile, call: Call) -> bool:
        method = call.callee.rsplit(".", 1)[-1]
        if RESET_CALL.search(method):
            return True
        arg = src.text_of(call.args[0]).strip() if len(call.args) == 1 else ""
        if (FAIL_SETTER.search(method) or LOCK_SETTER.search(method)) and CLEARED_VALUE.match(arg):
            return True
        statement = project.mappers().resolve(src, call)
        if statement is not None and statement.kind == "update":
            return any(self._fail_column(col) and CLEARED_VALUE.match(val.strip()) for col, val in statement.assignments.items())
        return False

    def _callers_checked(self, src: SourceFile, fn_name: str) -> bool:
        sites = [c for c in iter_calls(src) if c.callee.rsplit(".", 1)[-1] == fn_name]
        if not sites:
            return False
        for c in sites:
            outer = enclosing_function(c.node, src.lang)
            if outer is None or guard_status(src, c.node, outer) != "checked":  # iron-laws: ignore[IL-307] 검증에 묶이지 않은 호출 위치가 하나라도 있다는 판정이다
                return False
        return True

    def check_project(self, project: ProjectContext) -> list[Violation]:
        found: list[Violation] = []
        routes = {(r.file, r.node.start_byte): r for r in project.routes() if r.node is not None}
        for src in project.source_files():
            if src.lang not in (Lang.JAVA, Lang.KOTLIN, Lang.PYTHON, *JS_FAMILY, Lang.CSHARP):
                continue
            names = {fn.node.start_byte: fn.name for fn in iter_functions(src)}
            for call in iter_calls(src):
                fn = enclosing_function(call.node, src.lang)
                if fn is None or not self._resets(project, src, call):
                    continue
                fn_name = names.get(fn.start_byte, "")
                if SUCCESS_NAME.search(fn_name) or guard_status(src, call.node, fn) == "checked":
                    continue
                route = routes.get((src.path.as_posix(), fn.start_byte))
                if route is None and fn_name and self._callers_checked(src, fn_name):
                    continue
                if route is not None and route.auth == "yes":
                    found.append(self.at_node(src, call.node, "로그인한 사용자가 쓰는 기능에서 로그인 실패 기록을 초기화합니다. 관리자 잠금 해제처럼 권한을 확인한 기능인지 확인하십시오.", severity=Severity.LOW, confidence=Confidence.REVIEW))
                    continue
                where = f"{route.method} {route.path} 라우트" if route is not None else f"함수 {fn_name or '(이름 없음)'}"
                found.append(self.at_node(src, call.node, f"{where}가 비밀번호 대조 성공 분기 밖에서 로그인 실패 횟수·잠금 상태를 초기화합니다.", confidence=Confidence.REVIEW))
        return found
