"""
오철칙 소속(테넌트) 경계·요청 처리 규칙: 상태 변경을 GET으로 처리(AI-124), 요청 값으로 정한 조회 건수에 상한 없음(AI-125),
소속 키 없는 조회·변경(AI-129)

- AI-129는 설정의 tenancy(keys·principal)가 있을 때만 판정한다. MyBatis 매퍼 문장(engine/mybatis.py)을 Java 호출에 이어
  WHERE의 소속 열과 그 열에 바인딩한 값의 출처(로그인 사용자·요청 값·알 수 없음)를 본다.
  요청 값이라도 호출 앞에서 그 값을 로그인 사용자의 소속과 비교해 다르면 실행을 끊으면(직접 비교, 또는 본문이 그렇게 비교하는
  프로젝트 함수) 확인된 값(checked)으로 본다.
- tenancy_rows는 `iron-laws tenancy` 명령의 조회문별 소속 확인 표를 만든다.
작성자: 최진호
작성일: 2026-11-23
"""

import re
from dataclasses import dataclass

from tree_sitter import Node

from iron_laws.core.models import Confidence, IronLaw, Severity, Violation
from iron_laws.engine.ast_tools import Call, enclosing_function, iter_calls, walk
from iron_laws.engine.languages import Lang
from iron_laws.engine.mybatis import MapperStatement
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import is_tainted, param_name, reaching_definitions, resolve_any
from iron_laws.engine.taint.nodes import if_parts
from iron_laws.rules.ai_code_common import AiRule
from iron_laws.rules.auth_flow import login_sinks
from iron_laws.rules.guards import (
    _negated,
    _or_terms,
    _unwrap,
    redefined_between,
    runs_before,
    terminates,
)

STATE_CHANGE_CALL = re.compile(r"(?i)^(?:delete|remove|approve|cancel|switch|change|update|modify|reset|withdraw|transfer|insert|save|create|register|regist|grant|revoke|assign)\w*")
READ_ONLY_HINT = re.compile(r"(?i)view|hit|read|count|access|visit|log|history|cache|lastlogin|stat|touch")
LIMIT_BINDING = re.compile(r"(?i)\b(?:limit|rownum\s*<=?|fetch\s+first|top|offset\s+\S+\s+rows\s+fetch\s+next)\s*\(?\s*#\{\s*(\w+)")
LIMIT_METHODS = frozenset({"limit", "setMaxResults", "take", "setFetchSize", "paginate"})
BOUND_CALL = re.compile(r"\bMath\.min\b|\bmin\s*\(|\bclamp\b|\bcoerceAtMost\b|\bMIN\s*\(")


def _inside(node: Node, outer: Node) -> bool:
    return outer.start_byte <= node.start_byte and node.end_byte <= outer.end_byte


def _calls_in(src: SourceFile, scope: Node) -> list[Call]:
    return [c for c in iter_calls(src) if _inside(c.node, scope)]


class GetStateChangeRule(AiRule):
    rule_id = "AI-124"
    name = "상태 변경·권한 전환을 GET 요청으로 처리"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    plain = "주소를 여는 것만으로 계정 전환·삭제·승인이 일어나면, 다른 사이트에 심은 이미지 태그나 링크 하나로 로그인한 사용자가 모르는 사이에 그 기능이 실행됩니다(CSRF)."
    how_to_fix = "데이터를 바꾸거나 세션 사용자를 바꾸는 기능은 POST·PUT·DELETE로만 받고, 위조 요청 방지 토큰(CSRF)을 확인하세요."

    def check_project(self, project: ProjectContext) -> list[Violation]:
        found: list[Violation] = []
        by_path = {f.path.as_posix(): f for f in project.source_files()}
        mappers = project.mappers()
        for route in project.routes():
            src = by_path.get(route.file)
            if route.method != "GET" or src is None or route.node is None:
                continue
            reason, node, confidence = None, None, Confidence.CONFIRMED
            sinks = login_sinks(src, route.node)
            if sinks:
                reason, node = "세션의 로그인 사용자를 바꿉니다", sinks[0][0]
            else:
                for call in _calls_in(src, route.node):
                    statement = mappers.resolve(src, call)
                    if statement is not None and statement.kind in ("insert", "update", "delete"):
                        reason, node = f"매퍼 {statement.kind.upper()} 문장({statement.id})을 실행합니다", call.node
                        break
                    method = call.callee.rsplit(".", 1)[-1]
                    if STATE_CHANGE_CALL.match(method) and not READ_ONLY_HINT.search(method) and "." in call.callee:
                        reason, node, confidence = f"상태를 바꾸는 이름의 호출({method})이 있습니다", call.node, Confidence.REVIEW
                        break
            if reason is None:
                continue
            found.append(self.at_node(src, node, f"GET {route.path} 라우트가 {reason}. GET 요청은 링크·이미지로도 보내지므로 위조 요청을 막을 수 없습니다.", confidence=confidence))
        return found


class UnboundedPageSizeRule(AiRule):
    rule_id = "AI-125"
    name = "요청 값으로 정한 조회 건수에 상한 없음"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    plain = "한 번에 가져올 건수를 요청 값 그대로 쓰면 공격자가 size=100000처럼 보내 계좌·거래 목록 전체를 한 번에 빼 가거나 서버를 멈출 수 있습니다."
    how_to_fix = "건수는 서버가 정한 상한으로 자르세요. 예: int size = Math.min(requested, 100) / @Max(100)과 @Validated / limit = min(int(request.args['size']), 100)"

    def _bounded(self, src: SourceFile, fn: Node, arg: Node) -> bool:
        text = src.text_of(arg)
        if BOUND_CALL.search(text):
            return True
        if arg.type != "identifier":
            return False
        name = text
        for d in reaching_definitions(src, fn, name, arg.start_byte):
            if BOUND_CALL.search(src.text_of(d)):
                return True
        for node in walk(fn):
            if node.type != "if_statement" or node.end_byte > arg.start_byte:
                continue
            cond, body = if_parts(node)
            if cond is not None and body is not None and re.search(rf"\b{re.escape(name)}\b\s*[<>]", src.text_of(cond)) and re.search(rf"\b{re.escape(name)}\s*=[^=]|\b(return|throw|raise)\b", src.text_of(body)):
                return True
        header = src.data[fn.start_byte : (fn.child_by_field_name("body") or fn).start_byte].decode("utf-8", "replace")
        return bool(re.search(rf"@Max\([^)]*\)\s*(?:@\w+(?:\([^)]*\))?\s*)*[\w<>]+\s+{re.escape(name)}\b", header)) and "@Validated" in src.text

    @staticmethod
    def _size_args(src: SourceFile, call: Call, statement: MapperStatement | None, params: list[str] | None = None) -> list[Node]:
        """조회 건수로 쓰이는 인자: 매퍼 문장의 LIMIT 바인딩, PageRequest.of의 크기, limit()·setMaxResults() 등의 인자"""
        if statement is not None:
            bindings = set(LIMIT_BINDING.findall(statement.sql))
            if params:
                return [call.args[i] for i, name in enumerate(params) if name in bindings and i < len(call.args)]
            return [a for a in call.args if src.text_of(a) in bindings]
        method = call.callee.rsplit(".", 1)[-1]
        if call.callee.endswith("PageRequest.of") and len(call.args) >= 2:
            return [call.args[1]]
        if method in LIMIT_METHODS and call.args:
            return [call.args[0]]
        return []

    def check_project(self, project: ProjectContext) -> list[Violation]:
        found: list[Violation] = []
        by_path = {f.path.as_posix(): f for f in project.source_files()}
        catalog = project.mappers()
        for route in project.routes():
            src = by_path.get(route.file)
            if src is None or route.node is None:
                continue
            for call in _calls_in(src, route.node):
                statement = catalog.resolve(src, call)
                params = catalog.bindings_of(statement) if statement is not None else None
                for arg in self._size_args(src, call, statement, params):
                    if not is_tainted(src, arg) or self._bounded(src, route.node, arg):
                        continue
                    found.append(
                        self.at_node(src, call.node, f"요청 값({src.text_of(arg)})이 상한 없이 조회 건수로 쓰입니다.", confidence=Confidence.REVIEW)
                    )
                    break
        return found


@dataclass
class TenancyRow:
    mapper: str
    statement: str
    kind: str
    tables: str
    key_column: str  # where / optional / missing / n/a
    binding: str
    source: str  # principal / checked / request / unknown / -
    call: str
    verdict: str  # ok / violation / review / n/a

    def as_row(self) -> dict:
        return dict(self.__dict__)


def _target_tables(project: ProjectContext) -> set[str]:
    settings = project.config.tenancy
    if settings.tables:
        return {t.lower() for t in settings.tables}
    keys = {k.lower() for k in settings.keys}
    tables: set[str] = set()
    for src in project.by_kind("sql"):
        for m in re.finditer(r"(?is)create\s+table\s+(?:if\s+not\s+exists\s+)?(?:\w+\.)?\"?(\w+)\"?\s*\((.*?)\)\s*;", src.text):
            if any(re.search(rf"(?i)\b{re.escape(k)}\b", m.group(2)) for k in keys):
                tables.add(m.group(1).lower())
    for st in project.mappers().statements():
        if keys & (set(st.where) | set(st.optional_where)):
            tables.update(st.tables)
    return tables


def _value_source(project: ProjectContext, src: SourceFile, fn: Node | None, arg: Node | None) -> str:
    if arg is None:
        return "unknown"
    principals = [p for p in project.config.tenancy.principal if p]
    texts = [src.text_of(arg)]
    if fn is not None and arg.type == "identifier":
        texts += [src.text_of(d) for d in reaching_definitions(src, fn, src.text_of(arg), arg.start_byte)]
    if any(p in t for p in principals for t in texts):
        return "principal"
    if is_tainted(src, arg):
        at = arg.parent
        while at is not None and at.parent is not None and (fn is None or at.parent.id != fn.id) and at.type not in ("expression_statement", "return_statement", "local_variable_declaration"):
            at = at.parent
        if fn is not None and at is not None and _owner_checked(src, fn, at, arg, principals):
            return "checked"
        return "request"
    return "unknown"


def _compares(text: str, name: str, principals: list[str]) -> bool:
    """text가 name과 로그인 사용자의 소속 식을 같은지 비교한다(equals·==·!=·Objects.equals)"""
    n = rf"(?<![\w.]){re.escape(name)}\b"
    for p in principals:
        q = re.escape(p)
        if re.search(rf"{n}\s*\.\s*equals(?:IgnoreCase)?\(\s*[\w.]*{q}|{q}\s*\.\s*equals(?:IgnoreCase)?\(\s*{n}\s*\)|{n}\s*[!=]==?\s*[\w.]*{q}|{q}\s*[!=]==?\s*{n}", text):
            return True
        if re.search(rf"Objects\.equals\(\s*(?:{n}\s*,\s*[\w.]*{q}|[\w.]*{q}\s*,\s*{n})\s*\)", text):
            return True
    return False


def _negated_compare(text: str, name: str, principals: list[str]) -> bool:
    n = rf"(?<![\w.]){re.escape(name)}\b"
    return any(
        re.search(rf"!\s*{n}\s*\.\s*equals|{n}\s*!==?\s*[\w.]*{re.escape(p)}|{re.escape(p)}\s*!==?\s*{n}|!\s*Objects\.equals", text) for p in principals
    )


def _owner_check_call(src: SourceFile, cond: Node, name: str, principals: list[str]) -> bool:
    """cond 안에 name을 넘겨받아 본문에서 그 매개변수를 로그인 사용자의 소속과 비교하는 프로젝트 함수 호출이 있다"""
    for call in _calls_in(src, cond):
        for i, a in enumerate(call.args):
            if src.text_of(a) != name:
                continue
            for hsrc, fn in resolve_any(src, call.callee, len(call.args), at=call.node):
                params = [q for q in fn.params if hsrc.text_of(q) not in ("self", "cls")]
                pname = param_name(hsrc, params[i]) if i < len(params) else None
                returns = [hsrc.text_of(r) for r in walk(fn.node) if r.type == "return_statement"]
                if pname and any(_compares(r, pname, principals) and not _negated_compare(r, pname, principals) for r in returns):  # iron-laws: ignore[IL-307] 소속 확인 함수라는 판정 결과다
                    return True
    return False


def _mismatch_term(src: SourceFile, term: Node, name: str, principals: list[str]) -> bool:
    """or로 나눈 거부 조건의 한 항이 'name이 로그인 사용자의 소속과 다르다'이다. 이 항만 참이어도 실행이 끊긴다"""
    inner = _negated(term)
    if inner is not None:
        return _compares(src.text_of(inner), name, principals) or _owner_check_call(src, inner, name, principals)
    term = _unwrap(term)
    operator = term.child_by_field_name("operator") if term.type == "binary_expression" else None
    return operator is not None and src.text_of(operator) in ("!=", "!==") and _compares(src.text_of(term), name, principals)


def _owner_checked(src: SourceFile, fn: Node, at: Node, arg: Node, principals: list[str]) -> bool:
    """at 앞에서 arg 변수를 로그인 사용자의 소속과 비교해 다르면 실행을 끊는다"""
    if arg.type != "identifier":  # iron-laws: ignore[IL-307] 변수가 아닌 값은 검사 분기를 추적하지 않는다는 판정 결과다
        return False
    name = src.text_of(arg)
    for node in walk(fn):
        if node.type not in ("if_statement", "if_expression"):
            continue
        cond, consequence = if_parts(node)
        if cond is None or not terminates(src, consequence) or not runs_before(src, node, at, fn):
            continue
        if redefined_between(src, fn, name, node.end_byte, at.start_byte):
            continue
        if any(_mismatch_term(src, t, name, principals) for t in _or_terms(src, cond)):  # iron-laws: ignore[IL-307] 소속을 확인했다는 판정 결과다
            return True
    return False


def _bound_arg(src: SourceFile, call: Call, binding: str, params: list[str] | None = None) -> Node | None:
    """매퍼 문장의 바인딩 이름에 해당하는 호출 인자. 매퍼 인터페이스의 @Param 이름을 먼저 보고, 없으면 인자 모양으로 찾는다"""
    if params and binding in params and params.index(binding) < len(call.args):
        return call.args[params.index(binding)]
    for a in call.args:
        if src.text_of(a) == binding or src.text_of(a).endswith("." + binding) or re.search(rf"get{re.escape(binding)}\(\)$", src.text_of(a), re.IGNORECASE):
            return a
    return call.args[0] if len(call.args) == 1 else None


def tenancy_rows(project: ProjectContext) -> list[tuple[TenancyRow, SourceFile | None, Node | None]]:
    """조회문(매퍼 호출)별 소속 확인 표. tenancy가 설정되지 않았으면 비어 있다."""
    settings = project.config.tenancy
    if not settings.active:
        return []
    keys = [k.lower() for k in settings.keys]
    targets = _target_tables(project)
    mappers = project.mappers()
    rows: list[tuple[TenancyRow, SourceFile | None, Node | None]] = []
    called: set[tuple[str, str]] = set()
    for src in project.source_files():
        if src.lang not in (Lang.JAVA, Lang.KOTLIN):
            continue
        for call in iter_calls(src):
            st = mappers.resolve(src, call)
            if st is None:
                continue
            called.add((st.namespace, st.id))
            where = f"{src.path.as_posix()}:{call.line}"
            base = {"mapper": st.namespace, "statement": st.id, "kind": st.kind, "tables": ",".join(st.tables), "call": where}
            if st.kind == "insert" or not set(st.tables) & targets:
                rows.append((TenancyRow(**base, key_column="n/a", binding="", source="-", verdict="n/a"), src, call.node))
                continue
            key = next((k for k in keys if k in st.where), None)
            if key is not None:
                binding = st.where[key]
                arg = _bound_arg(src, call, binding, mappers.bindings_of(st))
                source = _value_source(project, src, enclosing_function(call.node, src.lang), arg)
                verdict = {"principal": "ok", "checked": "ok", "request": "violation", "unknown": "review"}[source]
                rows.append((TenancyRow(**base, key_column="where", binding=binding, source=source, verdict=verdict), src, call.node))
                continue
            optional = next((k for k in keys if k in st.optional_where), None)
            if optional is not None:
                rows.append((TenancyRow(**base, key_column="optional", binding=st.optional_where[optional], source="-", verdict="review"), src, call.node))
                continue
            rows.append((TenancyRow(**base, key_column="missing", binding="", source="-", verdict="violation"), src, call.node))
    for st in mappers.statements():
        if (st.namespace, st.id) not in called:
            rows.append((TenancyRow(st.namespace, st.id, st.kind, ",".join(st.tables), "-", "", "-", "(호출 없음)", "n/a"), None, None))
    return rows


class TenantBoundaryRule(AiRule):
    rule_id = "AI-129"
    name = "소속(테넌트) 키 없는 조회·변경 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.HIGH
    plain = "여러 가맹점·고객사가 한 시스템을 함께 쓰는데 조회 조건의 소속 코드를 요청 값에서 받거나 아예 빼면, 소속 코드만 바꿔 다른 소속의 계좌·거래 내역을 보거나 고칠 수 있습니다."
    how_to_fix = "소속 격리 대상 테이블의 조회·변경은 WHERE에 소속 열을 넣고, 그 값은 요청이 아니라 로그인 사용자의 소속(설정의 tenancy.principal)에서 가져오세요."

    def check_project(self, project: ProjectContext) -> list[Violation]:
        found: list[Violation] = []
        for row, src, node in tenancy_rows(project):
            if src is None or node is None or row.verdict not in ("violation", "review"):
                continue
            if row.key_column == "missing":
                message = f"소속 격리 대상 테이블({row.tables})을 다루는 매퍼 문장 {row.statement}의 조건에 소속 열이 없습니다."
            elif row.key_column == "optional":
                message = f"매퍼 문장 {row.statement}의 소속 조건({row.binding})이 동적 절 안에만 있어 빠질 수 있습니다."
            elif row.source == "request":
                message = f"매퍼 문장 {row.statement}의 소속 조건에 로그인 사용자가 아니라 요청 값({row.binding})을 넣습니다."
            else:
                message = f"매퍼 문장 {row.statement}의 소속 조건 값({row.binding})이 로그인 사용자의 소속인지 정할 수 없습니다."
            confidence = Confidence.CONFIRMED if row.verdict == "violation" else Confidence.REVIEW
            found.append(self.at_node(src, node, message, confidence=confidence, severity=None if row.verdict == "violation" else Severity.MEDIUM))
        return found
