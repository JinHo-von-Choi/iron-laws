"""injection 계열의 공유 AST·판정 기반."""
# iron-laws: ignore-file[IL-510] CSRF 해제 구문을 탐지하는 패턴 정의
import re

from tree_sitter import Node

from iron_laws.core.models import Confidence, EvidenceStep, IronLaw, Violation
from iron_laws.engine.ast_tools import (
    Call,
    enclosing_function,
    identifiers_in,
    is_literal,
    walk,
)
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import (
    CLI_SOURCE_RE,
    WEB_SOURCE_RE,
    Ctx,
    definitions,
    reaching_definitions,
    taint_state,
)
from iron_laws.rules.base import BaseRule
from iron_laws.rules.guards import (
    executes_unconditionally,
    mutated_between,
    terminates,
)
from iron_laws.rules.sinks import (
    Flow,
    Sink,
    sink_hits,
)

SQL_TEXT_RE = re.compile(
    r"(?is)\b(select\b.+\bfrom|insert\s+into|update\b.+\bset|delete\s+from|drop\s+table|create\s+table|alter\s+table|where\b|union\s+select|exec(ute)?\s)"
)


DDL_TEXT_RE = re.compile(r"(?is)\s*(drop|alter|create|truncate|comment\s+on|grant|revoke|set\s+search_path|vacuum|analyze|reindex)\b")


LDAP_TEXT_RE = re.compile(r"\([&|!]?\w+\s*[=~<>]")


SANITIZER_RE = re.compile(
    r"(?i)secure_filename|basename|GetFileName|filepath\.Base|\.getName\(\)|"
    r"is_relative_to|sanitize|uuid|Path\.GetRandomFileName|allowlist|whitelist"
)


NORMALIZE_RE = re.compile(r"(?i)normalize|getCanonical|realpath|abspath|resolve\(|GetFullPath|filepath\.Clean")


CONFINEMENT_RE = re.compile(
    r"(?i)is_relative_to|relative_to\(|commonpath|commonprefix|startswith|startsWith|StartsWith|HasPrefix|\.relative\(|isSubPath|within_base|inside_base"
)


FILENAME_RE = re.compile(
    r"\.filename\b|getOriginalFilename|originalname|\.FileName\b|\$_FILES\s*\[[^\]]+\]\s*\[\s*['\"]name['\"]\s*\]|header\.Filename|\bfile\.name\b"
)


ESCAPER_RE = re.compile(
    r"(?i)\bescape\b|html\.escape|markupsafe|htmlspecialchars|htmlentities|encodeURI|he\.encode|sanitize|DOMPurify|bleach|"
    r"cgi\.escape|HtmlEncode|Encoder\.|escapeHtml|StringEscapeUtils|textContent|html/template|escapeXml|\be\(|"
    r"(?-i:\b(?:[a-z]{1,4}Esc|esc|Esc|escape|[A-Za-z]+Escape)\w*\()"
)


def _context_text(src: SourceFile, arg: Node) -> str:
    """인자 식과, 식별자일 경우 그 정의식들의 원문을 합쳐 반환한다."""
    parts = [src.text_of(arg)]
    if arg.type in ("identifier", "variable_name"):
        scope = enclosing_function(arg, src.lang) or src.root
        if scope is not None:
            for d in definitions(src, scope, src.text_of(arg).lstrip("$")):
                parts.append(src.text_of(d))
    return "\n".join(parts)


class SinkRule(BaseRule):
    """싱크 호출의 인자가 외부 입력이거나 동적으로 조합된 경우를 지적한다."""

    sinks: list[Sink] = []
    iron_law = IronLaw.LAW_5
    dynamic_is_finding: bool = True
    include_cli_sources: bool = False
    taint_ctx: Ctx = Ctx.ANY  # 오염된 값이 도달하는 곳. 그 문맥에 유효한 정제만 인정한다
    tainted_message: str = ""

    def skip_hit(self, src: SourceFile, call: Call, arg: Node, flow: Flow) -> bool:
        return False

    DEAD_END_RE = re.compile(r"\b(raise|return|abort|exit|throw|panic|die)\b|sys\.exit")
    LITERAL_ELEMENT_TYPES = frozenset({"string", "integer", "float", "true", "false", "none", "concatenated_string"})

    def _literal_collection(self, src: SourceFile, node: Node, depth: int = 0) -> bool:
        """문자열·숫자 리터럴만 담은 목록·튜플·집합·사전(또는 그런 값으로 정의된 모듈 상수)인지"""
        if node.type in ("list", "tuple", "set", "dictionary", "parenthesized_expression"):
            items = [c for c in node.named_children if "comment" not in c.type]
            return all(
                (c.type in self.LITERAL_ELEMENT_TYPES and not (c.type == "string" and "interpolation" in {k.type for k in c.children}))
                or (c.type == "pair" and (key := c.child_by_field_name("key")) is not None and key.type in self.LITERAL_ELEMENT_TYPES)
                for c in items
            ) and bool(items)
        if node.type == "call" and src.text_of(node).startswith(("frozenset(", "set(", "tuple(", "list(")):
            inner = [c for c in node.named_children if c.type == "argument_list"]
            return bool(inner) and len(inner[0].named_children) == 1 and self._literal_collection(src, inner[0].named_children[0], depth + 1)
        if node.type == "identifier" and depth < 2 and src.root is not None:
            defs = [d for d in definitions(src, src.root, src.text_of(node)) if enclosing_function(d, src.lang) is None]
            return bool(defs) and all(self._literal_collection(src, d, depth + 1) for d in defs)
        return False

    def _membership(self, src: SourceFile, cond: Node) -> tuple[str, bool] | None:
        """`x in 허용목록` / `x not in 허용목록` 형태의 조건이면 (변수 이름, 부정 여부)"""
        negated = False
        if cond.type == "not_operator" and cond.named_children:
            negated, cond = True, cond.named_children[0]
        while cond.type == "parenthesized_expression" and cond.named_children:
            cond = cond.named_children[0]
        if cond.type != "comparison_operator" or len(cond.named_children) != 2:
            return None
        left, right = cond.named_children
        between = src.data[left.end_byte : right.start_byte].decode("utf-8", errors="replace")
        match = re.fullmatch(r"\s*(not\s+in|in)\s*", between)
        if match is None or left.type != "identifier" or not self._literal_collection(src, right):
            return None
        return src.text_of(left), negated != (match.group(1) != "in")

    def _allowlisted(self, src: SourceFile, call: Call, arg: Node) -> bool:
        """싱크에 들어가는 동적 변수가 모두, 싱크보다 앞서 실행되는 허용 목록 검사(`x not in (...)` → 거부, 또는 통과 분기 안에서만 사용)를 거친다"""
        if src.lang is not Lang.PYTHON:
            return False
        scope = enclosing_function(call.node, src.lang) or src.root
        if scope is None:
            return False
        names = set()
        for name in identifiers_in(src, arg):
            defs = reaching_definitions(src, scope, name, arg.start_byte)
            if defs and all(is_literal(d) for d in defs):
                continue  # 상수로만 정의된 변수는 닫혀 있다
            names.add(name)
        if not names:
            return False
        guarded: set[str] = set()
        for node in walk(scope):
            if node.type not in ("if_statement", "assert_statement"):
                continue
            cond = node.child_by_field_name("condition") or (node.named_children[0] if node.type == "assert_statement" and node.named_children else None)
            if cond is None:
                continue
            membership = self._membership(src, cond)
            if membership is None or membership[0] not in names:
                continue
            variable, rejects_when_true = membership
            if node.type == "assert_statement":
                if node.end_byte <= call.node.start_byte and not rejects_when_true and executes_unconditionally(node, scope) and not mutated_between(src, scope, variable, node.end_byte, call.node.start_byte):
                    guarded.add(variable)
                continue
            consequence = node.child_by_field_name("consequence")
            if consequence is None:
                continue
            if rejects_when_true:
                # 거부 분기가 실제로 실행을 끊고, 모든 경로에서 검사를 거치며, 검사한 값이 싱크까지 바뀌지 않아야 한다
                if (
                    node.end_byte <= call.node.start_byte
                    and terminates(src, consequence)
                    and executes_unconditionally(node, scope)
                    and not mutated_between(src, scope, variable, node.end_byte, call.node.start_byte)
                ):
                    guarded.add(variable)
            elif (
                consequence.start_byte <= call.node.start_byte
                and call.node.end_byte <= consequence.end_byte
                and not mutated_between(src, scope, variable, cond.end_byte, call.node.start_byte)
            ):
                guarded.add(variable)
        return names <= guarded

    def select_args(self, src: SourceFile, call: Call, sink: Sink) -> list[Node]:
        """싱크 호출에서 검사할 인자. 기본은 Sink에 지정한 위치(None이면 전부)"""
        if sink.arg is None:
            return list(call.args)
        return [call.args[sink.arg]] if sink.arg < len(call.args) else []

    def _evidence(self, src: SourceFile, call: Call, arg: Node, via: str | None) -> list[EvidenceStep]:
        """입력 유입 → 전파 → 싱크의 위치와 변수 이름만 남긴다. 코드 원문과 값은 담지 않는다."""
        path = src.path.as_posix()
        scope = enclosing_function(call.node, src.lang)
        first = scope.start_point[0] + 1 if scope is not None else 1
        source_re = WEB_SOURCE_RE
        steps: list[EvidenceStep] = []
        for line_no in range(first, call.line + 1):
            text = src.lines[line_no - 1] if line_no - 1 < len(src.lines) else ""
            if source_re.search(text) or (self.include_cli_sources and CLI_SOURCE_RE.search(text)):
                steps.append(EvidenceStep(role="source", file_path=path, line=line_no, note="외부 입력이 들어오는 지점"))
                break
        names = sorted(identifiers_in(src, arg) & set(taint_state(src, call.node, self.include_cli_sources, ctx=self.taint_ctx)))
        if names:
            steps.append(EvidenceStep(role="propagation", file_path=path, line=call.line, note=f"오염된 변수: {', '.join(names)}"))
        steps.append(EvidenceStep(role="sink", file_path=path, line=call.line, note=f"{call.callee}에 전달"))
        if via:
            via_path, _, via_line = via.rpartition(":")
            steps.append(EvidenceStep(role="sink", file_path=via_path, line=int(via_line) if via_line.isdigit() else 0, note="호출한 함수 안에서 실제로 사용되는 지점"))
        return steps

    def check(self, src: SourceFile) -> list[Violation]:
        found: list[Violation] = []
        hits = sink_hits(
            src, self.sinks, self.include_cli_sources, self.select_args, self.taint_ctx, self.skip_hit
        )
        for call, arg, flow, via in hits:
            if via is None and self.skip_hit(src, call, arg, flow):
                continue
            if via is None and self._allowlisted(src, call, arg):
                continue  # 허용 목록 검사를 통과한 값만 싱크에 닿는다
            if flow is Flow.TAINTED:
                message = self.tainted_message.format(callee=call.callee)
                if via:
                    message += f" (호출한 함수 안의 {via}에서 사용됩니다)"
                violation = self.at_node(src, call.node, message)
                violation.evidence = self._evidence(src, call, arg, via)
                found.append(violation)
            elif self.dynamic_is_finding:
                found.append(
                    self.at_node(
                        src,
                        call.node,
                        self.dynamic_message.format(callee=call.callee),
                        severity=self.downgrade(self.severity),
                        confidence=Confidence.REVIEW,
                    )
                )
        return found


DB_RECEIVER_RE = re.compile(
    r"(?i)(stmt|statement|ps\b|prepared|conn|connection|cursor|\bcur\b|\bdb\b|jdbc|template|session|entitymanager|\bem\b|repo|dao|query|sql|pool|client|knex|prisma|sequelize|mongo|collection|database|\bcmd\b|command|\bdbo\b)"
)


STRONG_SQL_CALLEES = re.compile(
    r"(^|\.)(execute|executemany|executescript|executeQuery|executeUpdate|prepareStatement|createNativeQuery|"
    r"ExecuteReader|ExecuteNonQuery|ExecuteScalar|FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync|"
    r"queryRawUnsafe|executeRawUnsafe|\$queryRawUnsafe|\$executeRawUnsafe|mysqli_query|mysql_query|pg_query|sqlite3_exec|PQexec)$|^new\w*Command$"
)


def _csrf_missing(self: BaseRule, project: ProjectContext) -> list[Violation]:
    text = "\n".join(f.code_text for f in project.source_files(include_tests=True))
    if re.search(r"(?i)csurf|csrf|lusca|samesite|CSRFProtect|flask_wtf|xsrf|antiforgery", text):
        return []
    found = []
    for src in project.source_files():
        if src.lang in JS_FAMILY and re.search(r"express-session|cookie-session", src.code_text):
            routes = len(re.findall(r"\b(?:app|router)\.(?:post|put|patch|delete)\(", text))
            if routes >= 3:
                m = re.search(r"express-session|cookie-session", src.code_text)
                line = src.code_text.count("\n", 0, m.start()) + 1
                found.append(self.at_line(src, line, f"쿠키 세션을 쓰는 Express 앱에 상태 변경 라우트 {routes}개가 있으나 CSRF 방어(csurf, SameSite 설정 등)가 프로젝트 어디에도 보이지 않습니다.", confidence=Confidence.REVIEW))
                break
    for src in project.source_files():
        if src.lang is Lang.PYTHON and re.search(r"\bFlask\(", src.code_text) and re.search(r"\bsession\b", src.code_text):
            posts = len(re.findall(r"methods\s*=\s*\[[^\]]*['\"]POST['\"]|@\w+\.post\(", text))
            if posts >= 3:
                found.append(self.at_line(src, 1, f"세션을 쓰는 Flask 앱에 POST 라우트 {posts}개가 있으나 CSRF 방어(Flask-WTF CSRFProtect 등)가 보이지 않습니다.", confidence=Confidence.REVIEW))
                break
    return found


XPATH_TEXT_RE = re.compile(r"(?:/{1,2}[A-Za-z_*][\w:*-]*(?:\[|/|\s|$|['\"])|\[@|\bcount\(|\btext\(\))")
