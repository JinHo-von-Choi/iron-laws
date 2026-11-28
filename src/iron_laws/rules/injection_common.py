"""injection 계열의 공유 AST·판정 기반."""
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
    Ctx,
    definitions,
    expr_has_source,
    reaching_definitions,
    taint_state,
)
from iron_laws.rules.base import BaseRule
from iron_laws.rules.guards import (
    PassFacts,
    _or_terms,
    executes_unconditionally,
    mutated_between,
    passing_facts,
    runs_before,
    terminates,
)
from iron_laws.rules.sinks import (
    Flow,
    Sink,
    sink_hits,
)

SQL_TEXT_RE = re.compile(
    r"(?is)\b(select\b.+\bfrom|insert\s+into|update\b.+\bset|delete\s+from|drop\s+table|create\s+table|alter\s+table|where\b|union\s+select|exec(ute)?\s)"
    r"|\{\s*(?:\?\s*=\s*)?call\b"  # JDBC 저장 프로시저 호출 구문: {call 프로시저(...)}, {? = call ...}
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

    GUARD_SKIP = "skip"

    def entry_confined(self, src: SourceFile, call: Call, arg: Node) -> bool:
        """도우미 함수로 넘기는 오염된 인자가 호출하는 곳에서 이미 이 규칙이 인정하는 검사를 거쳤는지. 기본은 아니다"""
        return False

    def entry_guard(self, src: SourceFile, call: Call, arg: Node) -> str | None:
        """도우미 함수로 넘기는 오염된 인자가 호출하는 곳에서 거친 검사를 이 규칙이 확인 필요로 낮출 때 그 사유. 기본은 없다"""
        return None

    def guard_verdict(self, src: SourceFile, call: Call, arg: Node, facts: dict[str, PassFacts]) -> str | None:
        """싱크 인자의 외부 입력이 모두 거부 분기를 거쳤을 때, 그 분기가 막는 것으로 이 규칙이 내릴 판정.
        facts가 비어 있으면 모든 외부 입력이 거친 검사가 없다는 뜻이다(값에 적용한 치환 등만 볼 수 있다).
        GUARD_SKIP이면 지적하지 않고, 문자열이면 그 사유를 붙여 확인 필요로 낮추고, None이면 그대로 둔다"""
        return None

    def _tainted_roots(self, src: SourceFile, scope: Node, node: Node, guarded: set[str], tainted: set[str], depth: int = 0) -> set[str] | None:
        """식의 외부 입력이 거쳐 온 검사 대상 변수들. 검사를 거치지 않은 외부 입력이 섞이면 None"""
        if depth > 6 or expr_has_source(src, node, self.include_cli_sources):
            return None
        roots: set[str] = set()
        for name in identifiers_in(src, node):
            if name in guarded:
                roots.add(name)
                continue
            defs = [d for d in reaching_definitions(src, scope, name, node.start_byte) if d.id != node.id]
            if not defs:
                if name in tainted:
                    return None  # 매개변수·바깥 변수로 들어온 외부 입력
                continue
            for d in defs:
                sub = self._tainted_roots(src, scope, d, guarded, tainted, depth + 1)
                if sub is None:
                    return None
                roots |= sub
        return roots

    def _guard_outcome(self, src: SourceFile, call: Call, arg: Node) -> str | None:
        scope = enclosing_function(call.node, src.lang)
        if scope is None:
            return None
        facts = passing_facts(src, scope, call.node)
        if not facts:
            return self.guard_verdict(src, call, arg, {})
        tainted = set(taint_state(src, call.node, self.include_cli_sources, ctx=self.taint_ctx))
        roots = self._tainted_roots(src, scope, arg, set(facts), tainted)
        if not roots:
            return self.guard_verdict(src, call, arg, {})
        if all({self.taint_ctx.value, "any"} & facts[name].validated for name in roots):
            return self.GUARD_SKIP  # 사용자 명세가 이 문맥을 막는다고 선언한 검사 함수를 모든 입력이 통과했다
        return self.guard_verdict(src, call, arg, {name: facts[name] for name in roots})

    @staticmethod
    def guard_reason(facts: dict[str, PassFacts]) -> str:
        lines = sorted({n for f in facts.values() for n in f.lines})
        what = "·".join(sorted({f.describe() for f in facts.values() if f.describe()}))
        return f"{', '.join(map(str, lines))}행 검사가 {what}을 막지만 이 검사만으로 안전한지는 확인이 필요합니다."

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

    # 통과한 값에 따옴표·공백·셸 메타문자·경로 구분자가 없다고 보는 문자 종류 검사
    safe_character_predicates: frozenset[str] = frozenset({"isalnum", "isalpha", "isdigit", "isdecimal", "isnumeric", "isidentifier"})

    def _character_check(self, src: SourceFile, cond: Node) -> str | None:
        """`x.isalnum()`·`x.isdigit()` 같은 문자 종류 검사나 `re.fullmatch(r'[A-Za-z0-9_-]+', x)` 검사이면 검사한 변수 이름.
        이런 검사를 통과한 값에는 따옴표·공백·셸 메타문자·경로 구분자가 없다."""
        if cond.type != "call":  # iron-laws: ignore[IL-307] None은 문자 종류 검사가 아니라는 판정 결과다
            return None
        function, args = cond.child_by_field_name("function"), cond.child_by_field_name("arguments")
        if function is None or args is None:  # iron-laws: ignore[IL-307] None은 문자 종류 검사가 아니라는 판정 결과다
            return None
        if function.type == "attribute":
            target, attribute = function.child_by_field_name("object"), function.child_by_field_name("attribute")
            if target is not None and target.type == "identifier" and attribute is not None and not args.named_children \
                    and src.text_of(attribute) in self.safe_character_predicates:
                return src.text_of(target)
            if src.text_of(function) in ("re.fullmatch", "re.match") and len(args.named_children) >= 2:
                pattern, value = args.named_children[0], args.named_children[1]
                body = re.sub(r"^[rRbB]*['\"]|['\"]$", "", src.text_of(pattern))
                anchored = src.text_of(function) == "re.fullmatch" or body.endswith("$") or body.endswith("\\Z")
                if value.type == "identifier" and pattern.type == "string" and anchored and SAFE_CHARACTER_PATTERN.fullmatch(body.lstrip("^").rstrip("$")):
                    return src.text_of(value)
        return None

    def _membership(self, src: SourceFile, cond: Node) -> tuple[str, bool] | None:
        """`x in 허용목록` / `x not in 허용목록` 형태의 조건이면 (변수 이름, 부정 여부)"""
        negated = False
        if cond.type == "not_operator" and cond.named_children:
            negated, cond = True, cond.named_children[0]
        while cond.type == "parenthesized_expression" and cond.named_children:
            cond = cond.named_children[0]
        checked = self._character_check(src, cond)
        if checked is not None:
            return checked, negated  # 안전한 문자만 허용하는 검사: 참이면 통과, 부정이면 거부
        if cond.type != "comparison_operator" or len(cond.named_children) != 2:
            return None
        left, right = cond.named_children
        between = src.data[left.end_byte : right.start_byte].decode("utf-8", errors="replace")
        match = re.fullmatch(r"\s*(not\s+in|in)\s*", between)
        if match is None or not self._literal_collection(src, right):
            return None
        subject = src.text_of(left) if left.type == "identifier" else self._parsed_url_host(src, left)
        if subject is None:
            return None
        return subject, negated != (match.group(1) != "in")

    URL_PARSE_RE = re.compile(r"^(?:urllib\.parse\.|parse\.)?(?:urlparse|urlsplit)$")

    def _parsed_url_host(self, src: SourceFile, node: Node) -> str | None:
        """`u.netloc`·`u.hostname`이고 u가 `urlparse(v)`로 정해지면 v. 호스트를 허용 목록과 비교하면 v의 이동 대상이 목록 안이다"""
        if node.type != "attribute":
            return None
        target, attribute = node.child_by_field_name("object"), node.child_by_field_name("attribute")
        if target is None or attribute is None or target.type != "identifier" or src.text_of(attribute) not in ("netloc", "hostname"):
            return None
        scope = enclosing_function(node, src.lang) or src.root
        defs = reaching_definitions(src, scope, src.text_of(target), node.start_byte) if scope is not None else []
        if len(defs) != 1 or defs[0].type != "call":
            return None
        function, arguments = defs[0].child_by_field_name("function"), defs[0].child_by_field_name("arguments")
        args = [a for a in arguments.named_children if "comment" not in a.type] if arguments is not None else []
        if function is None or not self.URL_PARSE_RE.match(src.text_of(function)) or len(args) != 1 or args[0].type != "identifier":
            return None
        return src.text_of(args[0])

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
            if membership is None and node.type == "if_statement":
                # 거부 조건을 or로 나눈 항 가운데 허용 목록 검사가 있으면, 통과한 경로에서는 그 검사가 참이다
                terms = [m for t in _or_terms(src, cond) if (m := self._membership(src, t)) is not None and m[1] and m[0] in names]
                membership = terms[0] if len(_or_terms(src, cond)) > 1 and terms else None
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
                    and runs_before(src, node, call.node, scope)
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

    def _flow_steps(self, src: SourceFile, call: Call, arg: Node) -> list[EvidenceStep]:
        """싱크 인자에서 도달 정의를 거슬러 올라가며 실제로 이어진 대입(전파)과 입력이 들어온 곳(원천)을 찾는다"""
        path = src.path.as_posix()
        scope = enclosing_function(call.node, src.lang) or src.root
        if scope is None:
            return []
        steps: list[EvidenceStep] = []
        seen: set[int] = set()
        frontier = [(arg, 0)]
        while frontier and len(steps) < 8:
            node, depth = frontier.pop(0)
            if expr_has_source(src, node, self.include_cli_sources):
                steps.append(EvidenceStep(role="source", file_path=path, line=src.line_of(node), note="외부 입력이 들어오는 지점"))
                continue
            if depth > 6:
                continue
            for name in sorted(identifiers_in(src, node)):
                for d in reaching_definitions(src, scope, name, node.start_byte):
                    if d.id in seen or d.id == node.id or is_literal(d):
                        continue
                    seen.add(d.id)
                    if not expr_has_source(src, d, self.include_cli_sources):
                        steps.append(EvidenceStep(role="propagation", file_path=path, line=src.line_of(d), note=f"{name}에 대입"))
                    frontier.append((d, depth + 1))
        return sorted(steps, key=lambda s: (s.line, s.role != "source"))

    def _evidence(self, src: SourceFile, call: Call, arg: Node, via: str | None, guard: str | None = None) -> list[EvidenceStep]:
        """입력 유입 → 전파 → (검사) → 싱크의 위치와 변수 이름만 남긴다. 코드 원문과 값은 담지 않는다.
        원천은 싱크 인자까지 실제로 이어진 정의에서 찾는다(같은 함수의 다른 입력을 원천으로 적지 않는다)"""
        path = src.path.as_posix()
        steps = self._flow_steps(src, call, arg)
        names = sorted(identifiers_in(src, arg) & set(taint_state(src, call.node, self.include_cli_sources, ctx=self.taint_ctx)))
        if names:
            steps.append(EvidenceStep(role="propagation", file_path=path, line=call.line, note=f"오염된 변수: {', '.join(names)}"))
        if guard:
            # 사유 문장 앞머리 "12, 15행 검사가 …"의 줄 번호가 검사 분기 위치다
            head = guard.split("행 검사", 1)[0] if "행 검사" in guard else ""
            lines = sorted({int(n) for n in re.findall(r"\d+", head)}) if re.fullmatch(r"[\d, ]+", head) else []
            for line in lines or [call.line]:
                steps.append(EvidenceStep(role="guard", file_path=path, line=line, note=guard[:160]))
        steps.append(EvidenceStep(role="sink", file_path=path, line=call.line, note=f"{call.callee}에 전달"))
        if via:
            via_path, _, via_line = via.rpartition(":")
            steps.append(EvidenceStep(role="sink", file_path=via_path, line=int(via_line) if via_line.isdigit() else 0, note="호출한 함수 안에서 실제로 사용되는 지점"))
        return steps

    def check(self, src: SourceFile) -> list[Violation]:
        found: list[Violation] = []
        hits = sink_hits(
            src, self.sinks, self.include_cli_sources, self.select_args, self.taint_ctx, self.skip_hit,
            lambda s, c, a, _f: self.entry_confined(s, c, a), self.entry_guard,
        )
        for call, arg, flow, via, entry_guard in hits:
            if via is None and self.skip_hit(src, call, arg, flow):
                continue
            if via is None and self._allowlisted(src, call, arg):
                continue  # 허용 목록 검사를 통과한 값만 싱크에 닿는다
            if flow is Flow.TAINTED:
                guard = self._guard_outcome(src, call, arg) if via is None else None
                if guard == self.GUARD_SKIP:
                    continue
                guard = guard or entry_guard  # 싱크 앞에 검사가 없으면 호출하는 곳에서 거친 검사를 본다
                message = self.tainted_message.format(callee=call.callee)
                if via:
                    message += f" (호출한 함수 안의 {via}에서 사용됩니다)"
                if guard:
                    violation = self.at_node(src, call.node, f"{message} 다만 {guard}", severity=self.downgrade(self.severity), confidence=Confidence.REVIEW)
                else:
                    violation = self.at_node(src, call.node, message)
                violation.evidence = self._evidence(src, call, arg, via, guard)
                found.append(violation)
            elif self.dynamic_is_finding:
                violation = self.at_node(
                    src,
                    call.node,
                    self.dynamic_message.format(callee=call.callee),
                    severity=self.downgrade(self.severity),
                    confidence=Confidence.REVIEW,
                )
                violation.evidence = self._evidence(src, call, arg, via)
                found.append(violation)
        if self.config is not None and self.config.policies.entry_points == "public_api" and self.rule_id in PUBLIC_API_RULES:
            public = self._public_api_findings(src, {v.line_number for v in found if v.confidence is Confidence.CONFIRMED})
            replaced = {v.line_number for v in public}
            # 같은 줄의 '동적 조합' 확인 필요 지적은 입력의 출처를 밝힌 공개 API 지적으로 바꾼다
            found = [v for v in found if not (v.confidence is Confidence.REVIEW and v.line_number in replaced)] + public
        return found

    def _public_api_findings(self, src: SourceFile, confirmed_lines: set[int]) -> list[Violation]:
        """공개 함수의 매개변수가 그대로 싱크에 닿는 흐름. 웹 입력이 닿는 확정 지적과 겹치면 확정을 그대로 두고, 이 흐름만이면 확인 필요로 낸다"""
        from iron_laws.engine.ast_tools import iter_calls
        from iron_laws.engine.public_api import public_entries
        from iron_laws.rules.sinks import _hits_in

        applicable = [s for s in self.sinks if src.lang in s.langs and not s.prop]
        if not applicable:
            return []
        calls = list(iter_calls(src))
        found = []
        seen: set[int] = set()
        for fn, params in public_entries(src):
            inner = [c for c in calls if fn.node.start_byte <= c.node.start_byte and c.node.end_byte <= fn.node.end_byte]
            for call, arg, flow in _hits_in(src, inner, applicable, self.include_cli_sources, self.select_args, params, self.taint_ctx):
                if flow is not Flow.TAINTED or call.line in confirmed_lines or call.node.id in seen:
                    continue
                if self.skip_hit(src, call, arg, flow) or self._allowlisted(src, call, arg):
                    continue
                # 웹 입력 흐름과 같은 기준으로 싱크 앞의 검사를 본다. 약한 검사의 사유는 문구와 근거에 함께 싣는다
                guard = self._guard_outcome(src, call, arg)
                if guard == self.GUARD_SKIP:
                    continue
                seen.add(call.node.id)
                message = self.tainted_message.format(callee=call.callee) + " 이 흐름은 공개 API 매개변수에서 시작합니다. 호출하는 쪽이 외부 입력을 넘기는지 확인하십시오."
                if guard:
                    message += f" 또한 {guard}"
                violation = self.at_node(src, call.node, message, severity=self.downgrade(self.severity), confidence=Confidence.REVIEW)
                violation.evidence = [EvidenceStep(role="source", file_path=src.path.as_posix(), line=src.line_of(fn.node), note=f"공개 API 매개변수: {', '.join(sorted(params))}"),
                                      *self._evidence(src, call, arg, None, guard)]
                found.append(violation)
        return found


SAFE_CHARACTER_PREDICATES = SinkRule.safe_character_predicates
# 공개 API 진입점 모드(policies.entry_points: public_api)를 적용하는 규칙: 경로·명령·코드·XPath. XXE·XSS는 각 규칙이 따로 본다
PUBLIC_API_RULES = frozenset({"IL-502", "IL-504", "IL-503", "IL-527"})
# 값을 감싸는 따옴표를 다른 글자로 바꾸는 치환: .replace("'", ...)
QUOTE_REPLACE_RE = re.compile(r"""\.replace\(\s*(?:'\\''|"'"|'"'|"\\""|"\\\\'"|'\\\\''|"\\\\\"")\s*,""")


def wrapped_in_quote(text: str, name: str, quote: str) -> bool:
    """식 원문에서 변수 name이 quote로 감싼 자리에 들어가는지: `'{name}`, `'" + name`"""
    return re.search(rf"{re.escape(quote)}(?:\{{|[\"']?\s*\+\s*)\s*{re.escape(name)}\b", text) is not None


def quote_guard_verdict(rule: SinkRule, facts: dict[str, PassFacts], text: str) -> str | None:
    """SQL·XPath: 숫자 형식 검사는 지적하지 않고, 값을 감싸는 따옴표와 같은 따옴표를 막은 검사는 확인 필요로 낮춘다.
    검사가 없어도 그 따옴표를 다른 글자로 바꾸는 치환을 거치면 확인 필요로 낮춘다"""
    if not facts:
        if QUOTE_REPLACE_RE.search(text):
            return "값을 감싸는 따옴표를 바꾸는 치환을 거치지만 이 치환만으로 안전한지는 확인이 필요합니다."
        return None
    if all(f.digits for f in facts.values()):
        return rule.GUARD_SKIP
    if all(any(q in f.blocked and wrapped_in_quote(text, name, q) for q in ("'", '"')) for name, f in facts.items()):
        return rule.guard_reason(facts)
    return None
# 허용하는 글자가 영문·숫자·밑줄·하이픈뿐인 정규식(따옴표·공백·점·슬래시·셸 메타문자가 없다)
SAFE_CHARACTER_PATTERN = re.compile(r"(?:\[(?:A-Z|a-z|0-9|\\w|\\d|_|-)+\]|\\w|\\d)(?:[+*]|\{\d+(?:,\d*)?\})")
DB_RECEIVER_RE = re.compile(
    r"(?i)(stmt|statement|ps\b|prepared|conn|connection|cursor|\bcur\b|\bdb\b|jdbc|template|session|entitymanager|\bem\b|repo|dao|query|sql|pool|client|knex|prisma|sequelize|mongo|collection|database|\bcmd\b|command|\bdbo\b)"
)


STRONG_SQL_CALLEES = re.compile(
    r"(^|\.)(execute|executemany|executescript|executeQuery|executeUpdate|prepareStatement|prepareCall|addBatch|queryForRowSet|createNativeQuery|"
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
