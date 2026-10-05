"""
성능 위험 점검 계열(PERF): 데이터가 적을 때는 멀쩡하다가 사용자가 늘면 갑자기 느려지는 코드를 알려 준다.
정적 점검이라 실제 느림을 측정하지 않는다. 데이터 크기를 알 수 없으므로 기본은 `확인 필요`이고, 상수 크기 반복은 제외한다.
반복문 안의 DB 조회(N+1)는 ARC-212가 맡고, 이 계열은 같은 호출을 다시 지적하지 않는다.
작성자: 최진호
작성일: 2026-10-05
"""

import re
from dataclasses import dataclass

from tree_sitter import Node

from iron_laws.core.models import Confidence, IronLaw, RuleLayer, Severity, Violation
from iron_laws.engine.ast_tools import iter_calls, iter_functions, walk
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.source import SourceFile
from iron_laws.rules.architecture import (
    FUNCTION_TYPE_SET,
    LOOP_NODE_TYPES,
    DbInLoopRule,
    _is_generated,
)
from iron_laws.rules.base import BaseRule

PERF_LANGS = frozenset({Lang.PYTHON, Lang.JAVASCRIPT, Lang.TYPESCRIPT, Lang.TSX, Lang.JAVA})
QUERY_LIMIT = 5  # 한 함수에서 반복문 밖 DB 호출이 이 횟수 이상이면 알린다
SMALL_CONSTANT = 20  # 이 이하의 상수 크기 반복은 제외한다
SMALL_LITERAL = 10  # 이 이하의 원소를 가진 고정 목록은 찾기 대상에서 제외한다
MAX_PER_FILE = 20
LOOP_TYPES = LOOP_NODE_TYPES | {"set_comprehension", "dictionary_comprehension"}
ASYNC_FUNCTION_TYPES = {"function_definition", "arrow_function", "function_declaration", "function_expression", "method_definition"}
MIGRATION_PATH = re.compile(r"(?i)(^|/)(migrations?|alembic|seeds?|fixtures?)(/|$)")

NETWORK_AWAIT = re.compile(r"(?i)\b(fetch|axios|requests?|httpx|aiohttp|http|urlopen|ainvoke|api|client\.(get|post|put|delete|request|send)|session\.(get|post|put|delete))")
RETRY_NAME = re.compile(r"(?i)^_?(attempt|attempts|retry|retries|try|tries|trial|round)$|^(attempt|retry)_?\w*$")
SLEEP_AWAIT = re.compile(r"(?i)\b(sleep|setTimeout|delay|wait)\b")
SERVER_MARKERS = re.compile(r"(?i)\b(express|fastify|koa|hono|createServer|Bun\.serve|app\.listen|http\.Server|next/server|NextResponse)\b")
SQL_BOUNDED = re.compile(r"(?is)\b(where|limit|group\s+by|top\s+\d|fetch\s+first|rownum|count\s*\(|sum\s*\(|max\s*\(|min\s*\(|avg\s*\()")
HTTP_CALL = re.compile(
    r"^(requests\.(get|post|put|patch|delete|head)|httpx\.(get|post|put|patch|delete|head)|urllib\.request\.urlopen|urlopen|fetch|axios(\.\w+)?|got|"
    r"HttpClient\.\w+|restTemplate\.\w+|RestTemplate\.\w+)$"
)
FILE_CALL = re.compile(r"^(open|fs\.(readFileSync|readFile|writeFileSync|appendFileSync)|Files\.(read\w*|write\w*))$")
SUBPROCESS_CALL = re.compile(r"^(subprocess\.\w+|os\.system|child_process\.\w+|execSync|spawnSync)$")
BLOCKING_IN_ASYNC = re.compile(
    r"^(time\.sleep|requests\.(get|post|put|patch|delete|head)|urllib\.request\.urlopen|urlopen|subprocess\.(run|call|check_output|check_call)|os\.system|"
    r"fs\.(readFileSync|writeFileSync|appendFileSync|readdirSync|statSync)|execSync|spawnSync|child_process\.(execSync|spawnSync))$"
)
UNBOUNDED_SQL = re.compile(r"(?is)^\s*select\b.+?\bfrom\b")
SQL_LIMITED = re.compile(r"(?is)\b(where|limit|top|fetch\s+first|group\s+by|rownum)\b")


class PerfRule(BaseRule):
    layer = RuleLayer.PERFORMANCE
    gov_standard = None
    iron_law = IronLaw.LAW_5
    languages = PERF_LANGS

    def usable(self, src: SourceFile) -> bool:
        return src.lang in PERF_LANGS and src.root is not None and not src.is_test and not _is_generated(src) and not MIGRATION_PATH.search(src.path.as_posix())


def _function_of(node: Node) -> Node | None:
    current = node.parent
    while current is not None:
        if current.type in FUNCTION_TYPE_SET:
            return current
        current = current.parent
    return None


def _loops_around(node: Node) -> list[Node]:
    """node를 둘러싼 반복문(같은 함수 안), 바깥쪽부터"""
    loops: list[Node] = []
    current = node.parent
    while current is not None and current.type not in FUNCTION_TYPE_SET:
        if current.type in LOOP_TYPES:
            loops.append(current)
        current = current.parent
    return list(reversed(loops))


def _loop_parts(src: SourceFile, loop: Node) -> tuple[Node | None, Node | None]:
    """반복 변수와 반복 대상 노드"""
    target = loop.child_by_field_name("left") or loop.child_by_field_name("name") or loop.child_by_field_name("pattern")
    iterable = loop.child_by_field_name("right") or loop.child_by_field_name("value")
    return target, iterable


WRAPPER_TYPES = {"as_expression", "satisfies_expression", "non_null_expression", "parenthesized_expression", "type_assertion"}
SMALL_SLICE = re.compile(r"\[\s*(?:0?\s*)?:\s*(\d+)\s*\]\s*$")
LITERAL_ASSIGN = r"(?m)^\s*(?:const\s+|let\s+|var\s+)?{name}\s*(?::[^=\n]+)?=\s*(\[[^\n]*\]|\([^\n]*\)|\{{[^\n]*\}})\s*;?\s*$"


def _unwrap(node: Node) -> Node:
    while node.type in WRAPPER_TYPES and node.named_children:
        node = node.named_children[0]
    return node


def _small_literal_variable(src: SourceFile, node: Node, name: str) -> bool:
    """같은 함수 안에서 원소가 몇 개 안 되는 리터럴 한 줄로 만든 변수인가"""
    scope = _function_of(node)
    text = src.text_of(scope) if scope is not None else src.text
    m = re.search(LITERAL_ASSIGN.format(name=re.escape(name)), text)
    return m is not None and m.group(1).count(",") + 1 <= SMALL_LITERAL


def _small_constant(src: SourceFile, iterable: Node | None) -> bool:
    if iterable is None:
        return False
    iterable = _unwrap(iterable)
    if iterable.type in ("identifier", "attribute", "member_expression") and any(re.fullmatch(r"_*[A-Z][A-Z0-9_]{2,}", part) for part in src.text_of(iterable).split(".")):
        return True  # 모듈 상수 목록(OUTCOMES, VALID_TYPES 등)은 고정 크기 열거로 본다
    if iterable.type == "identifier" and _small_literal_variable(src, iterable, src.text_of(iterable)):
        return True
    if iterable.type in ("subscript", "subscript_expression"):
        m = SMALL_SLICE.search(src.text_of(iterable))
        if m and int(m.group(1)) <= SMALL_CONSTANT:
            return True
    if iterable.type in ("list", "tuple", "set", "dictionary", "array", "string", "string_literal", "template_string"):
        return len(iterable.named_children) <= 10 or iterable.type in ("string", "string_literal", "template_string")
    if iterable.type in ("call", "call_expression"):
        text = src.text_of(iterable)
        m = re.fullmatch(r"range\(\s*(?:\d+\s*,\s*)?(\d+)\s*\)", text)
        if m:
            return int(m.group(1)) <= SMALL_CONSTANT
    return False


def _names(src: SourceFile, node: Node | None) -> set[str]:
    if node is None:
        return set()
    return set(re.findall(r"[A-Za-z_]\w*", src.text_of(node)))


def _comprehension_clauses(loop: Node) -> list[Node]:
    return [c for c in loop.named_children if c.type in ("for_in_clause",)]


COMPREHENSION_TYPES = {"list_comprehension", "set_comprehension", "dictionary_comprehension", "generator_expression"}
ASSIGNMENT = re.compile(r"^\s*(?:try\s*\{\s*)?(?:const\s+|let\s+|var\s+)?([A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*)*)\s*(?::[^=\n]+)?(?:[+\-*/|&]|\?\?|\|\|)?=(?!=)\s*(.+)$")
FOR_LINE = re.compile(r"^\s*(?:async\s+)?for\s*\(?\s*(?:const\s+|let\s+|var\s+)?([\w$,\s\[\]{}()]+?)\s+(?:in|of)\s+(.+?)\)?\s*:?\s*\{?\s*$")
FILL = re.compile(r"\b([A-Za-z_$][\w$]*)\s*(?:\.(?:append|add|extend|update|push|set)\(([^\n]*)\)|\[[^\]\n]*\]\s*=\s*([^\n]*))")


@dataclass
class LoopInfo:
    targets: set[str]
    iterable_names: set[str]
    sized: bool  # 반복 횟수가 데이터 크기에 비례할 수 있는가(고정 크기·격자 한 축이면 거짓)


def _range_kind(src: SourceFile, iterable: Node | None) -> str:
    """`range(...)` 반복의 종류: data(범위가 len(...)에서 옴), grid(그 밖의 범위), 그 밖은 collection"""
    if iterable is not None and iterable.type in ("call", "call_expression"):
        text = src.text_of(iterable)
        if re.match(r"range\(", text):
            return "data" if "len(" in text else "grid"
    return "collection"


def _loop_info(src: SourceFile, loop: Node) -> LoopInfo | None:
    if loop.type in ("while_statement", "do_statement"):
        return None
    target, iterable = _loop_parts(src, loop)
    if loop.type == "for_statement" and loop.child_by_field_name("condition") is not None:  # JS·Java의 C 방식 for
        init = loop.child_by_field_name("initializer") or loop.child_by_field_name("init")
        condition = src.text_of(loop.child_by_field_name("condition"))
        sized = bool(re.search(r"\.length\b|\.size\(\)|\blen\(|\.count\b", condition))
        return LoopInfo(_names(src, init), set(re.findall(r"[A-Za-z_$][\w$]*", condition)), sized)
    if iterable is None:
        return None
    kind = _range_kind(src, iterable)
    sized = not _small_constant(src, iterable) and kind != "grid"
    return LoopInfo(_names(src, target), _names(src, iterable), sized)


def _derived_names(src: SourceFile, outer: Node, inner: Node, names: set[str]) -> set[str]:
    """바깥 반복 시작부터 안쪽 반복 직전까지, 바깥 항목 이름을 쓰는 값으로 만들어지거나 채워진 변수를 파생 이름으로 더한다(고정점까지)
    대입(`a = f(x)`, `a, b = x[i], y[i]`)과 채우기(`a.append(f(x))`, `a.add(x)`, `a[k] = x`)를 본다."""
    first, last = outer.start_point[0], inner.start_point[0]
    edges: list[tuple[set[str], set[str]]] = []
    for line in src.lines[first : last + 1]:
        m = ASSIGNMENT.match(line)
        if m:
            targets = {t for t in re.findall(r"[A-Za-z_$][\w$]*", m.group(1))}
            edges.append((targets, set(re.findall(r"[A-Za-z_$][\w$]*", m.group(2)))))
        loop_line = FOR_LINE.match(line)
        if loop_line:  # 중간 반복의 변수도 그 반복 대상에서 파생된다
            edges.append((set(re.findall(r"[A-Za-z_$][\w$]*", loop_line.group(1))), set(re.findall(r"[A-Za-z_$][\w$]*", loop_line.group(2)))))
        for fill in FILL.finditer(line):
            edges.append(({fill.group(1)}, set(re.findall(r"[A-Za-z_$][\w$]*", fill.group(2) or fill.group(3) or ""))))
    result = set(names)
    changed = True
    while changed:
        changed = False
        for targets, used in edges:
            if used & result and not targets <= result:
                result |= targets
                changed = True
    return result


class NestedLoopRule(PerfRule):
    rule_id = "PERF-102"
    name = "중첩 반복(O(n²) 이상)과 반복 안의 리스트 찾기 탐지"
    severity = Severity.LOW
    plain = (
        "반복문 안에서 또 다른 컬렉션을 통째로 도는 코드는 데이터가 늘수록 일하는 횟수가 곱으로 늘어납니다. 1,000개 × 1,000개면 100만 번, 10만 개 × 10만 개면 100억 번입니다. "
        "반복문 안에서 리스트에 `in`으로 값을 찾는 것도 같은 문제입니다. 리스트는 앞에서부터 하나씩 확인하기 때문입니다. 지금 데이터가 적으면 문제가 안 보이다가 사용자가 늘면 갑자기 느려집니다."
    )
    how_to_fix = (
        "찾는 대상을 먼저 `set`이나 `dict`로 바꿔 두면 한 번에 찾습니다. 예) 고치기 전: `for a in A:\\n    for b in B:\\n        if a.id == b.id: ...`  "
        "고친 뒤: `by_id = {b.id: b for b in B}` 를 반복문 밖에서 만들고 `by_id.get(a.id)` 로 찾기. 리스트 `in` 검사는 `set(리스트)`로 바꾸세요. "
        "느린지 직접 재려면 `python -m timeit` 이나 `cProfile`을 쓰세요."
    )

    def check(self, src: SourceFile) -> list[Violation]:
        if not self.usable(src):
            return []
        found: list[Violation] = []
        reported: set[int] = set()
        for node in walk(src.root):
            if node.type in LOOP_TYPES:
                found.extend(self._nested(src, node, reported))
            if node.type == "comparison_operator" and src.lang is Lang.PYTHON:
                found.extend(self._membership(src, node, reported))
            elif node.type == "call_expression" and src.lang in JS_FAMILY:
                found.extend(self._js_membership(src, node, reported))
            if len(found) >= MAX_PER_FILE:
                break
        return found

    def _nested(self, src: SourceFile, loop: Node, reported: set[int]) -> list[Violation]:
        """서로 관계없는 두 컬렉션을 곱으로 도는 반복만 지적한다. 격자 순회(range·고정 크기), 바깥 항목 안을 도는 반복, while 반복은 제외한다."""
        if loop.type in ("list_comprehension", "set_comprehension", "dictionary_comprehension", "generator_expression"):
            return self._comprehension_nested(src, loop, reported)
        info = _loop_info(src, loop)
        outer = [lp for lp in _loops_around(loop) if lp.type not in COMPREHENSION_TYPES]
        if info is None or not info.sized or not outer:
            return []  # 안쪽 반복이 고정 크기이거나 격자 한 축이면 곱이 커지지 않는다
        chain = [_loop_info(src, lp) for lp in outer if lp.type not in ("while_statement", "do_statement")]
        if not chain or any(c is None for c in chain):
            return []
        if any(not c.sized for c in chain if c is not None):
            return []  # 바깥 반복이 고정 크기이거나 격자 한 축이면 곱이 데이터 크기에 비례하지 않는다
        outer_names: set[str] = set()
        for c in chain:
            if c is not None:
                outer_names |= c.targets
        outer_names = _derived_names(src, outer[0], loop, outer_names)
        if self._table_fill(src, loop, outer_names | info.targets):
            return []  # 이웃 칸을 읽으며 표를 채우는 알고리즘(편집 거리·최장 공통 부분열 등)은 곱 크기가 본래 필요하다
        if info.iterable_names & outer_names:
            return []  # 바깥 반복의 항목(또는 거기서 파생한 값) 안을 도는 것은 전체 크기에 비례한다
        line = loop.start_point[0] + 1
        if line in reported:
            return []
        reported.add(line)
        depth = len(chain) + 1
        severity = Severity.MEDIUM if depth >= 3 else Severity.LOW
        return [self._violation(src, loop, f"{depth}중 반복에서 서로 관계없는 컬렉션을 모두 돕니다. 데이터가 늘면 일의 양이 곱으로 늘어납니다.", severity=severity)]

    @staticmethod
    def _table_fill(src: SourceFile, loop: Node, index_names: set[str]) -> bool:
        names = [n for n in index_names if re.fullmatch(r"[A-Za-z_$][\w$]*", n) and n not in ("let", "const", "var", "int", "for")]
        if not names:
            return False
        alt = "|".join(re.escape(n) for n in names)
        return re.search(rf"\[\s*(?:{alt})\s*-\s*1\s*\]", src.text_of(loop)) is not None

    def _comprehension_nested(self, src: SourceFile, loop: Node, reported: set[int]) -> list[Violation]:
        clauses = _comprehension_clauses(loop)
        out: list[Violation] = []
        outer_names: set[str] = set()
        for i, clause in enumerate(clauses):
            target, iterable = _loop_parts(src, clause)
            kind = _range_kind(src, iterable)
            sized = not _small_constant(src, iterable) and kind != "grid"
            if i > 0 and sized and not (_names(src, iterable) & outer_names):
                line = clause.start_point[0] + 1
                if line not in reported:
                    reported.add(line)
                    out.append(self._violation(src, clause, "한 컴프리헨션에서 서로 관계없는 두 컬렉션을 모두 돌아 데이터가 늘면 일의 양이 곱으로 늘어납니다."))
            if not sized:
                return out
            outer_names |= _names(src, target)
        return out

    def _membership(self, src: SourceFile, node: Node, reported: set[int]) -> list[Violation]:
        if len(node.named_children) != 2 or not _loops_around(node):
            return []
        left, right = node.named_children
        between = src.data[left.end_byte : right.start_byte].decode("utf-8", errors="replace")
        if not re.fullmatch(r"\s*(not\s+in|in)\s*", between) or right.type != "identifier":
            return []
        if not self._is_list_variable(src, node, src.text_of(right)):
            return []
        line = node.start_point[0] + 1
        if line in reported:
            return []
        reported.add(line)
        return [self._violation(src, node, "반복문 안에서 리스트에 `in`으로 값을 찾습니다. 리스트는 앞에서부터 하나씩 확인하므로 데이터가 늘면 급격히 느려집니다.", severity=Severity.MEDIUM)]

    def _js_membership(self, src: SourceFile, node: Node, reported: set[int]) -> list[Violation]:
        func = node.child_by_field_name("function")
        if func is None or func.type != "member_expression" or not _loops_around(node):
            return []
        text = src.text_of(func)
        m = re.fullmatch(r"([A-Za-z_$][\w$]*)\.(includes|indexOf)", text)
        if m is None or not self._is_list_variable(src, node, m.group(1)):
            return []
        line = node.start_point[0] + 1
        if line in reported:
            return []
        reported.add(line)
        return [self._violation(src, node, f"반복문 안에서 배열의 {m.group(2)}로 값을 찾습니다. 배열은 앞에서부터 하나씩 확인하므로 데이터가 늘면 급격히 느려집니다.", severity=Severity.MEDIUM)]

    @staticmethod
    def _is_list_variable(src: SourceFile, node: Node, name: str) -> bool:
        """같은 함수 안에서 리스트·배열 리터럴, list(), 컴프리헨션, split()으로 만든 변수인가(형을 모르면 거짓)"""
        scope = _function_of(node)
        text = src.text_of(scope) if scope is not None else src.text
        escaped = re.escape(name)
        m = re.search(rf"(?m)^\s*(?:const\s+|let\s+|var\s+)?{escaped}\s*(?::[^=\n]+)?=\s*(\[[^\n]*\]|list\(|sorted\(|Array\.from\(|[\w.]+\.split\()([^\n]*)$", text)
        if m is None:
            return False
        if re.search(r"\)\s*(\[|\.\w+)", m.group(2)) or re.match(r"\]\s*\.", m.group(2)):
            return False  # 뒤에 인덱스나 메서드가 이어지면 목록이 아니라 그 결과(문자열 등)다
        literal = m.group(1)
        if literal.startswith("[") and literal.endswith("]") and "," in literal:
            return literal.count(",") + 1 > SMALL_LITERAL  # 원소가 몇 개 안 되는 고정 목록은 찾기 비용이 문제되지 않는다
        return True  # 빈 목록 `[]`는 반복하며 커질 수 있다

    def _violation(self, src: SourceFile, node: Node, message: str, severity: Severity = Severity.LOW) -> Violation:
        return self.at_node(src, node, message, severity=severity, confidence=Confidence.REVIEW)


class ExpensiveInLoopRule(PerfRule):
    rule_id = "PERF-103"
    name = "반복 안의 비싼 작업(요청·파일·순차 대기) 탐지"
    severity = Severity.LOW
    plain = (
        "반복문 안에서 인터넷 요청, 파일 열기, 외부 프로그램 실행을 하면 그 작업이 항목 수만큼 되풀이됩니다. 손님이 올 때마다 가게 문을 새로 짓는 것과 같습니다. "
        "`await`를 반복문 안에서 하나씩 기다리면 서로 기다릴 필요가 없는 작업도 줄을 서서 처리합니다."
    )
    how_to_fix = (
        "반복문 밖에서 한 번만 준비하고(파일은 한 번 읽어 두기, 연결은 세션 재사용), 서로 독립적인 요청은 한꺼번에 보내세요. "
        "예) 고치기 전: `for u in urls:\\n    r = await fetch(u)`  고친 뒤: `rs = await asyncio.gather(*(fetch(u) for u in urls))`. "
        "항목이 몇 개 안 되면 그대로 두어도 됩니다. 느린지 직접 재서 판단하세요."
    )

    def check(self, src: SourceFile) -> list[Violation]:
        if not self.usable(src):
            return []
        found: list[Violation] = []
        reported: set[int] = set()
        for call in iter_calls(src):
            loops = _loops_around(call.node)
            if not loops or call.line in reported or self._constant_loop(src, loops):
                continue
            kind = self._kind(call.callee)
            if kind is None:
                continue
            reported.add(call.line)
            found.append(self.at_node(src, call.node, f"반복문 안에서 {kind}을(를) 합니다. 항목 수만큼 되풀이됩니다.", severity=Severity.LOW, confidence=Confidence.REVIEW))
        for node in walk(src.root):
            if node.type == "await_expression" or node.type == "await":
                loops = [lp for lp in _loops_around(node) if lp.type in ("for_statement", "for_in_statement", "enhanced_for_statement")]
                line = node.start_point[0] + 1
                if loops and line not in reported and not self._constant_loop(src, loops) and NETWORK_AWAIT.search(self._callee_text(node, src)) and not SLEEP_AWAIT.search(src.text_of(node)):
                    reported.add(line)
                    found.append(self.at_node(src, node, "반복문 안에서 `await`로 하나씩 기다립니다. 서로 독립적인 작업이면 한꺼번에 보내는 편이 빠릅니다.", severity=Severity.LOW, confidence=Confidence.REVIEW))
            if len(found) >= MAX_PER_FILE:
                break
        return found

    @staticmethod
    def _callee_text(node: Node, src: SourceFile) -> str:
        """`await f(args)`에서 인자를 뺀 호출 대상 부분. 인자 속 단어(api 등)로 요청이라 오인하지 않는다."""
        return re.sub(r"^\s*await\s+", "", src.text_of(node)).split("(", 1)[0]

    @staticmethod
    def _constant_loop(src: SourceFile, loops: list[Node]) -> bool:
        """고정 크기 반복이거나 재시도 반복이면 참. 재시도(attempt·retry)는 앞 시도가 끝나야 다음 시도를 하므로 순차가 맞다."""
        for loop in loops:
            target, iterable = _loop_parts(src, loop)
            if iterable is not None and _small_constant(src, iterable):
                return True
            names = _names(src, target) | _names(src, loop.child_by_field_name("initializer"))
            if any(RETRY_NAME.search(n) for n in names) or (iterable is not None and _range_kind(src, iterable) != "collection"):
                return True
            if ExpensiveInLoopRule._sequential_by_design(src, loop, iterable):
                return True
        return False

    @staticmethod
    def _sequential_by_design(src: SourceFile, loop: Node, iterable: Node | None) -> bool:
        """순서나 앞 결과에 기대는 반복이면 참: 끝없이 되풀이하는 확인(polling)·시간 조건 반복, 먼저 성공한 것에서 멈추는 반복, 쪽·묶음 단위 반복"""
        if loop.type == "for_statement" and loop.child_by_field_name("condition") is None and iterable is None:
            return True
        if loop.type in ("while_statement", "do_statement"):
            condition = src.text_of(loop.child_by_field_name("condition")) if loop.child_by_field_name("condition") is not None else ""
            if re.fullmatch(r"\(?\s*(true|True|1)\s*\)?", condition.strip()) or re.search(r"(?i)Date\.now|time\.|monotonic|elapsed|deadline|timeout", condition):
                return True
        if iterable is not None and re.search(r"(?i)chunk|batch|page|shard", src.text_of(iterable)):
            return True
        body = loop.child_by_field_name("body")
        return body is not None and re.search(r"\b(break|return)\b", src.text_of(body)) is not None

    @staticmethod
    def _kind(callee: str) -> str | None:
        """반복 안에서 문제 삼을 작업. 항목마다 파일을 읽거나 프로그램을 부르는 것은 반복의 본래 목적이라 제외하고 인터넷 요청만 본다."""
        if HTTP_CALL.match(callee):
            return "인터넷 요청"
        return None


class UnboundedQueryRule(PerfRule):
    rule_id = "PERF-104"
    name = "한도 없는 조회 탐지"
    severity = Severity.LOW
    plain = (
        "조건이나 개수 제한 없이 테이블 전체를 가져오면 데이터가 쌓일수록 한 번의 요청이 점점 무거워지고, 어느 날 서버 메모리가 부족해 멈춥니다. "
        "지금은 행이 100개뿐이라 괜찮아 보여도 10만 개가 되면 같은 코드가 문제를 일으킵니다."
    )
    how_to_fix = (
        "필요한 만큼만 가져오세요: `LIMIT 50`, 페이지 번호(`OFFSET`), 조건(`WHERE`). ORM이면 `.limit(50)`, 슬라이스 `[:50]`, `Paginator`를 쓰세요. "
        "전체가 정말 필요하면 한 번에 다 읽지 말고 `fetchmany(1000)`처럼 나눠서 처리하세요."
    )
    all_call = re.compile(r"(?:^|\.)(fetchall|findAll|findMany)$")
    orm_all = re.compile(r"(?i)(objects|query|session|repo\w*|repository|\w*Repository)\b.*\.all$|\.objects\.all$|\.query\.all$")

    def check(self, src: SourceFile) -> list[Violation]:
        if not self.usable(src):
            return []
        found: list[Violation] = []
        reported: set[int] = set()
        for call in iter_calls(src):
            if call.line in reported:
                continue
            message = self._unbounded(src, call)
            if message is None:
                continue
            reported.add(call.line)
            found.append(self.at_node(src, call.node, message, severity=Severity.LOW, confidence=Confidence.REVIEW))
            if len(found) >= MAX_PER_FILE:
                break
        return found

    def _unbounded(self, src: SourceFile, call) -> str | None:
        callee = call.callee
        statement = self._statement_text(src, call.node)
        has_limit = re.search(r"(?i)\.limit\(|\[\s*:\s*\d+\s*\]|\bpageable\b|\btake\s*:|\blimit\s*:|\bPageRequest\b|\.paginate\(|Paginator", statement)
        bounded_sql = SQL_BOUNDED.search(statement) is not None
        if callee.endswith(".fetchall") and not has_limit:
            if bounded_sql or self._previous_sql_bounded(src, call.node):
                return None  # 조건·집계가 있는 조회의 결과다
            return "`fetchall()`은 조회 결과를 한 번에 모두 메모리로 가져옵니다. 데이터가 쌓이면 서버 메모리가 부족해질 수 있습니다."
        if callee.endswith(".findAll") and not call.args and not has_limit:
            return "`findAll()`은 테이블 전체를 가져옵니다. 페이지 단위(Pageable)로 가져오세요."
        if callee.endswith(".findMany") and not call.args and not has_limit:
            return "`findMany()`에 조건·개수 제한이 없어 테이블 전체를 가져옵니다."
        if self.orm_all.search(callee) and callee.endswith(".all") and not has_limit and not bounded_sql:
            return "`.all()`은 조건 없이 테이블 전체를 가져옵니다. 개수 제한이나 페이지를 붙이세요."
        if re.search(r"(?:^|\.)(execute|executemany|query|raw|prepareStatement|createQuery|createNativeQuery)$", callee) and call.args:
            first = call.args[0]
            if first.type in ("string", "string_literal", "template_string", "concatenated_string"):
                sql = src.text_of(first).strip("\"'`")
                if UNBOUNDED_SQL.match(sql) and not SQL_LIMITED.search(sql) and not SQL_BOUNDED.search(sql) and not has_limit:
                    return "`SELECT`에 `WHERE`·`LIMIT`이 없어 테이블 전체를 가져옵니다."
        return None

    @staticmethod
    def _previous_sql_bounded(src: SourceFile, node: Node) -> bool:
        """같은 함수에서 이 호출 앞의 가장 가까운 SQL 문자열에 조건·집계가 있는가"""
        fn = _function_of(node)
        text = src.text_of(fn) if fn is not None else src.text
        before = text[: max(0, node.start_byte - (fn.start_byte if fn is not None else 0))]
        sqls = re.findall(r"(?is)(select\b.*?)(?:[\"'`]\s*[,)]|[\"'`]\s*$|\"\"\"|$)", before)
        return bool(sqls) and SQL_BOUNDED.search(sqls[-1]) is not None

    @staticmethod
    def _statement_text(src: SourceFile, node: Node) -> str:
        current = node
        while current.parent is not None and current.parent.type not in FUNCTION_TYPE_SET and current.parent.type not in ("module", "program", "block", "statement_block", "class_body"):
            current = current.parent
        return src.text_of(current)


class BlockingInAsyncRule(PerfRule):
    rule_id = "PERF-105"
    name = "비동기 함수 안의 막는 호출 탐지"
    severity = Severity.MEDIUM
    plain = (
        "비동기(`async`) 서버는 한 줄로 모든 사용자를 처리합니다. 그 안에서 `time.sleep`이나 동기 `requests` 같은 '기다리는 호출'을 하면 그동안 다른 모든 사용자의 요청이 멈춥니다. "
        "한 명이 줄을 서면 뒤 사람이 모두 기다리는 것과 같습니다."
    )
    how_to_fix = (
        "비동기용 짝을 쓰세요. `time.sleep` → `await asyncio.sleep`, `requests` → `httpx.AsyncClient`/`aiohttp`, 파일·외부 프로그램 → `asyncio.to_thread(...)`로 별도 스레드에서 실행. "
        "JS는 `readFileSync` 대신 `await fs.promises.readFile`을 쓰세요."
    )

    def check(self, src: SourceFile) -> list[Violation]:
        if not self.usable(src):
            return []
        found: list[Violation] = []
        reported: set[int] = set()
        asyncs = [fn for fn in iter_functions(src) if self._is_async(src, fn.node)]
        if not asyncs:
            return []
        server_like = src.lang is Lang.PYTHON or SERVER_MARKERS.search(src.text) is not None  # JS·TS의 CLI 스크립트는 동기 호출이 흔해 서버 코드에서만 본다
        for call in iter_calls(src):
            if call.line in reported or not BLOCKING_IN_ASYNC.match(call.callee) or not server_like:
                continue
            owner = self._owner_async(src, call.node)
            if owner is None:
                continue
            reported.add(call.line)
            light = bool(re.match(r"^fs\.", call.callee))  # 작은 파일의 동기 읽기·쓰기는 영향이 작아 낮게 둔다. sleep·요청·프로그램 실행은 오래 멈춘다
            found.append(self.at_node(src, call.node, "비동기 함수 안에서 기다리는(막는) 호출을 합니다. 다른 모든 요청이 그동안 멈춥니다.", severity=Severity.LOW if light else Severity.MEDIUM, confidence=Confidence.REVIEW))
            if len(found) >= MAX_PER_FILE:
                break
        return found

    @staticmethod
    def _is_async(src: SourceFile, fn: Node) -> bool:
        head = src.text_of(fn)[:40]
        return head.lstrip().startswith("async") or (fn.parent is not None and fn.parent.type == "decorated_definition" and "async def" in src.text_of(fn)[:20])

    def _owner_async(self, src: SourceFile, node: Node) -> Node | None:
        """가장 가까운 함수가 async이면 그 함수(중첩 일반 함수는 제외)"""
        fn = _function_of(node)
        if fn is None:
            return None
        return fn if self._is_async(src, fn) else None


class ManyQueriesRule(PerfRule):
    rule_id = "PERF-101"
    name = "한 함수 안의 DB 조회 과다 탐지"
    severity = Severity.LOW
    plain = (
        "화면 하나를 만들려고 DB에 여러 번 따로 묻는 코드는 한 번에 묻는 코드보다 훨씬 느립니다. DB에 한 번 갔다 오는 데 걸리는 시간이 매번 더해지기 때문입니다. "
        f"한 함수에서 반복문 밖에서도 DB 호출이 {QUERY_LIMIT}번 이상이면 알려 드립니다."
    )
    how_to_fix = (
        "여러 번 묻는 것을 `JOIN`이나 `IN (...)` 조건으로 한 번에 가져오세요. 같은 값을 여러 번 조회하면 변수에 담아 재사용하고, 자주 바뀌지 않는 값은 캐시하세요. "
        "ORM이면 `select_related`/`prefetch_related`(Django), `joinedload`(SQLAlchemy), `include`(Prisma)를 쓰세요."
    )

    def check(self, src: SourceFile) -> list[Violation]:
        if not self.usable(src):
            return []
        in_loop_lines = {c.line for c in iter_calls(src) if DbInLoopRule._db_call_kind(c.callee, src.lang) and _loops_around(c.node)}
        per_function: dict[int, list] = {}
        for call in iter_calls(src):
            if DbInLoopRule._db_call_kind(call.callee, src.lang) is None or call.line in in_loop_lines:
                continue
            fn = _function_of(call.node)
            if fn is None:
                continue
            per_function.setdefault(fn.id, []).append(call)
        found: list[Violation] = []
        for calls in per_function.values():
            if len(calls) < QUERY_LIMIT:
                continue
            first = min(calls, key=lambda c: c.node.start_byte)
            severity = Severity.MEDIUM if len(calls) >= QUERY_LIMIT * 2 else Severity.LOW
            found.append(
                self.at_node(src, first.node, f"한 함수 안에서 DB를 {len(calls)}번 호출합니다. 한 번에 가져올 수 있는지 확인하세요.", severity=severity, confidence=Confidence.REVIEW)
            )
        return found[:MAX_PER_FILE]


PERF_RULES: list[type[BaseRule]] = [
    ManyQueriesRule,
    NestedLoopRule,
    ExpensiveInLoopRule,
    UnboundedQueryRule,
    BlockingInAsyncRule,
]
