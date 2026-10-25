"""architecture practices 규칙."""
import re
from collections import Counter, defaultdict

from tree_sitter import Node

from iron_laws.core.models import Confidence, Severity, Violation
from iron_laws.engine.ast_tools import (
    call_index,
    enclosing_function,
    is_literal,
    is_string_node,
    iter_calls,
    iter_functions,
    string_value,
)
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.python_bindings import is_regex_call
from iron_laws.engine.source import SourceFile
from iron_laws.rules.ai_code import HardcodedConfigRule
from iron_laws.rules.architecture_common import (
    CENTRAL_ERROR_FILE,
    DB_READ,
    DB_RECEIVER,
    DB_WRITE,
    EXCEPTION_CALLEE,
    FUNCTION_TYPE_SET,
    KEY_CALLEE,
    LOOP_NODE_TYPES,
    REQUEST_HOOK_NAMES,
    REUSABLE_PATTERNS,
    STANDARD_HEADER_RE,
    ArchRule,
    _is_generated,
)


class RepeatedLiteralRule(ArchRule):
    rule_id = "ARC-205"
    name = "여러 곳에 반복된 문자열 상수 탐지"
    severity = Severity.LOW
    plain = "같은 문자열(주소, 키 이름, 상태값)을 여러 파일에 직접 적어 두면 하나를 바꿀 때 나머지를 빼먹어 오류가 납니다."
    how_to_fix = "반복되는 값은 상수나 설정 모듈에 한 번만 정의하고 이름으로 참조하세요."

    def check(self, src: SourceFile) -> list[Violation]:
        return []

    def check_project(self, project: ProjectContext) -> list[Violation]:
        helper = HardcodedConfigRule()
        counts: Counter[str] = Counter()
        places: dict[str, list[tuple[SourceFile, Node]]] = defaultdict(list)
        for src in project.source_files():
            if src.root is None or _is_generated(src):
                continue
            for node in src.nodes:
                if not is_string_node(node) or not is_literal(node):
                    continue
                if node.parent is not None and is_string_node(node.parent):
                    continue
                value = string_value(src, node)
                if len(value) < 10 or len(value) > 120 or "\n" in value or re.search(r"\s{2,}", value):
                    continue
                if helper._in_skipped_call(src, node):
                    continue
                if re.match(r"^[./@]|^\w+://|^(application|text|image)/", value) and "/" in value and " " not in value and not value.startswith(("http", "ws")):
                    continue
                counts[value] += 1
                places[value].append((src, node))
        found = []
        for value, n in counts.most_common():
            files = {s.path for s, _ in places[value]}
            if n < 4 or len(files) < 2:
                continue
            src, node = places[value][0]
            found.append(self.at_node(src, node, f"문자열 '{value[:40]}'이(가) {len(files)}개 파일, {n}곳에 반복됩니다. 상수로 분리하십시오.", confidence=Confidence.REVIEW))
            if len(found) >= 15:
                break
        return found


class DtoMapMixRule(ArchRule):
    rule_id = "ARC-208"
    name = "DTO 대신 Map·딕셔너리를 데이터 객체로 혼용"
    severity = Severity.LOW
    plain = "요청·응답 데이터를 Map이나 딕셔너리로 주고받으면 어떤 필드가 있는지 코드만 봐서는 알 수 없고, 오타가 나도 컴파일러가 잡지 못합니다. 데이터 객체(DTO)와 섞어 쓰면 더 헷갈립니다."
    how_to_fix = "용도별로 DTO(Java record·class, C# record, TypeScript interface, Python dataclass·pydantic)를 정의하고 요청·응답·서비스 경계에서는 그 타입만 쓰세요."
    signature_re = re.compile(
        r"(?:Hash)?Map<\s*String\s*,\s*(?:Object|\?)\s*>|(?:I)?Dictionary<\s*string\s*,\s*object\s*>|Record<\s*string\s*,\s*(?:any|unknown)\s*>|\{\s*\[\w+:\s*string\]\s*:\s*(?:any|unknown)\s*\}|(?:dict|Dict)\[\s*str\s*,\s*(?:Any|object)\s*\]"
    )

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang is None or src.root is None or src.is_test or _is_generated(src):
            return []
        hits = []
        for fn in iter_functions(src):
            end = fn.body.start_byte if fn.body is not None else fn.node.end_byte
            signature = src.data[fn.node.start_byte : end].decode("utf-8", errors="replace")
            if self.signature_re.search(signature):
                hits.append(fn)
        if len(hits) < 3:
            return []
        return [
            self.at_node(
                src,
                hits[0].node,
                f"메서드 {len(hits)}개가 Map·딕셔너리를 매개변수나 반환 타입으로 씁니다. DTO를 정의해 쓰십시오.",
                confidence=Confidence.REVIEW,
            )
        ]


class ErrorMessageScatterRule(ArchRule):
    rule_id = "ARC-209"
    name = "에러 코드·메시지가 여러 곳에 흩어져 하드코딩됨"
    severity = Severity.LOW
    plain = "오류 메시지가 던지는 곳마다 문자열로 적혀 있으면 같은 오류가 서로 다른 문구로 나가고, 문구를 고치거나 다국어로 바꿀 때 전부 찾아다녀야 합니다."
    how_to_fix = "에러 코드와 메시지를 enum이나 상수 파일 한 곳에 모으고, 예외를 던지는 곳에서는 코드만 참조하세요. 응답에는 코드와 메시지를 함께 담는 공통 형식을 쓰세요."

    def check_project(self, project: ProjectContext) -> list[Violation]:
        if any(CENTRAL_ERROR_FILE.search(f.path.as_posix()) for f in project.files):
            return []
        messages: dict[str, list[tuple[SourceFile, Node]]] = defaultdict(list)
        for src in project.source_files():
            if src.root is None or _is_generated(src):
                continue
            for call in iter_calls(src):
                if not EXCEPTION_CALLEE.search(call.callee) or not call.args:
                    continue
                arg = call.args[0]
                if is_string_node(arg) and is_literal(arg):
                    value = string_value(src, arg)
                    if len(value) >= 4:
                        messages[value].append((src, arg))
        files = {s.path for places in messages.values() for s, _ in places}
        if len(messages) < 12 or len(files) < 3:
            return []
        src, node = next(iter(messages.values()))[0]
        return [
            self.at_node(
                src,
                node,
                f"예외 메시지 {len(messages)}종이 {len(files)}개 파일에 문자열로 흩어져 있고 에러 코드·메시지 중앙 정의(enum, 상수 파일)가 보이지 않습니다.",
                confidence=Confidence.REVIEW,
            )
        ]


class AttributeKeyRule(ArchRule):
    rule_id = "ARC-210"
    name = "속성·헤더 키 문자열이 호출부마다 흩어져 반복됨"
    severity = Severity.LOW
    plain = "request 속성이나 헤더 이름을 호출하는 곳마다 문자열로 적으면 오타 하나로 값이 사라지고, 데이터 구조를 바꿀 때 어디를 고쳐야 하는지 알 수 없습니다."
    how_to_fix = "키 이름은 상수(또는 enum)로 한 곳에 정의하고, 전달하는 데이터는 DTO로 명확히 정의해 호출부가 문자열 키를 직접 다루지 않게 하세요."

    def check_project(self, project: ProjectContext) -> list[Violation]:
        keys: dict[str, list[tuple[SourceFile, Node]]] = defaultdict(list)
        for src in project.source_files():
            if src.root is None or _is_generated(src):
                continue
            for call in iter_calls(src):
                if not (KEY_CALLEE.search(call.callee) and call.args and is_string_node(call.args[0]) and is_literal(call.args[0])):
                    continue
                if src.lang in JS_FAMILY and call.callee.endswith(("getAttribute", "setAttribute", "removeAttribute")):
                    continue  # DOM 속성 이름
                key = string_value(src, call.args[0])
                if STANDARD_HEADER_RE.match(key):
                    continue
                keys[key].append((src, call.args[0]))
        found = []
        for key, places in sorted(keys.items(), key=lambda kv: -len(kv[1])):
            if len(places) >= 3 and len(key) >= 3:
                src, node = places[0]
                found.append(
                    self.at_node(
                        src,
                        node,
                        f"키 문자열 '{key}'이(가) {len(places)}곳에서 직접 쓰입니다. 상수로 한 곳에 정의하십시오.",
                        confidence=Confidence.REVIEW,
                    )
                )
            if len(found) >= 10:
                break
        return found


class ReusableObjectRule(ArchRule):
    rule_id = "ARC-211"
    name = "스레드 안전·재사용 가능한 객체를 호출할 때마다 새로 생성"
    severity = Severity.LOW
    plain = "정규식 컴파일, JSON 변환기, HTTP 클라이언트는 만드는 비용이 큰데, 자주 불리는 함수 안에서 매번 새로 만들면 요청이 많아질수록 느려지고 자원이 낭비됩니다."
    how_to_fix = "스레드 안전한 객체는 static final 필드(또는 모듈 상수, 싱글턴·의존성 주입)로 한 번만 만들어 재사용하세요. HttpClient는 IHttpClientFactory·공유 인스턴스를 쓰세요."

    def check(self, src: SourceFile) -> list[Violation]:
        patterns = REUSABLE_PATTERNS.get(src.lang) if src.lang else None
        if not patterns or src.root is None or src.is_test or _is_generated(src):
            return []
        found = []
        for call in iter_calls(src):
            fn = enclosing_function(call.node, src.lang)
            if fn is None:
                continue
            for pattern, needs_literal, label in patterns:
                if not pattern.search(call.callee):
                    continue
                if needs_literal and not (call.args and is_literal(call.args[0])):
                    break
                if re.search(r"\bstatic\b", src.text_of(fn)[:60]) and re.match(r"\s*static\s*\{", src.text_of(fn)):
                    break
                is_http = "HttpClient" in label
                found.append(
                    self.at_node(
                        src,
                        call.node,
                        f"{label}을(를) 함수 안에서 매번 생성합니다. 한 번만 만들어 재사용하십시오.",
                        severity=Severity.MEDIUM if is_http and src.lang is Lang.CSHARP else Severity.LOW,
                        confidence=Confidence.REVIEW,
                    )
                )
                break
        return found[:15]


class DbInLoopRule(ArchRule):
    version = 3
    rule_id = "ARC-212"
    name = "반복문 안의 DB 조회(N+1)와 요청마다 반복되는 DB 조회"
    severity = Severity.MEDIUM
    plain = "목록의 항목마다 DB를 따로 조회하면 항목이 100개일 때 쿼리가 101번 나가서 데이터가 늘수록 급격히 느려집니다. 모든 요청의 필터에서 DB를 조회해도 같은 문제가 생깁니다."
    how_to_fix = "반복문 밖에서 IN 조건·JOIN·일괄 조회로 한 번에 가져오세요(JPA의 fetch join, 배치 조회). 요청마다 필요한 조회 결과(허용 IP, 권한 등)는 캐시하되 인스턴스가 여러 개이면 갱신이 모든 인스턴스에 반영되도록 만료·동기화 방식을 정하세요."

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang is None or src.root is None or src.is_test or _is_generated(src):
            return []
        found: list[Violation] = []
        reported: set[int] = set()
        calls = call_index(src)
        for call in calls.all:
            kind = None if is_regex_call(src, call) else self._db_call_kind(call.callee, src.lang)
            if kind is None:
                continue
            node = call.node.parent
            in_loop = False
            while node is not None:
                if node.type in LOOP_NODE_TYPES:
                    in_loop = True
                    break
                if node.type in FUNCTION_TYPE_SET:
                    break
                node = node.parent
            if in_loop and call.line not in reported:
                reported.add(call.line)
                found.append(
                    self.at_node(
                        src,
                        call.node,
                        f"반복문 안에서 {call.callee}로 DB를 호출합니다 (N+1 우려). 일괄 조회로 바꾸십시오.",
                        severity=Severity.MEDIUM if kind == "read" else Severity.LOW,
                        confidence=Confidence.REVIEW,
                    )
                )
        for fn in iter_functions(src):
            if not (REQUEST_HOOK_NAMES.match(fn.name) or self._is_middleware(src, fn)):
                continue
            for call in calls.functions.get(fn.node.id, []):
                if not is_regex_call(src, call) and self._db_call_kind(call.callee, src.lang) == "read" and call.line not in reported:
                    reported.add(call.line)
                    found.append(
                        self.at_node(
                            src,
                            call.node,
                            f"모든 요청이 지나는 {fn.name}에서 {call.callee}로 DB를 조회합니다. 요청마다 DB 부하가 생기니 캐시와 갱신 방식을 정하십시오.",
                            confidence=Confidence.REVIEW,
                        )
                    )
        return found

    @staticmethod
    def _is_middleware(src: SourceFile, fn) -> bool:
        """app.use()에 직접 등록된 함수만 모든 요청이 지나는 미들웨어로 본다."""
        if src.lang not in JS_FAMILY:
            return False
        parent = fn.node.parent
        grand = parent.parent if parent is not None else None
        if grand is None or grand.type not in ("call_expression",):
            return False
        callee = grand.child_by_field_name("function")
        return callee is not None and src.text_of(callee).endswith(".use")

    @staticmethod
    def _db_call_kind(callee: str, lang: Lang | None) -> str | None:
        if "." not in callee:
            return None
        receiver, method = callee.rsplit(".", 1)
        if lang is Lang.PYTHON and receiver.endswith(("session", "request", "g")) and method == "get":
            return None
        if not DB_RECEIVER.search(receiver):
            return None
        if DB_READ.match(method):
            return "read"
        if DB_WRITE.match(method):
            return "write"
        return None
