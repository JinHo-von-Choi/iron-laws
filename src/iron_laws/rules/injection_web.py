"""injection web 규칙."""
# iron-laws: ignore-file[IL-510] CSRF 해제 구문을 탐지하는 패턴 정의
import re

from tree_sitter import Node

from iron_laws.core.models import Confidence, IronLaw, Severity, Violation
from iron_laws.engine.ast_tools import (
    Call,
    enclosing_function,
    is_literal,
    iter_calls,
)
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import (
    Ctx,
    expr_has_source,
    is_tainted,
)
from iron_laws.rules.base import BaseRule
from iron_laws.rules.injection_common import (
    ESCAPER_RE,
    SinkRule,
    _context_text,
)
from iron_laws.rules.sinks import (
    CS,
    GO,
    JAVA,
    JS,
    PHP,
    PY,
    RUST,
    Flow,
    Sink,
    assess,
    looks_like_browser_script,
)
from iron_laws.standards import mois_ref


class XssRule(BaseRule):
    rule_id = "IL-505"
    name = "크로스사이트 스크립트(XSS) 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.HIGH
    gov_standard = mois_ref("1-4")
    plain = "사용자가 입력한 글이 화면에 그대로 출력되면 공격자가 다른 사용자의 브라우저에서 스크립트를 실행시켜 계정을 탈취할 수 있습니다."
    how_to_fix = (
        "출력할 때 HTML을 이스케이프하세요. 화면 갱신은 innerHTML 대신 textContent를 쓰고, "
        "HTML을 꼭 넣어야 하면 DOMPurify 같은 검증된 정제기를 거치세요. 템플릿의 |safe, th:utext, Html.Raw 사용을 피하세요."
    )
    dom_sink_props = re.compile(r"\.(innerHTML|outerHTML)$")
    js_html_calls = re.compile(r"(^|\.)(write|writeln|insertAdjacentHTML|html|append|prepend|after|before)$")
    resp_sinks = [
        Sink.of(JS, r"^(res|response|reply)\.(send|end|write)$"),
        Sink.of(JAVA, r"getWriter\(\)\.(print|println|write|append|printf|format)$", None),
        Sink.of(CS, r"^(Response\.Write|Html\.Raw|newHtmlString)$"),
        Sink.of(GO, r"^(fmt\.Fprintf|fmt\.Fprint|fmt\.Fprintln|io\.WriteString)$", 1),
        Sink.of(GO, r"^template\.HTML$"),
        Sink.of(PY, r"^(render_template_string|Markup|mark_safe|HttpResponse|HTMLResponse|make_response|Response)$"),
    ]

    def _unsafe_html_flow(self, src: SourceFile, arg: Node) -> Flow:
        context = _context_text(src, arg)
        if ESCAPER_RE.search(context):
            return Flow.SAFE
        flow = assess(src, arg, ctx=Ctx.HTML)
        if flow is Flow.TAINTED:
            return flow
        return Flow.SAFE

    def check(self, src: SourceFile) -> list[Violation]:
        if src.kind == "template":
            return self._check_template(src)
        found: list[Violation] = []
        if src.root is None:
            return found
        found.extend(self._dom_assignments(src))
        found.extend(self._jsx(src))
        writers = self._response_writers(src)
        for call in iter_calls(src):
            target, _, method = call.callee.rpartition(".")
            scope = enclosing_function(call.node, src.lang) if src.lang is Lang.JAVA else None
            if scope is not None and (scope.start_byte, target) in writers and method in ("print", "println", "write", "append", "printf", "format") and call.args:
                if self._json_response(src, scope, call.node):
                    continue  # JSON으로 내보내는 응답은 브라우저가 HTML로 해석하지 않는다
                if any(not is_literal(arg) and self._unsafe_html_flow(src, arg) is Flow.TAINTED for arg in call.args):
                    found.append(self.at_node(src, call.node, f"외부 입력이 이스케이프 없이 응답 출력 스트림({target})으로 출력됩니다."))
                continue
            if src.lang in JS_FAMILY and self.js_html_calls.search(call.callee):
                if re.search(r"(^|\.)(write|writeln)$", call.callee) and not call.callee.startswith("document."):
                    continue
                arg = call.args[-1] if call.args else None
                if arg is not None and not is_literal(arg) and not ESCAPER_RE.search(_context_text(src, arg)):
                    if call.callee.endswith((".html", ".append", ".prepend", ".after", ".before")) and not re.match(r"(\$|jQuery)", call.callee):
                        continue
                    flow = assess(src, arg, ctx=Ctx.HTML)
                    if flow is Flow.TAINTED:
                        found.append(self.at_node(src, call.node, f"외부 입력이 {call.callee}로 HTML에 그대로 삽입됩니다."))
                    elif call.callee.endswith(("insertAdjacentHTML", "document.write", "document.writeln")):
                        found.append(self.at_node(src, call.node, f"{call.callee}에 동적 값을 넣고 있습니다. 이스케이프 또는 정제 여부를 확인하십시오.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
                continue
            for sink in self.resp_sinks:
                if src.lang not in sink.langs or not sink.callee.search(call.callee):
                    continue
                indices = range(len(call.args)) if sink.arg is None else [sink.arg]
                for i in indices:
                    if i >= len(call.args):
                        continue
                    arg = call.args[i]
                    if src.lang is Lang.JAVA and (scope := enclosing_function(call.node, src.lang)) is not None and self._json_response(src, scope, call.node):
                        break
                    if self._unsafe_html_flow(src, arg) is Flow.TAINTED and self._htmlish(src, arg, call.callee):
                        found.append(self.at_node(src, call.node, f"외부 입력이 이스케이프 없이 {call.callee}로 응답에 출력됩니다."))
                        break
                break
        found.extend(self._php_echo(src))
        found.extend(self._python_return_html(src))
        return found

    RESPONSE_STREAM_RE = re.compile(r"\b\w*(?:[rR]esp|[rR]esponse)\w*\.(getWriter|getOutputStream)\s*\(\s*\)")

    JSON_CONTENT_RE = re.compile(r"setContentType\s*\(\s*(?:\"application/json|MediaType\.APPLICATION_JSON)|setHeader\s*\(\s*\"Content-Type\"\s*,\s*\"application/json")

    def _json_response(self, src: SourceFile, scope: Node, at: Node) -> bool:
        """출력(at)보다 앞서, 그 출력과 같은 경로에서 무조건 응답 콘텐츠 유형을 JSON으로 정한다.
        주석·일반 문자열이 아니라 설정 호출만 보며, 다른 분기에서만 JSON을 정하면 인정하지 않는다"""
        from iron_laws.rules.guards import executes_unconditionally, shared_scope

        json_calls = src.memo("json_content_calls", lambda: [c.node for c in iter_calls(src) if self.JSON_CONTENT_RE.search(src.code_of(c.node))])
        return any(
            scope.start_byte <= node.start_byte and node.end_byte <= at.start_byte and executes_unconditionally(node, shared_scope(node, at, scope))
            for node in json_calls
        )

    def _response_writers(self, src: SourceFile) -> set[tuple[int, str]]:
        """Java에서 응답 객체의 getWriter()·getOutputStream()을 (감싸서라도) 담은 (함수 시작 위치, 변수 이름).
        그 함수 안에서 그 변수의 print·write는 응답 출력이다. 다른 함수의 같은 이름 변수(로그 파일 writer 등)와 섞지 않는다"""
        if src.lang is not Lang.JAVA or src.root is None:
            return set()
        names: set[tuple[int, str]] = set()
        for node in src.nodes:
            if node.type not in ("variable_declarator", "assignment_expression"):
                continue
            left = node.child_by_field_name("name") or node.child_by_field_name("left")
            right = node.child_by_field_name("value") or node.child_by_field_name("right")
            if left is not None and right is not None and left.type == "identifier" and self.RESPONSE_STREAM_RE.search(src.text_of(right)):
                scope = enclosing_function(node, src.lang)
                if scope is not None:
                    names.add((scope.start_byte, src.text_of(left)))
        return names

    def _htmlish(self, src: SourceFile, arg: Node, callee: str) -> bool:
        if re.search(r"Markup|mark_safe|render_template_string|Html\.Raw|HtmlString|template\.HTML|getWriter|Response\.Write|Fprint|WriteString|^res\.|^response\.|^reply\.", callee):
            return True
        return bool(re.search(r"<\s*[a-zA-Z/]", _context_text(src, arg)))

    def _dom_assignments(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.lang not in JS_FAMILY or src.root is None:
            return found
        for node in src.nodes:
            if node.type != "assignment_expression":
                continue
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None or not self.dom_sink_props.search(src.text_of(left)):
                continue
            if is_literal(right) or ESCAPER_RE.search(_context_text(src, right)):
                continue
            if assess(src, right, ctx=Ctx.HTML) is Flow.TAINTED:
                found.append(self.at_node(src, node, f"외부 입력이 {src.text_of(left)}에 대입되어 DOM XSS가 발생할 수 있습니다."))
            else:
                found.append(self.at_node(src, node, f"{src.text_of(left)}에 동적 값을 대입합니다. textContent로 바꾸거나 정제 후 사용하십시오.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
        return found

    def _jsx(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.lang not in JS_FAMILY or src.root is None:
            return found
        for node in src.nodes:
            if node.type == "jsx_attribute" and "dangerouslySetInnerHTML" in src.text_of(node)[:40]:
                text = src.text_of(node)
                if ESCAPER_RE.search(text):
                    continue
                found.append(self.at_node(src, node, "dangerouslySetInnerHTML을 사용합니다. 정제된 값만 넣는지 확인하십시오.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
        return found

    def _php_echo(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.lang is not Lang.PHP or src.root is None:
            return found
        for node in src.nodes:
            if node.type in ("echo_statement", "print_intrinsic"):
                text = src.text_of(node)
                if ESCAPER_RE.search(text):
                    continue
                if expr_has_source(src, node) or any(
                    is_tainted(src, c, ctx=Ctx.HTML) for c in node.named_children if c.type != "echo"
                ):
                    found.append(self.at_node(src, node, "외부 입력을 이스케이프 없이 echo 합니다. htmlspecialchars()를 사용하십시오."))
        return found

    def _python_return_html(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.lang is not Lang.PYTHON or src.root is None:
            return found
        for node in src.nodes:
            if node.type != "return_statement" or not node.named_children:
                continue
            value = node.named_children[0]
            if value.type in ("string", "binary_operator") or (
                value.type == "call" and ".format" in src.text_of(value)
            ):
                text = src.text_of(value)
                if re.search(r"<\s*[a-zA-Z/]", text) and not ESCAPER_RE.search(text) and is_tainted(src, value, ctx=Ctx.HTML):
                    found.append(self.at_node(src, node, "외부 입력이 이스케이프 없이 HTML 문자열에 결합되어 반환됩니다."))
        return found

    def _check_template(self, src: SourceFile) -> list[Violation]:
        found = []
        pattern = re.compile(
            r"(?i)\|\s*safe\b|th:utext|v-html|@Html\.Raw|Html\.Raw\s*\(|\{!!|dangerouslySetInnerHTML|"
            r"\{%-?\s*autoescape\s+(?:false|off)|\|\s*raw\b|<%-|@\(Html\.Raw|MarkupString|\{@html"
        )
        for idx, line in enumerate(src.code_lines, start=1):
            if pattern.search(line):
                found.append(self.at_line(src, idx, "템플릿에서 이스케이프를 끄는 구문(|safe, th:utext, v-html, Html.Raw 등)을 사용합니다. 값이 정제되었는지 확인하십시오.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
        return found


class SsrfRule(SinkRule):
    rule_id = "IL-506"
    taint_ctx = Ctx.URL
    name = "서버사이드 요청 위조(SSRF) 탐지"
    severity = Severity.HIGH
    gov_standard = mois_ref("1-12")
    plain = "받은 주소로 서버가 대신 접속하게 하면 공격자가 내부 서버나 클라우드 인증 정보에 접근하도록 유도할 수 있습니다."
    how_to_fix = "접속 가능한 도메인을 허용 목록으로 제한하고, 내부 IP·메타데이터 주소(169.254.169.254, localhost 등)를 차단하세요. 리다이렉트 추적은 끄세요."
    dynamic_is_finding = False
    tainted_message = "외부 입력이 {callee}의 대상 주소로 쓰입니다. 허용 도메인 목록으로 제한하십시오."
    sinks = [
        Sink.of(PY, r"^(requests\.\w+|httpx\.\w+|urllib\.request\.urlopen|urlopen|urllib3\.\w+|aiohttp\.\w+|session\.\w+|client\.(get|post|request|put|delete)|http\.client\.\w+)$", None),
        Sink.of(JS, r"^(fetch|axios(\.\w+)?|got(\.\w+)?|request|needle\.\w+|https?\.(get|request)|superagent\.\w+|undici\.\w+|\$http\.\w+|ky(\.\w+)?)$", None),
        Sink.of(JAVA, r"^(newURL|newURI|URI\.create|newHttpGet|newHttpPost)$|(?i:rest\w*|template)\.(getForObject|getForEntity|postForObject|postForEntity|exchange)$", None),
        Sink.of(CS, r"^newUri$|WebRequest\.Create$|(?i:http\w*|client\w*|webclient|request\w*)\.(GetAsync|PostAsync|GetStringAsync|GetByteArrayAsync|SendAsync|DownloadString|DownloadFile|DownloadData)$", None),
        Sink.of(GO, r"^(http\.(Get|Post|Head|NewRequest|NewRequestWithContext)|client\.(Get|Do))$", None),
        Sink.of(PHP, r"^(curl_init|get_headers)$", None),
        Sink.of(PHP, r"^curl_setopt$", None),
        Sink.of(RUST, r"^reqwest::\w+$|(^|\.)(get|post)$", None),
    ]

    URL_KEYS = frozenset({"url", "uri", "baseURL", "baseUrl", "base_url", "endpoint", "host", "hostname"})

    def select_args(self, src: SourceFile, call: Call, sink: Sink) -> list[Node]:
        """요청 본문·헤더가 아니라 접속 대상이 되는 인자(위치 인자와 url 키워드)만 고른다."""
        callee = call.callee
        index = 0
        if src.lang is Lang.PYTHON and callee.endswith(".request"):
            index = 1  # requests.request(method, url)
        elif src.lang in JS_FAMILY and re.search(r"(^|\.)request$", callee) and len(call.args) >= 2 and call.args[0].type == "string":
            index = 1  # needle.request(method, url)
        elif src.lang is Lang.GO:
            index = {"http.NewRequest": 1, "http.NewRequestWithContext": 2}.get(callee, 0)
        elif src.lang is Lang.PHP and callee == "curl_setopt":
            if len(call.args) >= 3 and "CURLOPT_URL" in src.text_of(call.args[1]):
                return [call.args[2]]
            return []
        chosen: list[Node] = []
        if index < len(call.args):
            first = call.args[index]
            if first.type == "keyword_argument":
                chosen.extend(self._named(src, [first]))
            elif first.type in ("object", "dictionary"):
                chosen.extend(self._named(src, list(first.named_children)))
            else:
                chosen.append(first)
        chosen.extend(self._named(src, [a for a in call.args if a.type == "keyword_argument"]))
        return chosen

    def _named(self, src: SourceFile, nodes: list[Node]) -> list[Node]:
        values: list[Node] = []
        for node in nodes:
            if node.type == "keyword_argument":
                key, value = node.child_by_field_name("name"), node.child_by_field_name("value")
            elif node.type == "pair":
                key, value = node.child_by_field_name("key"), node.child_by_field_name("value")
            else:
                continue
            if key is not None and value is not None and src.text_of(key).strip("'\"") in self.URL_KEYS:
                values.append(value)
        return values

    def skip_hit(self, src: SourceFile, call: Call, arg: Node, flow: Flow) -> bool:
        if src.lang in JS_FAMILY and looks_like_browser_script(src):
            return True
        if call.callee.endswith((".get", ".post")) and src.lang is Lang.RUST and "reqwest" not in src.text:
            return True
        if call.callee.startswith("session.") and src.lang is Lang.PYTHON and "requests" not in src.text:
            return True
        return False


class OpenRedirectRule(SinkRule):
    rule_id = "IL-507"
    taint_ctx = Ctx.URL
    name = "신뢰되지 않는 URL로 자동접속(오픈 리다이렉트) 탐지"
    severity = Severity.MEDIUM
    gov_standard = mois_ref("1-7")
    plain = "받은 주소로 사용자를 보내면 공격자가 진짜 사이트처럼 보이는 링크로 사용자를 피싱 사이트에 보낼 수 있습니다."
    how_to_fix = "이동 가능한 경로를 허용 목록이나 서버 내부 상대 경로로 제한하세요. 외부 값은 목록의 키로만 사용하세요."
    dynamic_is_finding = False
    tainted_message = "외부 입력이 {callee}의 이동 주소로 쓰입니다. 허용된 경로 목록으로 제한하십시오."
    sinks = [
        Sink.of(PY, r"^(redirect|HttpResponseRedirect|RedirectResponse)$"),
        Sink.of(JS, r"(^|\.)redirect$", None),
        Sink.of(JAVA, r"(^|\.)sendRedirect$|^newRedirectView$"),
        Sink.of(CS, r"^(Redirect|RedirectPermanent)$"),
        Sink.of(GO, r"^http\.Redirect$", 2),
    ]

    def check(self, src: SourceFile) -> list[Violation]:
        found = super().check(src)
        if src.lang is Lang.PHP:
            for call in iter_calls(src):
                if call.callee == "header" and call.args:
                    text = src.text_of(call.args[0])
                    if re.search(r"(?i)location\s*:", text) and is_tainted(src, call.args[0]):
                        found.append(self.at_node(src, call.node, "외부 입력이 Location 헤더에 쓰입니다. 허용된 경로로 제한하십시오."))
        if src.lang in JS_FAMILY and src.root is not None and not looks_like_browser_script(src):
            for node in src.nodes:
                if node.type == "assignment_expression":
                    left = node.child_by_field_name("left")
                    right = node.child_by_field_name("right")
                    if left is not None and right is not None and re.search(r"(window\.)?location(\.href)?$", src.text_of(left)):
                        if not is_literal(right) and is_tainted(src, right):
                            found.append(self.at_node(src, node, "외부 입력이 location에 대입됩니다. 허용된 경로로 제한하십시오."))
        return found


class HeaderInjectionRule(SinkRule):
    rule_id = "IL-511"
    taint_ctx = Ctx.HEADER
    name = "HTTP 응답분할(헤더 삽입) 탐지"
    severity = Severity.MEDIUM
    gov_standard = mois_ref("1-13")
    plain = "받은 값이 응답 헤더에 섞이면 공격자가 줄바꿈을 넣어 가짜 응답이나 쿠키를 심을 수 있습니다."
    how_to_fix = "헤더·쿠키에 넣는 외부 값에서 CR/LF를 제거하거나 허용 문자만 남기세요. 프레임워크의 헤더 설정 API를 쓰세요."
    dynamic_is_finding = False
    tainted_message = "외부 입력이 {callee}로 응답 헤더에 쓰입니다. 개행 문자를 제거하십시오."
    sinks = [
        Sink.of(JS, r"^(res|response|reply)\.(setHeader|header|set|append|cookie)$", None),
        Sink.of(JAVA, r"(^|\.)(setHeader|addHeader|addCookie)$|^newCookie$", None),
        Sink.of(CS, r"Response\.(AppendHeader|AddHeader|Headers\.Add|Cookies\.Append)$", None),
        Sink.of(GO, r"\.Header\(\)\.(Set|Add)$|^http\.SetCookie$", None),
        Sink.of(PHP, r"^(header|setcookie)$", None),
    ]
