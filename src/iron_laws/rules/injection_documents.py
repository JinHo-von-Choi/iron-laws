"""injection documents 규칙."""
# iron-laws: ignore-file[IL-510] CSRF 해제 구문을 탐지하는 패턴 정의
import re

from tree_sitter import Node

from iron_laws.core.models import Confidence, IronLaw, Severity, Violation
from iron_laws.engine.ast_tools import (
    Call,
    enclosing_function,
    is_literal,
    iter_calls,
    iter_functions,
)
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.python_call_kinds import is_regex_call
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import (
    Ctx,
    definitions,
    is_tainted,
    reaching_definitions,
)
from iron_laws.engine.taint.closed import is_closed_value
from iron_laws.engine.xfile_python import qualified_name
from iron_laws.rules.base import BaseRule
from iron_laws.rules.guards import PassFacts
from iron_laws.rules.injection_common import (
    LDAP_TEXT_RE,
    XPATH_TEXT_RE,
    SinkRule,
    _context_text,
    _csrf_missing,
    quote_guard_verdict,
)
from iron_laws.rules.sinks import (
    CS,
    GO,
    JAVA,
    JS,
    PHP,
    PY,
    Flow,
    Sink,
    typed_names,
)
from iron_laws.standards import mois_ref


class LdapInjectionRule(SinkRule):
    version = 4
    rule_id = "IL-508"
    taint_ctx = Ctx.LDAP
    name = "LDAP 삽입 탐지"
    severity = Severity.HIGH
    gov_standard = mois_ref("1-10")
    plain = "받은 값이 디렉터리(LDAP) 검색 조건에 섞이면 공격자가 인증을 우회하거나 다른 사용자 정보를 조회할 수 있습니다."
    how_to_fix = "LDAP 필터에 들어가는 값은 이스케이프(ldap.filter.escape_filter_chars, Encoder.encodeForLDAP 등)한 뒤 결합하세요."
    tainted_message = "외부 입력이 LDAP 검색 필터에 결합되어 {callee}로 실행됩니다. 필터 값을 이스케이프하십시오."
    dynamic_message = "LDAP 검색 필터를 변수와 결합해 {callee}로 실행합니다. 값을 이스케이프하십시오."
    sinks = [
        Sink.of(PY, r"\.(search|search_s|search_ext|search_ext_s)$", None),
        Sink.of(JS, r"(^|\.)search$", None),
        Sink.of(JAVA, r"(^|\.)search$", None),
        Sink.of(CS, r"^newDirectorySearcher$", None),
        Sink.assigned(CS, r"\.Filter$"),  # DirectorySearcher.Filter = 필터. select_args가 수신자 형식을 확인한다
        Sink.of(PHP, r"^ldap_(search|list|read)$", None),
        Sink.of(GO, r"^ldap\.NewSearchRequest$", None),
    ]

    def select_args(self, src: SourceFile, call: Call, sink: Sink) -> list[Node]:
        """C# `search.Filter = 필터`는 search가 DirectorySearcher일 때만 본다"""
        if sink.prop:
            receiver = call.callee.rsplit(".", 1)[0]
            scope = enclosing_function(call.node, src.lang)
            defs = definitions(src, scope, receiver) if scope is not None and re.fullmatch(r"[A-Za-z_]\w*", receiver) else []
            if not defs or not all(re.match(r"new\s+(?:System\.DirectoryServices\.)?DirectorySearcher\b", src.text_of(d)) for d in defs):
                if receiver not in typed_names(src, r"DirectorySearcher", call.node):
                    return []
        return super().select_args(src, call, sink)

    def skip_hit(self, src: SourceFile, call: Call, arg: Node, flow: Flow) -> bool:
        if is_regex_call(src, call):
            return True
        text = _context_text(src, arg)
        if re.search(r"(?i)escape_filter|encodeForLDAP|ldap\.EscapeFilter|escapeLDAP", text):
            return True
        return not LDAP_TEXT_RE.search(text)


class XxeRule(BaseRule):
    version = 2
    rule_id = "IL-509"
    name = "부적절한 XML 외부 개체 참조(XXE) 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.HIGH
    gov_standard = mois_ref("1-8")
    plain = "XML 파서가 외부 개체를 읽도록 두면 공격자가 서버의 파일을 읽거나 내부망을 조회할 수 있습니다."
    how_to_fix = (
        "외부 개체와 DTD를 끄세요. Java: factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true) / "
        "Python: defusedxml 사용 / C#: DtdProcessing.Prohibit, XmlResolver = null"
    )
    insecure = {
        Lang.PYTHON: re.compile(r"resolve_entities\s*=\s*True|no_network\s*=\s*False|feature_external_ges\s*,\s*(True|1)|load_dtd\s*=\s*True"),
        Lang.CSHARP: re.compile(r"DtdProcessing\.Parse|XmlResolver\s*=\s*new\s+XmlUrlResolver|ProhibitDtd\s*=\s*false"),
        Lang.PHP: re.compile(r"LIBXML_NOENT|libxml_disable_entity_loader\(\s*false"),
    }
    java_factory = re.compile(
        r"(?:(?P<var>\w+)\s*=\s*)?(?:(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory)\.newInstance\(|new\s+SAXBuilder\(|XMLReaderFactory\.createXMLReader\()"
    )
    java_setting = re.compile(r"(?P<var>\w+)\.(?P<method>setFeature|setProperty|setAttribute|setExpandEntityReferences)\((?P<args>[^;]*?)\)\s*;")
    java_use = re.compile(
        r"(?P<var>\w+)\.(?:newDocumentBuilder|newSAXParser|createXMLStreamReader|createXMLEventReader|newTransformer|newSchema|parse|build)\("
    )
    # 설정 이름 → (이름 식별자, 그 설정이 '차단' 상태가 되는 값)
    java_safe_settings = (
        ("doctype", re.compile(r"disallow-doctype-decl"), re.compile(r"\btrue\b")),
        ("secure", re.compile(r"FEATURE_SECURE_PROCESSING"), re.compile(r"\btrue\b")),
        ("external", re.compile(r"external-(general|parameter)-entities|load-external-dtd"), re.compile(r"\bfalse\b")),
        ("ext_entities", re.compile(r"IS_SUPPORTING_EXTERNAL_ENTITIES"), re.compile(r"\bfalse\b")),
        ("dtd", re.compile(r"SUPPORT_DTD"), re.compile(r"\bfalse\b")),
        ("access_dtd", re.compile(r"ACCESS_EXTERNAL_DTD"), re.compile(r'""')),
        ("access_schema", re.compile(r"ACCESS_EXTERNAL_SCHEMA"), re.compile(r'""')),
        ("access_style", re.compile(r"ACCESS_EXTERNAL_STYLESHEET"), re.compile(r'""')),
    )

    def _java_final_state(self, text: str, var: str, start: int, before: int) -> bool:
        """var에 [start, before) 사이에서 적용한 설정을 순서대로 반영한 최종 상태가 차단 상태인지.
        같은 설정을 나중에 다시 바꾸면 마지막 값이 이긴다."""
        final: dict[str, bool] = {}
        for m in self.java_setting.finditer(text, start, before):
            if m.group("var") != var:
                continue
            args = m.group("args")
            if m.group("method") == "setExpandEntityReferences":
                final["expand"] = re.fullmatch(r"\s*false\s*", args) is not None
                continue
            name_part, _, value_part = args.rpartition(",")
            for key, name_re, safe_re in self.java_safe_settings:
                if name_re.search(name_part):
                    final[key] = safe_re.search(value_part) is not None
        return any(final.values())

    def _check_java(self, src: SourceFile) -> list[Violation]:
        found = []
        text = src.code_text
        spans = [(f.node.start_byte, f.node.end_byte) for f in iter_functions(src)] if src.root is not None else []
        data = src.code_data if src.code_data is not None else src.data  # code_text는 주석을 바이트 단위로 공백 처리한 본문이라 같은 바이트열 기준으로 위치를 옮긴다
        for m in self.java_factory.finditer(text):
            var = m.group("var")
            line = text.count("\n", 0, m.start()) + 1
            # 객체의 범위는 그 객체를 만든 메서드 안이다. 다른 메서드의 같은 이름 변수는 다른 객체다.
            byte_pos = len(text[: m.start()].encode("utf-8"))
            enclosing = [(a, b) for a, b in spans if a <= byte_pos < b]
            lo, hi = (min(enclosing, key=lambda ab: ab[1] - ab[0]) if enclosing else (0, len(data)))
            start_char = len(data[:lo].decode("utf-8", errors="replace"))
            end_char = len(data[:hi].decode("utf-8", errors="replace"))
            if var:  # 같은 이름에 팩토리를 다시 만들면 그 앞까지가 이 객체의 범위다
                rebuilt = [n.start() for n in self.java_factory.finditer(text, m.end(), end_char) if n.group("var") == var]
                end_char = min([end_char, *rebuilt])
            uses = [use.start() for use in self.java_use.finditer(text, m.end(), end_char) if use.group("var") == var] if var else []
            # 파서를 쓰는 지점마다 그 시점의 최종 설정 상태를 본다. 첫 사용 뒤에 되돌린 설정이 두 번째 사용에 닿을 수 있다.
            checkpoints = uses or [end_char]
            unsafe = None
            if not var:
                unsafe = end_char
            else:
                for point in checkpoints:
                    if not self._java_final_state(text, var, max(m.end(), start_char), point):
                        unsafe = point
                        break
            if unsafe is None:
                continue
            used_at = text.count("\n", 0, unsafe) + 1 if uses and unsafe in uses else None
            where = f" (설정이 막혀 있지 않은 사용 지점: {used_at}행)" if used_at and used_at != line else ""
            found.append(
                self.at_line(
                    src,
                    line,
                    "XML 파서 팩토리를 만들면서 DTD·외부 개체를 막는 설정이 없습니다. "
                    "(차단 값이 true/false인지, 같은 메서드 안의 그 객체에 파싱 전에 적용했는지, 나중에 값을 되돌리지 않았는지 확인하십시오.)" + where,
                )
            )
        return found

    PY_PARSE_METHODS = frozenset({"parse", "feed", "parseString"})

    def _python_parser_name(self, src: SourceFile, call: Call) -> str:
        """외부 개체를 켜는 설정 호출이 바꾸는 파서 변수. `p.setFeature(...)`는 수신자, `p = XMLParser(...)`는 대입받는 변수"""
        if call.callee.endswith(".setFeature"):
            return call.callee.rsplit(".", 1)[0]
        parent = call.node.parent
        if parent is not None and parent.type == "assignment":
            left = parent.child_by_field_name("left")
            if left is not None and left.type == "identifier":
                return src.text_of(left)
        return ""

    def _python_parse_inputs(self, src: SourceFile, setting: Call, parser: str) -> list[tuple[Call, Node]]:
        """설정 뒤 같은 함수에서 그 파서로 파싱하는 호출과 파싱할 입력 식"""
        scope = enclosing_function(setting.node, src.lang) or src.root
        found = []
        for call in iter_calls(src):
            if call.node.start_byte < setting.node.end_byte or scope is None or call.node.end_byte > scope.end_byte:
                continue
            receiver, _, method = call.callee.rpartition(".")
            if receiver == parser and method in self.PY_PARSE_METHODS and call.args:
                found.append((call, call.args[0]))
            elif any(src.text_of(a) == parser or src.text_of(a) == f"parser={parser}" for a in call.args):
                data = next((a for a in call.args if a.type != "keyword_argument" and src.text_of(a) != parser), None)
                if data is not None:
                    found.append((call, data))
        return found

    @staticmethod
    def _python_inline_parse(src: SourceFile, setting: Call) -> list[tuple[Call, Node]]:
        """`etree.fromstring(데이터, etree.XMLParser(resolve_entities=True))`처럼 파서를 만들어 바로 넘기는 파싱 호출"""
        holder = setting.node.parent
        if holder is not None and holder.type == "keyword_argument":
            holder = holder.parent
        outer = holder.parent if holder is not None and holder.type == "argument_list" else None
        if outer is None:
            return []
        for call in iter_calls(src):
            if call.node.id == outer.id and call.args and call.args[0].id != setting.node.id:
                return [(call, call.args[0])]
        return []

    def _public_param_reaches(self, src: SourceFile, uses: list[tuple[Call, Node]]) -> bool:
        if self.config is None or self.config.policies.entry_points != "public_api":
            return False
        from iron_laws.engine.public_api import public_entries

        for fn, params in public_entries(src):
            if any(fn.node.start_byte <= use.node.start_byte < fn.node.end_byte and is_tainted(src, data, seeds=params) for use, data in uses):
                return True
        return False

    def _check_python(self, src: SourceFile) -> list[Violation]:
        """외부 개체를 켠 파서로 파싱하는 입력을 본다: 외부 입력이면 확정, 상수면 지적하지 않고, 출처를 모르거나 파싱 호출을 못 찾으면 확인 필요"""
        found = []
        pattern = self.insecure[Lang.PYTHON]
        matched_lines: set[int] = set()
        for call in iter_calls(src):
            if not pattern.search(src.text_of(call.node)) or any(pattern.search(src.text_of(a)) for a in call.args if a.type in ("call",)):
                continue
            matched_lines.add(src.line_of(call.node))
            parser = self._python_parser_name(src, call)
            uses = self._python_parse_inputs(src, call, parser) if parser else self._python_inline_parse(src, call)
            tainted = [(use, data) for use, data in uses if is_tainted(src, data)]
            if tainted:
                use = tainted[0][0]
                found.append(self.at_node(src, use.node, f"외부 개체 처리를 켠 파서({parser + ', ' if parser else ''}{src.line_of(call.node)}행 설정)로 외부 입력 XML을 파싱합니다."))
            elif uses and all(is_literal(data) or is_closed_value(src, data) for _use, data in uses):
                continue  # 코드에 고정된 XML만 파싱한다
            elif uses and self._public_param_reaches(src, uses):
                found.append(self.at_node(src, uses[0][0].node, f"외부 개체 처리를 켠 파서({parser + ', ' if parser else ''}{src.line_of(call.node)}행 설정)로 공개 API 매개변수의 XML을 파싱합니다. 호출하는 쪽이 외부 입력을 넘기는지 확인하십시오.", confidence=Confidence.REVIEW))
            else:
                found.append(self.at_node(src, call.node, "XML 외부 개체 처리를 허용하는 설정이 있습니다. 이 파서로 파싱하는 XML의 출처를 확인하십시오.", confidence=Confidence.REVIEW))
        for idx, line in enumerate(src.code_lines, start=1):
            if idx not in matched_lines and pattern.search(line):
                found.append(self.at_line(src, idx, "XML 외부 개체 처리를 허용하는 설정이 있습니다. 이 설정을 쓰는 파서로 파싱하는 XML의 출처를 확인하십시오.", confidence=Confidence.REVIEW))
        return found

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.lang is Lang.JAVA:
            found.extend(self._check_java(src))
        elif src.lang is Lang.PYTHON and src.root is not None:
            found.extend(self._check_python(src))
        elif src.lang in self.insecure:
            for idx, line in enumerate(src.code_lines, start=1):
                if self.insecure[src.lang].search(line):
                    found.append(self.at_line(src, idx, "XML 외부 개체 처리를 허용하는 설정이 있습니다."))
        elif src.lang in JS_FAMILY:
            for idx, line in enumerate(src.code_lines, start=1):
                if re.search(r"noent\s*:\s*true", line):
                    found.append(self.at_line(src, idx, "libxmljs의 noent:true는 외부 개체 치환을 허용합니다."))
        return found


class CsrfDisabledRule(BaseRule):
    rule_id = "IL-510"
    name = "크로스사이트 요청 위조(CSRF) 방어 해제 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    gov_standard = mois_ref("1-11")
    plain = "로그인한 사용자가 악성 페이지를 열기만 해도 본인 권한으로 송금·삭제 같은 요청이 실행될 수 있습니다."
    how_to_fix = "CSRF 방어를 켜 두세요. 쿠키 인증을 쓰면 CSRF 토큰 또는 SameSite=Lax/Strict 쿠키를 쓰고, 토큰(Authorization 헤더) 방식이면 사유를 문서화하세요."
    patterns = [
        re.compile(r"\.csrf\(\)\s*\.disable\(\)|csrf\(\s*(AbstractHttpConfigurer::disable|\w+\s*->\s*\w+\.disable\(\))"),
        re.compile(r"@csrf_exempt|csrf_exempt\(|WTF_CSRF_ENABLED\s*=\s*False|CSRF_ENABLED\s*=\s*False|csrf\.exempt"),
        re.compile(r"\[IgnoreAntiforgeryToken\]"),
        re.compile(r"csrf\s*:\s*false|csrfProtection\s*=\s*false|\bcsrf\(\{\s*cookie\s*:\s*false"),
    ]

    def check_project(self, project: ProjectContext) -> list[Violation]:
        return _csrf_missing(self, project)

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang is None:
            return []
        found = []
        for idx, line in enumerate(src.code_lines, start=1):
            if any(p.search(line) for p in self.patterns):
                found.append(self.at_line(src, idx, "CSRF 방어를 해제하는 설정이 있습니다. 쿠키 기반 인증이면 위험합니다.", confidence=Confidence.REVIEW))
        return found


class XPathInjectionRule(SinkRule):
    version = 3
    rule_id = "IL-527"
    taint_ctx = Ctx.XPATH
    name = "XML(XPath) 삽입 탐지"
    severity = Severity.HIGH
    gov_standard = mois_ref("1-9")
    plain = "받은 값이 XML 검색식(XPath)에 섞이면 공격자가 조건을 바꿔 다른 사용자의 데이터를 조회하거나 인증을 우회할 수 있습니다."
    how_to_fix = "XPath 변수 바인딩(XPathVariableResolver, lxml의 xpath 변수 인자)을 쓰거나, 값에서 따옴표와 특수문자를 제거·이스케이프하세요."
    tainted_message = "외부 입력이 XPath 식에 결합되어 {callee}로 실행됩니다. 변수 바인딩을 쓰십시오."
    dynamic_message = "XPath 식을 변수와 결합해 {callee}로 실행합니다. 외부 입력이 닿는지 확인하고 변수 바인딩을 쓰십시오."
    PY_BARE_CALL = Sink.of(PY, r"^\w+$")  # import한 select, XPath 객체·평가기 호출. 실제 대상은 select_args가 고른다
    sinks = [
        Sink.of(PY, r"\.(xpath|find|findall|iterfind)$"),
        Sink.of(PY, r"^elementpath\.(select|iter_select)$", 1),
        PY_BARE_CALL,
        Sink.of(JS, r"(^|\.)(evaluate|select|select1|selectNodes|xpath)$"),
        Sink.of(JAVA, r"(?i:xp\w*|xpath\w*|path\w*)\.(evaluate|compile)$|\.(selectNodes|selectSingleNode)$"),
        Sink.of(CS, r"(^|\.)(SelectNodes|SelectSingleNode|Evaluate)$|XPathExpression\.Compile$"),
        Sink.of(PHP, r"(->|::)xpath$|^xpath_eval$"),
    ]

    PY_SELECT_FUNCTIONS = frozenset({"elementpath.select", "elementpath.iter_select"})
    # 식을 받아 XPath 객체를 만드는 생성자(객체를 부르면 그 식이 실행된다)와, 부를 때 식을 받는 평가기 생성자
    PY_XPATH_OBJECTS = re.compile(r"^(?:(?:lxml\.)?etree\.)?(XPath|ETXPath)$")
    PY_XPATH_EVALUATORS = re.compile(r"^(?:(?:lxml\.)?etree\.)?(XPathEvaluator|XPathDocumentEvaluator|XPathElementEvaluator)$")

    def select_args(self, src: SourceFile, call: Call, sink: Sink) -> list[Node]:
        if sink is not self.PY_BARE_CALL:
            return super().select_args(src, call, sink)
        if qualified_name(src, call.callee) in self.PY_SELECT_FUNCTIONS:
            return call.args[1:2]
        scope = enclosing_function(call.node, src.lang) or src.root
        if scope is None:
            return []
        for d in reaching_definitions(src, scope, call.callee, call.node.start_byte):
            if d.type != "call":
                continue
            ctor = d.child_by_field_name("function")
            ctor_args = d.child_by_field_name("arguments")
            name = src.text_of(ctor) if ctor is not None else ""
            positional = [a for a in ctor_args.named_children if a.type != "keyword_argument"] if ctor_args is not None else []
            if self.PY_XPATH_OBJECTS.match(name) and positional:
                return positional[:1]  # run = etree.XPath(식); run(문서) — 실행되는 식은 생성자 인자다
            if self.PY_XPATH_EVALUATORS.match(name):
                return call.args[:1]  # ev = etree.XPathEvaluator(문서); ev(식)
        return []

    @staticmethod
    def _assembled_text(src: SourceFile, arg: Node) -> str:
        """`buf.write(조각)`으로 조립하고 `buf.getvalue()`로 꺼낸 질의는 쓴 조각까지 문맥에 넣는다"""
        if arg.type != "identifier":
            return ""
        scope = enclosing_function(arg, src.lang) or src.root
        if scope is None:
            return ""
        parts = []
        for d in definitions(src, scope, src.text_of(arg)):
            m = re.fullmatch(r"(\w+)\.getvalue\(\s*\)", src.text_of(d).strip())
            if m is None:
                continue
            for c in iter_calls(src):
                if c.callee == f"{m.group(1)}.write" and scope.start_byte <= c.node.start_byte < scope.end_byte:
                    parts.append(src.text_of(c.node))
        return "\n".join(parts)

    def _query_text(self, src: SourceFile, arg: Node) -> str:
        text = _context_text(src, arg)
        if src.lang is Lang.PYTHON:
            text += "\n" + self._assembled_text(src, arg)
        return text

    def skip_hit(self, src: SourceFile, call: Call, arg: Node, flow: Flow) -> bool:
        return not XPATH_TEXT_RE.search(self._query_text(src, arg))

    def guard_verdict(self, src: SourceFile, call: Call, arg: Node, facts: dict[str, PassFacts]) -> str | None:
        return quote_guard_verdict(self, facts, self._query_text(src, arg))
