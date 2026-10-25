"""injection documents 규칙."""
# iron-laws: ignore-file[IL-510] CSRF 해제 구문을 탐지하는 패턴 정의
import re

from tree_sitter import Node

from iron_laws.core.models import Confidence, IronLaw, Severity, Violation
from iron_laws.engine.ast_tools import (
    Call,
    iter_functions,
)
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.python_bindings import is_regex_call
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import (
    Ctx,
)
from iron_laws.rules.base import BaseRule
from iron_laws.rules.injection_common import (
    LDAP_TEXT_RE,
    XPATH_TEXT_RE,
    SinkRule,
    _context_text,
    _csrf_missing,
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
)
from iron_laws.standards import mois_ref


class LdapInjectionRule(SinkRule):
    version = 3
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
        Sink.of(PHP, r"^ldap_(search|list|read)$", None),
        Sink.of(GO, r"^ldap\.NewSearchRequest$", None),
    ]

    def skip_hit(self, src: SourceFile, call: Call, arg: Node, flow: Flow) -> bool:
        if is_regex_call(src, call):
            return True
        text = _context_text(src, arg)
        if re.search(r"(?i)escape_filter|encodeForLDAP|ldap\.EscapeFilter|escapeLDAP", text):
            return True
        return not LDAP_TEXT_RE.search(text)


class XxeRule(BaseRule):
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

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.lang is Lang.JAVA:
            found.extend(self._check_java(src))
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
    version = 2
    rule_id = "IL-527"
    taint_ctx = Ctx.XPATH
    name = "XML(XPath) 삽입 탐지"
    severity = Severity.HIGH
    gov_standard = mois_ref("1-9")
    plain = "받은 값이 XML 검색식(XPath)에 섞이면 공격자가 조건을 바꿔 다른 사용자의 데이터를 조회하거나 인증을 우회할 수 있습니다."
    how_to_fix = "XPath 변수 바인딩(XPathVariableResolver, lxml의 xpath 변수 인자)을 쓰거나, 값에서 따옴표와 특수문자를 제거·이스케이프하세요."
    tainted_message = "외부 입력이 XPath 식에 결합되어 {callee}로 실행됩니다. 변수 바인딩을 쓰십시오."
    dynamic_message = "XPath 식을 변수와 결합해 {callee}로 실행합니다. 외부 입력이 닿는지 확인하고 변수 바인딩을 쓰십시오."
    sinks = [
        Sink.of(PY, r"\.(xpath|find|findall|iterfind)$"),
        Sink.of(JS, r"(^|\.)(evaluate|select|select1|selectNodes|xpath)$"),
        Sink.of(JAVA, r"(?i:xp\w*|xpath\w*|path\w*)\.(evaluate|compile)$|\.(selectNodes|selectSingleNode)$"),
        Sink.of(CS, r"(^|\.)(SelectNodes|SelectSingleNode|Evaluate)$|XPathExpression\.Compile$"),
        Sink.of(PHP, r"(->|::)xpath$|^xpath_eval$"),
    ]

    def skip_hit(self, src: SourceFile, call: Call, arg: Node, flow: Flow) -> bool:
        return not XPATH_TEXT_RE.search(_context_text(src, arg))
