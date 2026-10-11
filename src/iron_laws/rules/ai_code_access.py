"""ai_code access 규칙."""


import re

from tree_sitter import Node

from iron_laws.core.models import Confidence, IronLaw, RuleLayer, Severity, Violation
from iron_laws.engine.ast_tools import (
    enclosing_function,
    identifiers_in,
    is_literal,
    is_string_node,
    iter_calls,
    iter_functions,
    string_value,
    walk,
)
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import is_tainted
from iron_laws.rules.ai_code_common import (
    AUTH_MARKER,
    PUBLIC_PATH,
    ROUTE_DECORATOR,
    SENSITIVE_PATH,
    AiRule,
)
from iron_laws.rules.base import BaseRule
from iron_laws.rules.sinks import CS, GO, JAVA, JS, PHP, PY, Sink
from iron_laws.standards import mois_ref


class ClientSideAuthRule(AiRule):
    rule_id = "AI-109"
    name = "브라우저 저장소 값으로 하는 인증·권한 판단 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    plain = "관리자인지, 로그인했는지를 브라우저에 저장된 값(localStorage 등)으로만 판단하면, 사용자가 개발자 도구에서 값을 바꿔 관리자 화면에 들어갈 수 있습니다."
    how_to_fix = "화면 숨김은 편의일 뿐입니다. 권한 확인은 반드시 서버 API에서 세션/토큰으로 다시 검사하세요."
    pattern = re.compile(
        r"""(?:localStorage|sessionStorage|Cookies?)\.(?:getItem|get)\(\s*['"][^'"]*(?:admin|role|auth|logged|permission|isAdmin)[^'"]*['"]\s*\)\s*(?:===?|!==?|&&|\?|\|\|)|if\s*\(\s*(?:localStorage|sessionStorage)\.getItem\(\s*['"][^'"]*(?:admin|role|auth|logged|permission)""",
        re.IGNORECASE,
    )

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang not in JS_FAMILY:
            return []
        return [
            self.at_line(src, idx, "브라우저 저장소 값으로 권한/로그인 여부를 판단합니다. 서버에서 다시 검증해야 합니다.", confidence=Confidence.REVIEW)
            for idx, line in enumerate(src.code_lines, start=1)
            if self.pattern.search(line)
        ]


class LoggingSafetyRule(AiRule):
    rule_id = "AI-112"
    name = "민감정보 로깅 및 로그 주입 탐지"
    iron_law = IronLaw.LAW_3
    severity = Severity.HIGH
    plain = "비밀번호·토큰이 로그에 남으면 로그를 볼 수 있는 모든 사람(그리고 로그 수집 서비스)이 그 값을 보게 됩니다. 사용자 입력을 그대로 로그에 쓰면 줄바꿈으로 가짜 로그를 심을 수도 있습니다."
    how_to_fix = "비밀번호·토큰·카드번호는 로그에서 제외하거나 마스킹하세요. 사용자 입력은 repr()/JSON 인코딩으로 줄바꿈을 제거한 뒤 기록하세요."
    log_sinks = [
        Sink.of(PY, r"^(logger|logging|log|_logger|LOGGER|self\.logger|self\.log|current_app\.logger|app\.logger)\.(debug|info|warning|warn|error|exception|critical|fatal)$", None),
        Sink.of(PY, r"^print$", None),
        Sink.of(JS, r"^(console\.(log|info|debug|warn|error)|logger\.\w+|log\.\w+)$", None),
        Sink.of(JAVA, r"^(log|logger|LOG|LOGGER)\.(debug|info|warn|error|trace)$|^System\.out\.println$|^System\.out\.printf?$", None),
        Sink.of(CS, r"^(_?logger|Log)\.(Log\w*|Debug|Info|Warn|Error|Information|Warning)$|^Console\.Write(Line)?$", None),
        Sink.of(GO, r"^(log\.(Print\w*|Fatal\w*|Panic\w*)|slog\.\w+|logger\.\w+|fmt\.Print\w*)$", None),
        Sink.of(PHP, r"^(error_log|var_dump|print_r)$|\$logger->|->(info|error|warning|debug)$", None),
    ]
    sensitive = re.compile(r"(?i)^(pass(word|wd)?|pwd|secret|token|api_?key|apikey|authorization|credit_?card|card_?(no|number)|ssn|jumin|cvv|private_?key|access_?token|refresh_?token|client_?secret|passwd)$|password|passwd|secret|token|apikey|api_key")
    whole_request = re.compile(r"\b(request\.(json|form|data|get_json\(\))|req\.(body|headers)|request\.(body|headers))\b")
    sanitized = re.compile(r"(?i)repr\(|%r|json\.dumps|escape|sanitize|replace\(|encode|strip\(|quote\(|JSON\.stringify|StringEscapeUtils|Encode")

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        for call in iter_calls(src):
            if not any(src.lang in s.langs and s.callee.search(call.callee) for s in self.log_sinks):
                continue
            if call.callee == "print" and src.is_test:
                continue
            sensitive_hit = False
            for arg in call.args:
                if is_string_node(arg) and not any(n.type == "interpolation" for n in walk(arg)):
                    continue
                names = identifiers_in(src, arg)
                if any(self.sensitive.search(n) for n in names):
                    sensitive_hit = True
                    break
            if sensitive_hit:
                found.append(self.at_node(src, call.node, f"{call.callee}로 비밀번호·토큰 등 민감정보로 보이는 값을 기록합니다."))
                continue
            args_text = " ".join(src.text_of(a) for a in call.args)
            if self.whole_request.search(args_text):
                found.append(self.at_node(src, call.node, "요청 본문/헤더 전체를 로그에 기록합니다. 비밀번호·토큰이 포함될 수 있습니다.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
                continue
            if call.callee in ("print", "console.log", "console.info", "console.debug"):
                continue
            if any(not is_literal(a) and is_tainted(src, a) for a in call.args) and not self.sanitized.search(args_text):
                found.append(self.at_node(src, call.node, "사용자 입력을 정제 없이 로그에 기록합니다 (줄바꿈 삽입으로 로그 위조 가능).", severity=Severity.LOW, confidence=Confidence.REVIEW))
        return found


class IdorRule(AiRule):
    rule_id = "AI-113"
    name = "객체 소유자 검증 없는 조회(IDOR/BOLA) 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    gov_standard = mois_ref("2-2")
    layer = RuleLayer.STANDARD
    plain = "주소의 번호만 바꾸면 남의 주문·메시지·프로필이 보이는 취약점입니다. AI가 만든 CRUD API에서 가장 흔한 사고 원인입니다."
    how_to_fix = "ID로 조회할 때 반드시 '로그인한 사용자의 소유인지' 조건을 함께 거세요. 예: Order.objects.get(id=id, user=request.user) / findOne({_id: id, owner: req.user.id})"
    sinks = [
        Sink.of(PY, r"(\.objects\.get|get_object_or_404|\.query\.get|\.filter_by|session\.get|\.get_or_404)$", None),
        Sink.of(JS, r"(^|\.)(findById|findOne|findByPk|findUnique|findFirst|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|deleteOne|updateOne)$", None),
        Sink.of(JAVA, r"(^|\.)(findById|getById|getOne|deleteById|getReferenceById)$", None),
        Sink.of(CS, r"(^|\.)(FindAsync|Find|FirstOrDefaultAsync|SingleOrDefaultAsync|GetByIdAsync|FirstOrDefault)$", None),
    ]
    owner = re.compile(
        r"(?i)request\.user|current_user|\bowner|user_id|userId|req\.user|req\.auth|req\.session|session\[|getPrincipal|SecurityContext|Authentication|"
        r"User\.Identity|User\.FindFirst|ClaimTypes|HttpContext\.User|createdBy|created_by|\.user\b|ownerId|@AuthenticationPrincipal|g\.user|get_jwt_identity|where\s*:\s*\{[^}]*user|tenant|organization|org_id|\.is_staff|is_admin|isAdmin|hasRole|PreAuthorize|\[Authorize"
    )

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        for call in iter_calls(src):
            if not any(src.lang in s.langs and s.callee.search(call.callee) for s in self.sinks):
                continue
            tainted = any(not is_literal(a) and is_tainted(src, a) for a in call.args)
            if not tainted:
                continue
            fn = enclosing_function(call.node, src.lang)
            scope = src.text_of(fn) if fn is not None else src.text_of(call.node)
            if src.lang is Lang.JAVA or src.lang is Lang.CSHARP:
                cls = fn.parent if fn is not None else None
                while cls is not None and cls.type not in ("class_declaration",):
                    cls = cls.parent
                if cls is not None:
                    scope += " " + src.data[cls.start_byte : (cls.child_by_field_name("body") or cls).start_byte].decode("utf-8", "replace")
            if self.owner.search(scope):
                continue
            found.append(
                self.at_node(src, call.node, f"요청의 ID로 {call.callee} 조회를 하지만 소유자·권한 조건이 보이지 않습니다 (남의 데이터 조회 가능성).", confidence=Confidence.REVIEW)
            )
        return found


class DatabaseAccessPolicyRule(AiRule):
    rule_id = "AI-108"
    name = "Supabase·Firebase 접근 규칙 누락/개방 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.HIGH
    plain = "Supabase·Firebase는 브라우저에서 DB를 직접 호출하는 구조라서 '접근 규칙(RLS/보안 규칙)'이 곧 보안의 전부입니다. 규칙이 없거나 모두 허용이면 누구나 전체 데이터를 읽고 지울 수 있습니다."
    how_to_fix = "모든 테이블에 `alter table ... enable row level security;`를 켜고 `auth.uid() = user_id` 같은 소유자 조건의 policy를 만드세요. Firebase는 `allow read, write: if request.auth != null && request.auth.uid == resource.data.uid` 형태로 제한하세요."
    open_rules = re.compile(r"allow\s+[\w\s,]+:\s*if\s+true\b")
    timebomb = re.compile(r"request\.time\s*<\s*timestamp\.date\(")
    json_open = re.compile(r"""["']\.(read|write)["']\s*:\s*(true|["']true["'])""")
    open_policy = re.compile(r"(?is)create\s+policy\b[^;]*?\b(?:using|with\s+check)\s*\(\s*true\s*\)")
    anon_write = re.compile(r"(?is)create\s+policy\b[^;]*?\bfor\s+(all|insert|update|delete)\b[^;]*?\bto\s+(anon|public)\b[^;]*?\b(?:using|with\s+check)\s*\(\s*true\s*\)")

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.kind == "rules":
            for idx, line in enumerate(src.code_lines, start=1):
                if self.open_rules.search(line):
                    found.append(self.at_line(src, idx, "누구나 읽고 쓸 수 있도록 규칙이 `if true`로 열려 있습니다.", severity=Severity.CRITICAL))
                elif self.timebomb.search(line):
                    found.append(self.at_line(src, idx, "기간 한정 전체 공개(테스트 모드) 규칙입니다. 기간이 지나기 전에 실제 규칙으로 교체하십시오.", severity=Severity.HIGH))
        elif src.kind == "json" and re.search(r"rules|database", src.path.name, re.IGNORECASE):
            for idx, line in enumerate(src.code_lines, start=1):
                if self.json_open.search(line):
                    found.append(self.at_line(src, idx, "Realtime Database 규칙이 읽기/쓰기를 누구에게나 허용합니다.", severity=Severity.CRITICAL))
        elif src.kind == "sql":
            text = src.code_text
            for m in self.anon_write.finditer(text):
                found.append(self.at_line(src, text.count("\n", 0, m.start()) + 1, "anon/public 역할에게 조건 없이 쓰기를 허용하는 policy입니다.", severity=Severity.CRITICAL))
            seen = {v.line_number for v in found}
            for m in self.open_policy.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                if line not in seen:
                    found.append(self.at_line(src, line, "using (true) 정책은 모든 행을 모두에게 공개합니다.", confidence=Confidence.REVIEW))
        return found

    def check_project(self, project: ProjectContext) -> list[Violation]:
        sql_files = project.by_kind("sql")
        if not sql_files:
            return []
        joined = "\n".join(f.code_text for f in project.files if f.kind in ("sql", "code", "json", "toml", "env", "yaml"))
        if not re.search(r"(?i)supabase|auth\.uid\(\)|create\s+policy|row\s+level\s+security", joined):
            return []
        enabled = {m.group(1).lower() for m in re.finditer(r"(?is)alter\s+table\s+(?:only\s+)?(?:public\.)?\"?(\w+)\"?\s+enable\s+row\s+level\s+security", "\n".join(f.code_text for f in sql_files))}
        found = []
        for src in sql_files:
            text = src.code_text
            for m in re.finditer(r"(?is)create\s+table\s+(?:if\s+not\s+exists\s+)?(?P<schema>\"?\w+\"?\.)?\"?(?P<name>\w+)\"?", text):
                schema = (m.group("schema") or "public.").strip('".').lower()
                if schema not in ("public",):
                    continue
                name = m.group("name").lower()
                if name not in enabled:
                    found.append(self.at_line(src, text.count("\n", 0, m.start()) + 1, f"테이블 {name}에 Row Level Security가 켜져 있지 않습니다. 브라우저에서 누구나 접근할 수 있습니다.", confidence=Confidence.REVIEW))
        return found


class UnauthenticatedEndpointRule(BaseRule):
    rule_id = "IL-525"
    name = "인증 확인이 보이지 않는 중요 기능 엔드포인트 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    gov_standard = mois_ref("2-1")
    plain = "데이터를 바꾸거나 관리자·사용자 정보를 다루는 API에 '로그인 확인'이 없으면 로그인하지 않은 누구나 그 기능을 호출할 수 있습니다. AI는 화면 기능만 만들고 서버 쪽 인증을 빼먹는 경우가 많습니다."
    how_to_fix = "쓰기·관리·개인정보 API에는 인증 미들웨어/데코레이터를 붙이고, 서버에서 사용자와 권한을 확인하세요. 예: @login_required / app.post('/x', authenticate, handler) / @PreAuthorize / [Authorize]"
    languages = None

    def check(self, src: SourceFile) -> list[Violation]:
        return []

    def check_project(self, project: ProjectContext) -> list[Violation]:
        found = []
        all_text = "\n".join(f.code_text for f in project.source_files())
        spring_secured = bool(re.search(r"SecurityFilterChain|@EnableWebSecurity|WebSecurityConfigurerAdapter|authorizeHttpRequests|authorizeRequests", all_text))
        dotnet_global = bool(re.search(r"FallbackPolicy|AuthorizeFilter|RequireAuthorization\(\)|UseAuthorization", all_text)) and bool(re.search(r"FallbackPolicy|AuthorizeFilter|AddAuthorizationBuilder", all_text))
        for src in project.source_files():
            if src.lang is Lang.PYTHON:
                found.extend(self._python(src))
            elif src.lang in JS_FAMILY:
                found.extend(self._express(src))
            elif src.lang is Lang.JAVA and not spring_secured:
                found.extend(self._spring(src))
            elif src.lang is Lang.CSHARP and not dotnet_global:
                found.extend(self._aspnet(src))
        return found

    def _sensitive(self, method: str, path: str) -> bool:
        if PUBLIC_PATH.match(path.lstrip("/")) and not SENSITIVE_PATH.search(path):
            return False
        if re.match(r"(?i)^/?(login|logout|register|signup|signin|auth|health|ping|webhook|callback|oauth|token|refresh|forgot|reset)\b", path):
            return False
        return method.lower() in ("post", "put", "patch", "delete") or bool(SENSITIVE_PATH.search(path))

    @staticmethod
    def _head(src: SourceFile, fn) -> str:
        end = fn.body.start_byte if fn.body is not None else fn.node.end_byte
        return src.data[fn.node.start_byte : end].decode("utf-8", errors="replace")

    def _make(self, src: SourceFile, node: Node, what: str) -> Violation:
        return self.at_node(src, node, f"{what}에 인증·권한 확인이 보이지 않습니다. 로그인하지 않은 사용자도 호출할 수 있는지 확인하십시오.", confidence=Confidence.REVIEW)

    def _python(self, src: SourceFile) -> list[Violation]:
        found = []
        assert src.root is not None
        for node in src.nodes:
            if node.type != "decorated_definition":
                continue
            decorators = [c for c in node.named_children if c.type == "decorator"]
            definition = node.child_by_field_name("definition")
            if definition is None or definition.type != "function_definition":
                continue
            route = next((d for d in decorators if ROUTE_DECORATOR.search(src.text_of(d))), None)
            if route is None:
                continue
            rtext = src.text_of(route)
            m = re.search(r"\(\s*[rbf]?['\"]([^'\"]*)['\"]", rtext)
            path = m.group(1) if m else ""
            method_m = re.search(r"@\s*(?:\w+\.)*(get|post|put|patch|delete)\b", rtext)
            methods = [method_m.group(1)] if method_m else [x.lower() for x in re.findall(r"['\"](GET|POST|PUT|PATCH|DELETE)['\"]", rtext)] or ["get"]
            if not any(self._sensitive(mm, path) for mm in methods):
                continue
            scope = src.code_of(node)
            if AUTH_MARKER.search(scope):
                continue
            found.append(self._make(src, definition, f"{' '.join(m.upper() for m in methods)} {path or '(경로 미상)'} 핸들러"))
        return found

    def _express(self, src: SourceFile) -> list[Violation]:
        found = []
        for call in iter_calls(src):
            m = re.match(r"^(?:app|router|api|server|r|route)\.(get|post|put|patch|delete)$", call.callee)
            if not m or len(call.args) < 2:
                continue
            path_arg = call.args[0]
            if path_arg.type not in ("string", "template_string"):
                continue
            path = string_value(src, path_arg)
            if not self._sensitive(m.group(1), path):
                continue
            scope = src.code_of(call.node)
            if AUTH_MARKER.search(scope):
                continue
            file_has_global = re.search(r"(?:app|router)\.use\(\s*(?:['\"][^'\"]*['\"]\s*,\s*)?(?:\w*auth\w*|passport\.authenticate|jwt\w*|protect|verifyToken)", src.code_text, re.IGNORECASE)
            if file_has_global:
                continue
            found.append(self._make(src, call.node, f"{m.group(1).upper()} {path} 라우트"))
        return found

    def _spring(self, src: SourceFile) -> list[Violation]:
        found = []
        if "@RestController" not in src.text and "@Controller" not in src.text:
            return found
        class_secured = bool(re.search(r"@(PreAuthorize|Secured|RolesAllowed)", src.text.split("class ", 1)[0]))
        if class_secured:
            return found
        for fn in iter_functions(src):
            text = src.code_of(fn.node)
            head = self._head(src, fn)
            m = re.search(r"@(Get|Post|Put|Patch|Delete|Request)Mapping(?:\(([^)]*)\))?", head)
            if not m:
                continue
            method = m.group(1)
            path_m = re.search(r"\"([^\"]*)\"", m.group(2) or "")
            path = path_m.group(1) if path_m else ""
            if not self._sensitive("get" if method in ("Get", "Request") else method.lower(), path):
                continue
            if re.search(r"@(PreAuthorize|Secured|RolesAllowed)|Principal|Authentication|SecurityContext", text):
                continue
            found.append(self._make(src, fn.node, f"{method.upper()} {path} 컨트롤러 메서드"))
        return found

    def _aspnet(self, src: SourceFile) -> list[Violation]:
        found = []
        if not re.search(r":\s*(Controller|ControllerBase)\b|\[ApiController\]", src.text):
            return found
        if re.search(r"\[Authorize\b", src.text.split("class ", 1)[0]):
            return found
        for fn in iter_functions(src):
            text = src.code_of(fn.node)
            head = self._head(src, fn)
            m = re.search(r"\[Http(Get|Post|Put|Patch|Delete)(?:\(\s*\"([^\"]*)\"\s*\))?\]", head)
            if not m:
                continue
            if re.search(r"\[Authorize|\[AllowAnonymous\]|User\.Identity|HttpContext\.User", text):
                continue
            if self._sensitive(m.group(1).lower(), m.group(2) or fn.name):
                found.append(self._make(src, fn.node, f"{m.group(1).upper()} {fn.name} 액션"))
        return found


class CookieFlagsRule(AiRule):
    rule_id = "AI-115"
    name = "쿠키 보안 속성(Secure·HttpOnly) 누락 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.MEDIUM
    plain = "Secure가 없으면 암호화되지 않은 연결로도 쿠키가 전송되고, HttpOnly가 없으면 스크립트(XSS)가 로그인 쿠키를 읽어 갈 수 있습니다."
    how_to_fix = "로그인·세션 쿠키에는 Secure, HttpOnly, SameSite=Lax(또는 Strict)를 항상 지정하세요. 예: set_cookie(name, value, secure=True, httponly=True, samesite='Lax') / res.cookie(name, value, {httpOnly: true, secure: true, sameSite: 'lax'})"
    session_name = re.compile(r"(?i)sess|token|auth|sid|jwt|login|remember|refresh")
    sinks = [
        Sink.of(PY, r"(^|\.)set_cookie$", None),
        Sink.of(JS, r"^(res|response|reply)\.cookie$", None),
        Sink.of(PHP, r"^(setcookie|setrawcookie)$", None),
        Sink.of(CS, r"Cookies\.Append$", None),
        Sink.of(GO, r"^http\.SetCookie$", None),
    ]

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        for call in iter_calls(src):
            if src.lang is Lang.JAVA:
                continue
            if not any(src.lang in sk.langs and sk.callee.search(call.callee) for sk in self.sinks):
                continue
            text = src.text_of(call.node)
            missing = self._missing(src, call, text)
            if not missing:
                continue
            important = bool(self.session_name.search(text))
            found.append(
                self.at_node(
                    src,
                    call.node,
                    f"쿠키 설정에 {', '.join(missing)}이(가) 보이지 않습니다.",
                    severity=Severity.MEDIUM if important else Severity.LOW,
                    confidence=Confidence.REVIEW,
                )
            )
        found.extend(self._java(src))
        found.extend(self._session_middleware(src))
        return found

    def _session_middleware(self, src: SourceFile) -> list[Violation]:
        if src.lang not in JS_FAMILY or not re.search(r"express-session|cookie-session", src.text):
            return []
        found = []
        for call in iter_calls(src):
            if call.callee not in ("session", "expressSession", "cookieSession") or not call.args:
                continue
            text = src.text_of(call.node)
            lowered = text.lower()
            secure = re.search(r"secure\s*:\s*true", lowered) is not None
            httponly = re.search(r"httponly\s*:\s*true", lowered) is not None
            if secure and httponly:
                continue
            missing = [n for n, ok in (("Secure", secure), ("HttpOnly", httponly)) if not ok]
            found.append(
                self.at_node(
                    src,
                    call.node,
                    f"세션 미들웨어 설정에 쿠키 {', '.join(missing)} 옵션이 명시되어 있지 않습니다 (secure 기본값은 꺼져 있습니다).",
                    confidence=Confidence.REVIEW,
                )
            )
        return found

    @staticmethod
    def _missing(src: SourceFile, call, text: str) -> list[str]:
        lowered = text.lower()
        secure = re.search(r"secure\s*[:=]\s*(true|1)|secure\s*=\s*true|'secure'\s*=>\s*true", lowered) is not None
        httponly = re.search(r"http_?only\s*[:=]\s*(true|1)|httponly\s*=\s*true|'httponly'\s*=>\s*true", lowered) is not None
        if src.lang is Lang.PHP and len(call.args) >= 7:
            secure = httponly = True  # 위치 인자로 지정된 경우는 값 확인 대신 지정 자체를 신뢰한다
        missing = []
        if not secure:
            missing.append("Secure")
        if not httponly:
            missing.append("HttpOnly")
        return missing

    def _java(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.lang is not Lang.JAVA:
            return found
        for call in iter_calls(src):
            if call.callee != "newCookie":
                continue
            fn = enclosing_function(call.node, src.lang)
            scope = src.text_of(fn) if fn is not None else src.text
            missing = [n for n, pat in (("Secure", r"setSecure\(\s*true"), ("HttpOnly", r"setHttpOnly\(\s*true")) if not re.search(pat, scope)]
            if missing:
                found.append(
                    self.at_node(src, call.node, f"쿠키에 {', '.join(missing)} 설정이 보이지 않습니다.", confidence=Confidence.REVIEW)
                )
        return found
