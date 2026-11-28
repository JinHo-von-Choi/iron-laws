"""
오철칙 라우트 접근통제 행렬: 웹 프레임워크의 라우트를 찾고 라우트마다 인증·인가 근거를 yes/no/unknown으로 판정한다

지원: Flask·FastAPI·Django(urls.py)·Express·Next.js(app/**/route, pages/api)·Spring·ASP.NET.
- 인증(auth) yes: 라우트 정의·미들웨어·핸들러 본문에 인증 표지가 있거나, 평가할 수 있는 전역 설정이 이 경로를 보호한다.
  no: 아무 근거가 없거나 전역 설정이 이 경로를 명시적으로 공개(permitAll·AllowAnonymous)한다.
  unknown: 전역 설정이 있지만 이 경로에 적용되는지 정할 수 없다(Spring 보안 체인의 일부 경로 규칙, Next.js 미들웨어 matcher 등).
- 종류(kind): auth_flow(로그인·비밀번호·인증번호·SSO·세션 전환·토큰 발급), admin(관리 콘솔·문서·관리 경로), normal.
  경로 조각과 핸들러 이름의 낱말로 정한다. 공개 경로 판정(PUBLIC_PATH)과는 독립이다.
- 설정의 auth 절: 로그인 검사 예외 표지(exempt_markers)가 붙은 라우트는 no, 인터셉터가 보호한다고 설정하면(interceptor_protects)
  addPathPatterns·excludePathPatterns를 읽어 그 범위 안의 표지 없는 라우트를 yes로 본다. 코드의 보안 설정 근거가 설정보다 우선한다.
- 인가(authz)는 객체 식별자를 받는 라우트(`/users/{id}`, `/:id`, `<int:id>`)와 관리 경로에서만 본다.
  yes: 역할·권한 검사가 있거나, 데이터 조회보다 먼저 현재 사용자와 대상의 소유 관계를 비교한다.
  no: 식별자로 데이터를 조회하는데 그런 검사가 없다. unknown: 데이터 조회 여부를 정할 수 없다. 해당 없는 라우트는 n/a.
작성자: 최진호
작성일: 2026-10-12
"""

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from iron_laws.core.config import AuthSettings
from iron_laws.engine.ast_tools import iter_calls, iter_functions, string_value
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.source import SourceFile

ROUTE_DECORATOR = re.compile(r"@\s*(?:\w+\.)*(route|get|post|put|patch|delete|api_view|websocket)\b")
SENSITIVE_PATH = re.compile(r"(?i)admin|user|delete|remove|payment|pay|account|order|password|secret|internal|manage|dashboard|upload|export|import|settings|billing|token|profile|invoice|config")
PUBLIC_PATH = re.compile(r"(?i)^/?(login|logout|register|signup|sign-up|signin|sign-in|auth|health|healthz|ping|status|public|webhook|callback|oauth|token|refresh|forgot|reset|verify|docs|openapi|static|favicon|robots|metrics|$)")
AUTH_MARKER = re.compile(
    r"(?i)login_required|jwt_required|permission|require_?auth|requires?_?\w*role|Depends\(|Security\(|current_user|request\.user|g\.user|session\[|token_required|verify_?token|HTTPBearer|OAuth2|"
    r"authenticat|authoriz|auth\b|passport|protect|isLoggedIn|requireLogin|guard|ensureAuth|req\.user|req\.session|req\.auth|getServerSession|getSession|currentUser|jwt\.verify|@PreAuthorize|@Secured|@RolesAllowed|\[Authorize|get_jwt|firebase.*verifyIdToken|supabase\.auth\.getUser|Authorization|api_key|apikey|x-api-key"
)
ROLE_MARKER = re.compile(r"(?i)hasRole|hasAuthority|hasAnyRole|@Secured|@RolesAllowed|Roles\s*=|permission_required|has_perm|is_staff|is_superuser|is_admin|isAdmin|requireRole|requires?_?\w*role|role\s*(?:===?|!==?|in)\b|\.role\b|admin_required|PermissionRequired")
OWNER_MARKER = re.compile(r"(?i)(owner|user_?id|author|created_by|userId|ownerId|account_?id)\w*\s*(?:===?|!==?|==|!=)\s*\w*(?:current_?user|req\.user|request\.user|user\.id|principal|session)|(?:current_?user|req\.user|request\.user|principal)\S*\s*(?:===?|!==?|==|!=)\s*\w*\.(owner|user_?id|author|userId|ownerId)")
DATA_ACCESS = re.compile(r"(?i)\.(find\w*|get\w*|query|filter\w*|select\w*|fetch\w*|load\w*|objects\.get|findById|findOne|findUnique|first|execute)\s*\(|SELECT\s|get_object_or_404|repository\.|Repository\.")
ID_PARAM = re.compile(r"(\{[^}]*\b(?:id|\w+_id|\w+Id)\}|/:\w*[iI]d\b|<(?:\w+:)?\w*id>|\[\w*[iI]d\])")
PUBLIC_NAMES = re.compile(r"(?i)^/?(login|logout|register|signup|signin|auth|health|ping|webhook|callback|oauth|token|refresh|forgot|reset)\b")
# 라우트 종류를 정하는 낱말. 경로 조각과 핸들러 이름을 낱말(camelCase·구분자)로 나눠 비교한다
AUTH_FLOW_TOKENS = frozenset(
    {"login", "logout", "signin", "signout", "password", "passwd", "pw", "pwd", "reset", "otp", "totp", "sms", "mfa", "2fa",
     "certify", "certification", "verify", "verification", "sso", "switch", "token", "session"}
)
AUTH_FLOW_COMPACT = ("login", "logout", "signin", "signout", "password", "passwd")
ADMIN_CONSOLE_COMPACT = ("actuator", "swagger", "apidocs", "h2console", "druid", "phpmyadmin")
ADMIN_TOKENS = frozenset({"admin", "manage", "management", "manager"})


def _tokens(text: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return [w.lower() for w in re.split(r"[^A-Za-z0-9]+", spaced) if w]


def route_kind(path: str, handler: str = "") -> str:
    """auth_flow·admin·normal. 관리 콘솔(actuator·swagger·api-docs 등)은 admin이 먼저다."""
    compact = re.sub(r"[^a-z0-9]", "", path.lower())
    if any(word in compact for word in ADMIN_CONSOLE_COMPACT):
        return "admin"
    words = set(_tokens(path)) | set(_tokens(handler))
    if words & AUTH_FLOW_TOKENS or any(word in compact for word in AUTH_FLOW_COMPACT):
        return "auth_flow"
    if set(_tokens(path)) & ADMIN_TOKENS:
        return "admin"
    return "normal"


def _marker_re(markers: list[str]) -> re.Pattern[str] | None:
    names = [m.lstrip("@").strip() for m in markers if m.strip()]
    if not names:
        return None
    return re.compile(r"(?<![\w.])@?(?:" + "|".join(re.escape(n) for n in names) + r")\b")


@dataclass
class Route:
    framework: str
    method: str
    path: str
    file: str
    line: int
    handler: str
    sensitive: bool
    auth: str
    auth_reason: str
    authz: str
    authz_reason: str
    node: object = field(default=None, repr=False, compare=False)
    kind: str = "normal"

    def as_row(self) -> dict:
        return {k: getattr(self, k) for k in ("framework", "method", "path", "file", "line", "handler", "kind", "sensitive", "auth", "auth_reason", "authz", "authz_reason")}


def is_sensitive(method: str, path: str) -> bool:
    """데이터를 바꾸는 메서드, 또는 관리·개인정보·결제 경로(GET 포함). 로그인·헬스체크 같은 공개 경로는 뺀다."""
    if PUBLIC_PATH.match(path.lstrip("/")) and not SENSITIVE_PATH.search(path):
        return False
    if PUBLIC_NAMES.match(path):
        return False
    return method.lower() in ("post", "put", "patch", "delete") or bool(SENSITIVE_PATH.search(path))


def _authz(path: str, text: str, handler_body: str, tenancy_keys: tuple[str, ...] = ()) -> tuple[str, str]:
    if ROLE_MARKER.search(text):
        return "yes", "역할·권한 검사가 있다"
    needs = bool(ID_PARAM.search(path)) or bool(re.search(r"(?i)admin|manage|internal", path)) or _has_key_param(path, tenancy_keys)
    if not needs:
        return "n/a", "객체 식별자·관리 경로가 아니다"
    owner = OWNER_MARKER.search(handler_body)
    access = DATA_ACCESS.search(handler_body)
    if owner and (access is None or owner.start() < access.start()):
        return "yes", "데이터 조회보다 먼저 소유 관계를 비교한다"
    if access is not None:
        return "no", "식별자로 데이터를 조회하는데 소유 관계·역할 검사가 앞에 없다"
    return "unknown", "데이터 조회 여부를 정할 수 없다"


@dataclass
class _Globals:
    spring: str = ""  # authenticated / partial / ""
    spring_public: list[str] = field(default_factory=list)
    spring_protected: list[str] = field(default_factory=list)
    dotnet: bool = False
    next_middleware: str = ""  # all / matcher / ""
    django_default: bool = False  # DEFAULT_PERMISSION_CLASSES = IsAuthenticated
    interceptor: bool = False  # WebMvcConfigurer.addInterceptors가 있다
    interceptor_include: list[str] = field(default_factory=list)
    interceptor_exclude: list[str] = field(default_factory=list)


def _globals(files: list[SourceFile]) -> _Globals:
    g = _Globals()
    for f in files:
        text = f.code_text
        if f.lang is Lang.JAVA and re.search(r"SecurityFilterChain|@EnableWebSecurity|WebSecurityConfigurerAdapter|authorizeHttpRequests|authorizeRequests", text):
            g.spring = "authenticated" if re.search(r"anyRequest\(\)\s*\.\s*(authenticated|hasRole|hasAnyRole|hasAuthority|fullyAuthenticated)", text) else (g.spring or "partial")
            for block in re.findall(r"(?:requestMatchers|antMatchers|mvcMatchers)\(([^)]*)\)\s*\.\s*permitAll", text):
                g.spring_public += re.findall(r"\"([^\"]+)\"", block)
            for block in re.findall(r"(?:requestMatchers|antMatchers|mvcMatchers)\(([^)]*)\)\s*\.\s*(?:authenticated|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|fullyAuthenticated)", text):
                g.spring_protected += re.findall(r"\"([^\"]+)\"", block)
        if f.lang is Lang.JAVA and re.search(r"\baddInterceptors\s*\(", text):
            g.interceptor = True
            for kind, target in (("addPathPatterns", g.interceptor_include), ("excludePathPatterns", g.interceptor_exclude)):
                for block in re.findall(rf"\.{kind}\(([^)]*)\)", text):
                    target += re.findall(r"\"([^\"]+)\"", block)
        if f.lang is Lang.CSHARP and re.search(r"FallbackPolicy|AuthorizeFilter|AddAuthorizationBuilder", text) and re.search(r"FallbackPolicy|AuthorizeFilter|RequireAuthorization\(\)|UseAuthorization", text):
            g.dotnet = True
        if f.lang in JS_FAMILY and PurePosixPath(f.path.as_posix()).stem == "middleware" and len(f.path.parts) <= 2 and AUTH_MARKER.search(text):
            g.next_middleware = "matcher" if re.search(r"matcher\s*:", text) else "all"
        if f.lang is Lang.PYTHON and re.search(r"DEFAULT_PERMISSION_CLASSES[^\]]*IsAuthenticated", text, re.DOTALL):
            g.django_default = True
    return g


def _ant_match(pattern: str, path: str) -> bool:
    regex = re.escape(pattern).replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    path = re.sub(r"\{[^}]+\}", "x", path)
    return re.fullmatch(regex, path) is not None


def _flask_fastapi(src: SourceFile) -> list[Route]:
    routes = []
    framework = "fastapi" if re.search(r"\bfastapi\b", src.code_text) else "flask"
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
        scope = src.code_of(node)
        name = definition.child_by_field_name("name")
        body = definition.child_by_field_name("body")
        body_text = src.code_of(body) if body is not None else ""
        auth = ("yes", "라우트 정의·핸들러에 인증 표지가 있다") if AUTH_MARKER.search(scope) else ("no", "인증 표지가 없다")
        authz = _authz(path, scope, body_text)
        for method in methods:
            routes.append(Route(framework, method.upper(), path or "(경로 미상)", src.path.as_posix(), src.line_of(definition), src.text_of(name) if name else "",
                                is_sensitive(method, path), *auth, *authz, node=definition))
    return routes


def _django(src: SourceFile, views: dict[str, tuple[SourceFile, object]], g: _Globals) -> list[Route]:
    routes = []
    if PurePosixPath(src.path.as_posix()).name != "urls.py":
        return routes
    for call in iter_calls(src):
        if call.callee not in ("path", "re_path", "url") or len(call.args) < 2:
            continue
        route_path = "/" + string_value(src, call.args[0]).lstrip("^").rstrip("$") if call.args[0].type == "string" else "(경로 미상)"
        view_text = src.text_of(call.args[1])
        view_name = re.sub(r"\.as_view\(.*\)$", "", view_text).rsplit(".", 1)[-1]
        target = views.get(view_name)
        text = target[0].code_of(target[1].node) if target else ""
        head = text
        if target is not None and target[1].node.parent is not None and target[1].node.parent.type == "decorated_definition":
            head = target[0].code_of(target[1].node.parent)
        if target is None:
            auth = ("unknown", f"보기 {view_name}의 정의를 찾지 못했다")
        elif re.search(r"login_required|permission_required|user_passes_test|LoginRequiredMixin|PermissionRequiredMixin|IsAuthenticated|request\.user\.is_authenticated", head):
            auth = ("yes", "보기에 인증 데코레이터·믹스인·검사가 있다")
        elif g.django_default and re.search(r"APIView|ViewSet|api_view", head):
            auth = ("yes", "DRF 기본 권한(IsAuthenticated)이 적용된다")
        else:
            auth = ("no", "인증 데코레이터·믹스인·검사가 없다")
        methods = ["post"] if re.search(r"(?i)delete|remove|update|edit|create", view_name) else ["get"]
        authz = _authz(route_path, head, text)
        routes.append(Route("django", methods[0].upper(), route_path, src.path.as_posix(), call.line, view_name, is_sensitive(methods[0], route_path), *auth, *authz, node=call.node))
    return routes


def _under(path: str, prefix: str | None) -> bool:
    if prefix is None or prefix.strip("/") == "":
        return True
    base = "/" + prefix.strip("/")
    return path == base or path.startswith(base + "/")


def _express(src: SourceFile) -> list[Route]:
    routes = []
    # app.use("/admin", auth)처럼 경로를 준 인증 미들웨어는 그 경로 아래 라우트에만 적용된다
    # 라우터에 건 미들웨어는 그 라우터의 라우트에만, app(server)에 건 미들웨어는 모든 라우트에 적용된다
    middlewares = [
        (m.start(), m.group("prefix"), m.group("owner"))
        for m in re.finditer(r"\b(?P<owner>app|server|\w*[rR]outer|api)\.use\(\s*(?:['\"](?P<prefix>[^'\"]*)['\"]\s*,\s*)?(?:\w*auth\w*|passport\.authenticate|jwt\w*|protect|verifyToken)", src.code_text, re.IGNORECASE)
    ]
    for call in iter_calls(src):
        m = re.match(r"^(app|\w*[rR]outer|api|server|r|route)\.(get|post|put|patch|delete)$", call.callee)
        if not m or len(call.args) < 2:
            continue
        path_arg = call.args[0]
        if path_arg.type not in ("string", "template_string"):
            continue
        path = string_value(src, path_arg)
        scope = src.code_of(call.node)
        handler = call.args[-1]
        body_text = src.code_of(handler)
        if AUTH_MARKER.search(scope):
            auth = ("yes", "미들웨어·핸들러에 인증 표지가 있다")
        elif (applies := [start for start, prefix, owner in middlewares if _under(path, prefix) and owner in (m.group(1), "app", "server")]) and min(applies) < call.node.start_byte:
            auth = ("yes", "앞서 등록한 인증 미들웨어(app.use)가 이 경로에 적용된다")
        elif applies:
            auth = ("unknown", "인증 미들웨어가 이 라우트보다 뒤에 등록되어 적용 여부를 정할 수 없다")
        else:
            auth = ("no", "인증 표지가 없다")
        authz = _authz(path, scope, body_text)
        routes.append(Route("express", m.group(2).upper(), path, src.path.as_posix(), call.line, "", is_sensitive(m.group(2), path), *auth, *authz, node=call.node))
    return routes


def _next_path(rel: str) -> str | None:
    parts = PurePosixPath(rel).parts
    for anchor in ("app", "pages"):
        if anchor in parts:
            rest = list(parts[parts.index(anchor) + 1 :])
            if anchor == "app" and PurePosixPath(rel).stem != "route":
                return None
            if anchor == "pages" and (not rest or rest[0] != "api"):
                return None
            rest[-1] = PurePosixPath(rest[-1]).stem
            if rest[-1] in ("route", "index"):
                rest = rest[:-1]
            return "/" + "/".join(p for p in rest if not (p.startswith("(") and p.endswith(")")))
    return None


USE_SERVER_RE = re.compile(r"""^\s*['"]use server['"];?""")


def _next_actions(src: SourceFile, g: _Globals) -> list[Route]:
    """Next.js Server Actions. 파일 첫 문장이 'use server'이면 내보낸 함수가, 함수 본문 첫 문장이 'use server'이면 그 함수가
    브라우저에서 POST로 부를 수 있는 서버 함수다. URL이 없으므로 경로는 `/_action/<폴더>/<함수 이름>`으로 적는다"""
    file_level = bool(USE_SERVER_RE.match(src.code_text))
    if not file_level and "use server" not in src.code_text:
        return []
    routes = []
    for fn in iter_functions(src):
        if fn.name == "<anonymous>" or fn.body is None:
            continue
        exported = fn.node.parent is not None and fn.node.parent.type == "export_statement"
        inline = bool(USE_SERVER_RE.match(src.code_of(fn.body).lstrip("{")))
        if not ((file_level and exported) or inline):
            continue
        folder = PurePosixPath(src.path.as_posix()).parent.as_posix()
        path = f"/_action/{folder}/{fn.name}" if folder != "." else f"/_action/{fn.name}"  # 폴더를 넣어 관리 화면(admin)의 서버 함수를 구분한다
        text = src.code_of(fn.node)
        if AUTH_MARKER.search(text):
            auth = ("yes", "서버 함수에 인증 표지가 있다")
        elif g.next_middleware == "all":
            auth = ("yes", "모든 경로에 적용되는 미들웨어에 인증 표지가 있다")
        elif g.next_middleware == "matcher":
            auth = ("unknown", "미들웨어 matcher가 이 서버 함수를 부르는 화면에 적용되는지 정할 수 없다")
        else:
            auth = ("no", "인증 표지가 없다")
        authz = _authz(path, text, text)
        routes.append(Route("nextjs-action", "POST", path, src.path.as_posix(), src.line_of(fn.node), fn.name, is_sensitive("post", path), *auth, *authz, node=fn.node))
    return routes


def _nextjs(src: SourceFile, g: _Globals) -> list[Route]:
    path = _next_path(src.path.as_posix())
    if path is None:
        return []
    routes = []
    for fn in iter_functions(src):
        name = fn.name
        if not (name in ("GET", "POST", "PUT", "PATCH", "DELETE", "handler") or (name == "<anonymous>" and "export default" in src.code_text)):
            continue
        node = fn.node.parent if fn.node.parent is not None and fn.node.parent.type == "export_statement" else fn.node
        if node.type != "export_statement" and not src.code_of(node.parent or node).startswith("export"):
            continue
        method = name if name not in ("handler", "<anonymous>") else "ANY"
        text = src.code_of(fn.node)
        if AUTH_MARKER.search(text):
            auth = ("yes", "핸들러에 인증 표지가 있다")
        elif g.next_middleware == "all":
            auth = ("yes", "모든 경로에 적용되는 미들웨어에 인증 표지가 있다")
        elif g.next_middleware == "matcher":
            auth = ("unknown", "미들웨어 matcher가 이 경로에 적용되는지 정할 수 없다")
        else:
            auth = ("no", "인증 표지가 없다")
        authz = _authz(path, text, text)
        routes.append(Route("nextjs", method, path, src.path.as_posix(), src.line_of(fn.node), name, is_sensitive(method if method != "ANY" else "post", path), *auth, *authz, node=fn.node))
    return routes


SPRING_AUTH_EVIDENCE = re.compile(
    r"@(PreAuthorize|Secured|RolesAllowed|AuthenticationPrincipal)\b|\bPrincipal\s+\w+\s*[,)]|\bAuthentication\s+\w+\s*[,)]|"
    r"getAuthentication\(\)|getUserPrincipal\(\)|getRemoteUser\(\)"
)


def _spring_methods(name: str, args: str) -> list[str]:
    if name != "Request":
        return [name.upper()]
    m = re.search(r"\bmethod\s*=\s*\{?([^}]*)", args)
    found = re.findall(r"\b(GET|POST|PUT|PATCH|DELETE)\b", m.group(1)) if m else []
    return list(dict.fromkeys(found)) or ["GET"]


@dataclass(frozen=True)
class _SpringScope:
    """Spring 컨트롤러 한 파일의 인증 판정 문맥"""

    class_head: str
    class_secured: bool
    g: _Globals
    auth: AuthSettings
    markers: re.Pattern[str] | None


def _spring_auth(path: str, head: str, text: str, scope: _SpringScope) -> tuple[str, str]:
    g, auth, markers = scope.g, scope.auth, scope.markers
    if scope.class_secured or SPRING_AUTH_EVIDENCE.search(text):
        return "yes", "메서드·클래스에 보안 애너테이션이나 인증 주체 사용이 있다"
    if any(_ant_match(p, path) for p in g.spring_public):
        return "no", "보안 설정이 이 경로를 permitAll로 공개한다"
    if g.spring == "authenticated":
        return "yes", "보안 설정의 anyRequest()가 인증을 요구한다"
    if any(_ant_match(p, path) for p in g.spring_protected):
        return "yes", "보안 설정의 경로 규칙이 이 경로에 인증을 요구한다"
    if markers is not None and (markers.search(head) or markers.search(scope.class_head)):
        return "no", "로그인 검사 예외 표지가 있다"
    if auth.interceptor_protects:
        if any(_ant_match(p, path) for p in [*auth.exempt_paths, *g.interceptor_exclude]):
            return "no", "인터셉터의 예외 경로에 속한다"
        if g.interceptor_include:
            if any(_ant_match(p, path) for p in g.interceptor_include):
                return "yes", "설정된 로그인 인터셉터의 적용 경로에 속한다"
        elif g.interceptor:
            return "unknown", "로그인 인터셉터가 있지만 적용 경로(addPathPatterns)를 읽지 못했다"
        else:
            return "unknown", "로그인 인터셉터를 쓴다고 설정했지만 addInterceptors를 찾지 못했다"
    if g.spring == "partial":
        return "unknown", "보안 설정이 있지만 이 경로에 적용되는 규칙을 정할 수 없다"
    return "no", "보안 애너테이션·보안 설정이 없다"


def _spring(src: SourceFile, g: _Globals, auth: AuthSettings, markers: re.Pattern[str] | None) -> list[Route]:
    routes = []
    if "@RestController" not in src.text and "@Controller" not in src.text:
        return routes
    head_class = src.text.split("class ", 1)[0]
    class_secured = bool(re.search(r"@(PreAuthorize|Secured|RolesAllowed)", head_class))
    prefix_m = re.search(r"@RequestMapping\(\s*(?:value\s*=\s*|path\s*=\s*)?\"([^\"]*)\"", head_class)
    prefix = prefix_m.group(1) if prefix_m else ""
    for fn in iter_functions(src):
        text = src.code_of(fn.node)
        end = fn.body.start_byte if fn.body is not None else fn.node.end_byte
        head = src.data[fn.node.start_byte : end].decode("utf-8", errors="replace")
        m = re.search(r"@(Get|Post|Put|Patch|Delete|Request)Mapping(?:\(([^)]*)\))?", head)
        if not m:
            continue
        path_m = re.search(r"\"([^\"]*)\"", m.group(2) or "")
        path = prefix + (path_m.group(1) if path_m else "")
        auth_row = _spring_auth(path, head, text, _SpringScope(head_class, class_secured, g, auth, markers))
        authz = _authz(path, (head_class if class_secured else "") + text, text)
        for method in _spring_methods(m.group(1), m.group(2) or ""):
            routes.append(Route("spring", method, path, src.path.as_posix(), src.line_of(fn.node), fn.name, is_sensitive(method, path), *auth_row, *authz, node=fn.node))
    return routes


def _aspnet(src: SourceFile, g: _Globals) -> list[Route]:
    routes = []
    if not re.search(r":\s*(Controller|ControllerBase)\b|\[ApiController\]", src.text):
        return routes
    class_authorized = bool(re.search(r"\[Authorize\b", src.text.split("class ", 1)[0]))
    for fn in iter_functions(src):
        text = src.code_of(fn.node)
        end = fn.body.start_byte if fn.body is not None else fn.node.end_byte
        head = src.data[fn.node.start_byte : end].decode("utf-8", errors="replace")
        m = re.search(r"\[Http(Get|Post|Put|Patch|Delete)(?:\(\s*\"([^\"]*)\"\s*\))?\]", head)
        if not m:
            continue
        path = m.group(2) or fn.name
        if re.search(r"\[AllowAnonymous\]", text):
            auth = ("no", "[AllowAnonymous]로 공개한다")
        elif class_authorized or re.search(r"\[Authorize|User\.Identity|HttpContext\.User", text):
            auth = ("yes", "[Authorize]나 사용자 확인이 있다")
        elif g.dotnet:
            auth = ("yes", "전역 권한 정책(FallbackPolicy·AuthorizeFilter)이 있다")
        else:
            auth = ("no", "[Authorize]·전역 권한 정책이 없다")
        authz = _authz(path, text, text)
        routes.append(Route("aspnet", m.group(1).upper(), path, src.path.as_posix(), src.line_of(fn.node), fn.name, is_sensitive(m.group(1), path), *auth, *authz, node=fn.node))
    return routes


def _apply_markers(routes: list[Route], files: dict[str, SourceFile], markers: re.Pattern[str] | None) -> None:
    """Spring 밖의 프레임워크: 인증 근거가 yes가 아닌 라우트에 예외 표지가 있으면 no로 적는다."""
    if markers is None:
        return
    for r in routes:
        if r.framework == "spring" or r.auth == "yes" or r.node is None:
            continue
        node = r.node
        if getattr(node, "parent", None) is not None and node.parent.type == "decorated_definition":
            node = node.parent
        if markers.search(files[r.file].code_of(node)):
            r.auth, r.auth_reason = "no", "로그인 검사 예외 표지가 있다"


def _has_key_param(path: str, keys: tuple[str, ...]) -> bool:
    """소속 키(tenancy.keys)를 경로 변수로 받는가: /payout/{mid}, /payout/:mid, /payout/<mid>"""
    if not keys:
        return False
    return re.search(r"(\{|/:|<(?:\w+:)?)(?:" + "|".join(re.escape(k) for k in keys) + r")\b", path) is not None


def _tenancy_authz(routes: list[Route], files: dict[str, SourceFile], keys: list[str] | tuple[str, ...]) -> None:
    """소속 키를 경로 변수로 받는 라우트도 인가 판정 대상으로 본다. 추출기가 n/a로 둔 라우트만 다시 판정한다."""
    keys = tuple(keys)
    for r in routes:
        if r.authz != "n/a" or r.node is None or not _has_key_param(r.path, keys):
            continue
        text = files[r.file].code_of(r.node)
        r.authz, r.authz_reason = _authz(r.path, text, text, keys)


def discover_routes(files: list[SourceFile], auth: AuthSettings | None = None, tenancy_keys: list[str] | tuple[str, ...] = ()) -> list[Route]:
    auth = auth or AuthSettings()
    markers = _marker_re(auth.exempt_markers)
    code = [f for f in files if f.lang is not None]
    g = _globals(code)
    views: dict[str, tuple[SourceFile, object]] = {}
    for f in code:
        if f.lang is Lang.PYTHON and PurePosixPath(f.path.as_posix()).name.startswith("views"):
            for fn in iter_functions(f):
                views.setdefault(fn.name, (f, fn))
            for node in f.nodes:
                if node.type == "class_definition":
                    name = node.child_by_field_name("name")
                    if name is not None:
                        views.setdefault(f.text_of(name), (f, type("ClassView", (), {"node": node, "name": f.text_of(name)})()))
    routes: list[Route] = []
    for f in code:
        if f.lang is Lang.PYTHON:
            routes += _flask_fastapi(f) + _django(f, views, g)
        elif f.lang in JS_FAMILY:
            routes += _express(f) + _nextjs(f, g) + _next_actions(f, g)
        elif f.lang is Lang.JAVA:
            routes += _spring(f, g, auth, markers)
        elif f.lang is Lang.CSHARP:
            routes += _aspnet(f, g)
    by_file = {f.path.as_posix(): f for f in code}
    _apply_markers(routes, by_file, markers)
    _tenancy_authz(routes, by_file, tenancy_keys)
    for r in routes:
        r.kind = route_kind(r.path, r.handler)
    return sorted(routes, key=lambda r: (r.file, r.line, r.method))


FLASK_ROUTE_CALL = re.compile(r"^@\s*(\w+)\.(route|get|post|put|patch|delete)\s*\(")


def _flask_object_prefix(src: SourceFile, obj: str) -> str | None:
    """데코레이터 객체의 경로 접두사. Flask 앱(대입 `Flask(...)` 또는 함수 매개변수)은 빈 접두사,
    Blueprint는 생성자의 url_prefix 리터럴. register_blueprint로 접두사를 다시 주거나 접두사를 정할 수 없으면 None"""
    if re.search(rf"register_blueprint\(\s*{re.escape(obj)}\b[^)]*url_prefix", src.code_text):
        return None
    for call in iter_calls(src):
        parent = call.node.parent
        if parent is None or parent.type != "assignment" or src.text_of(parent.child_by_field_name("left") or parent) != obj:
            continue
        if re.search(r"(^|\.)Flask$", call.callee):
            return ""
        if re.search(r"(^|\.)Blueprint$", call.callee):
            prefix = next((a.child_by_field_name("value") for a in call.args if a.type == "keyword_argument" and src.text_of(a.child_by_field_name("name")) == "url_prefix"), None)
            if prefix is None:
                return ""
            return string_value(src, prefix) if prefix.type == "string" and "{" not in src.text_of(prefix) else None
        return None
    return ""  # 앱을 매개변수로 받아 라우트를 등록하는 init(app) 꼴


def flask_handler_paths(src: SourceFile, fn, depth: int = 0) -> list[str] | None:
    """Flask 핸들러 함수(fn: function_definition 노드)를 등록한 모든 경로. 데코레이터 전부, 같은 파일의 add_url_rule,
    Blueprint 접두사를 모은다. 다른 핸들러가 이 함수를 그대로 부르면 그 핸들러의 경로도 더한다.
    핸들러가 아닌 함수에서 불리거나 경로가 리터럴이 아니거나 등록을 다 모으지 못하면 None"""
    if depth > 3 or fn is None or fn.type != "function_definition":
        return None
    name_node = fn.child_by_field_name("name")
    name = src.text_of(name_node) if name_node is not None else ""
    paths: list[str] = []
    holder = fn.parent
    for decorator in holder.named_children if holder is not None and holder.type == "decorated_definition" else []:
        if decorator.type != "decorator":
            continue
        m = FLASK_ROUTE_CALL.match(src.text_of(decorator))
        if m is None:
            continue
        call = next((c for c in iter_calls(src) if decorator.start_byte <= c.node.start_byte and c.node.end_byte <= decorator.end_byte), None)
        rule = call.args[0] if call is not None and call.args else None
        prefix = _flask_object_prefix(src, m.group(1))
        if rule is None or rule.type != "string" or "{" in src.text_of(rule) or prefix is None:
            return None
        paths.append(prefix.rstrip("/") + string_value(src, rule))
    for call in iter_calls(src):
        if call.callee.endswith(".add_url_rule"):
            view = next((a.child_by_field_name("value") for a in call.args if a.type == "keyword_argument" and src.text_of(a.child_by_field_name("name")) == "view_func"), None)
            positional = [a for a in call.args if a.type != "keyword_argument"]
            view = view if view is not None else (positional[2] if len(positional) > 2 else None)
            if view is None or src.text_of(view) != name:
                continue
            prefix = _flask_object_prefix(src, call.callee.rsplit(".", 1)[0])
            if not positional or positional[0].type != "string" or prefix is None:
                return None
            paths.append(prefix.rstrip("/") + string_value(src, positional[0]))
        elif call.callee == name:
            from iron_laws.engine.ast_tools import enclosing_function

            caller = enclosing_function(call.node, src.lang)
            caller_paths = flask_handler_paths(src, caller, depth + 1) if caller is not None and caller.id != fn.id else None
            if caller_paths is None:
                return None
            paths.extend(caller_paths)
    return paths or None


def route_segment_value(src: SourceFile, fn, index: int) -> str | None:
    """핸들러를 등록한 모든 경로에서 request.path.split('/')[index]가 같은 리터럴이면 그 값"""
    paths = flask_handler_paths(src, fn)
    if not paths:
        return None
    values = set()
    for path in paths:
        parts = path.split("/")
        if not -len(parts) <= index < len(parts) or any("<path:" in p for p in parts[: index + 1] if index >= 0) or "<" in parts[index]:
            return None
        values.add(parts[index])
    return values.pop() if len(values) == 1 else None
