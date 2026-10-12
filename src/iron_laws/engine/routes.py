"""
오철칙 라우트 접근통제 행렬: 웹 프레임워크의 라우트를 찾고 라우트마다 인증·인가 근거를 yes/no/unknown으로 판정한다

지원: Flask·FastAPI·Django(urls.py)·Express·Next.js(app/**/route, pages/api)·Spring·ASP.NET.
- 인증(auth) yes: 라우트 정의·미들웨어·핸들러 본문에 인증 표지가 있거나, 평가할 수 있는 전역 설정이 이 경로를 보호한다.
  no: 아무 근거가 없거나 전역 설정이 이 경로를 명시적으로 공개(permitAll·AllowAnonymous)한다.
  unknown: 전역 설정이 있지만 이 경로에 적용되는지 정할 수 없다(Spring 보안 체인의 일부 경로 규칙, Next.js 미들웨어 matcher 등).
- 인가(authz)는 객체 식별자를 받는 라우트(`/users/{id}`, `/:id`, `<int:id>`)와 관리 경로에서만 본다.
  yes: 역할·권한 검사가 있거나, 데이터 조회보다 먼저 현재 사용자와 대상의 소유 관계를 비교한다.
  no: 식별자로 데이터를 조회하는데 그런 검사가 없다. unknown: 데이터 조회 여부를 정할 수 없다. 해당 없는 라우트는 n/a.
작성자: 최진호
작성일: 2026-10-12
"""

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

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

    def as_row(self) -> dict:
        return {k: getattr(self, k) for k in ("framework", "method", "path", "file", "line", "handler", "sensitive", "auth", "auth_reason", "authz", "authz_reason")}


def is_sensitive(method: str, path: str) -> bool:
    """데이터를 바꾸는 메서드, 또는 관리·개인정보·결제 경로(GET 포함). 로그인·헬스체크 같은 공개 경로는 뺀다."""
    if PUBLIC_PATH.match(path.lstrip("/")) and not SENSITIVE_PATH.search(path):
        return False
    if PUBLIC_NAMES.match(path):
        return False
    return method.lower() in ("post", "put", "patch", "delete") or bool(SENSITIVE_PATH.search(path))


def _authz(path: str, text: str, handler_body: str) -> tuple[str, str]:
    if ROLE_MARKER.search(text):
        return "yes", "역할·권한 검사가 있다"
    needs = bool(ID_PARAM.search(path)) or bool(re.search(r"(?i)admin|manage|internal", path))
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


def _spring(src: SourceFile, g: _Globals) -> list[Route]:
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
        method = "GET" if m.group(1) in ("Get", "Request") else m.group(1).upper()
        path_m = re.search(r"\"([^\"]*)\"", m.group(2) or "")
        path = prefix + (path_m.group(1) if path_m else "")
        if class_secured or re.search(r"@(PreAuthorize|Secured|RolesAllowed)|Principal|Authentication|SecurityContext", text):
            auth = ("yes", "메서드·클래스에 보안 애너테이션이나 인증 주체 사용이 있다")
        elif any(_ant_match(p, path) for p in g.spring_public):
            auth = ("no", "보안 설정이 이 경로를 permitAll로 공개한다")
        elif g.spring == "authenticated":
            auth = ("yes", "보안 설정의 anyRequest()가 인증을 요구한다")
        elif any(_ant_match(p, path) for p in g.spring_protected):
            auth = ("yes", "보안 설정의 경로 규칙이 이 경로에 인증을 요구한다")
        elif g.spring == "partial":
            auth = ("unknown", "보안 설정이 있지만 이 경로에 적용되는 규칙을 정할 수 없다")
        else:
            auth = ("no", "보안 애너테이션·보안 설정이 없다")
        authz = _authz(path, (head_class if class_secured else "") + text, text)
        routes.append(Route("spring", method, path, src.path.as_posix(), src.line_of(fn.node), fn.name, is_sensitive(method, path), *auth, *authz, node=fn.node))
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


def discover_routes(files: list[SourceFile]) -> list[Route]:
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
            routes += _express(f) + _nextjs(f, g)
        elif f.lang is Lang.JAVA:
            routes += _spring(f, g)
        elif f.lang is Lang.CSHARP:
            routes += _aspnet(f, g)
    return sorted(routes, key=lambda r: (r.file, r.line, r.method))
