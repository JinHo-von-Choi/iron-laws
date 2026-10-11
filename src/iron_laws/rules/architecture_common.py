"""architecture 계열의 공유 AST·판정 기반."""
import re

from iron_laws.core.models import IronLaw, RuleLayer
from iron_laws.engine.ast_tools import (
    FUNCTION_TYPES,
)
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.source import SourceFile
from iron_laws.rules.base import BaseRule

GENERATED_RE = re.compile(r"(?i)generated\s+by|do\s+not\s+edit|auto-?generated|@generated|code generated")


class ArchRule(BaseRule):
    layer = RuleLayer.ARCHITECTURE
    gov_standard = None
    iron_law = IronLaw.LAW_5


def _is_generated(src: SourceFile) -> bool:
    return bool(GENERATED_RE.search("\n".join(src.lines[:5]))) or src.path.name.endswith((".d.ts", ".min.js", ".pb.go", "_pb2.py", ".designer.cs", ".g.cs"))


LAYER_RANK = {"presentation": 0, "service": 1, "data": 2}


LAYER_LABEL = {"presentation": "표현(컨트롤러)", "service": "서비스", "data": "데이터 접근"}


LAYER_DIR_TOKENS = {
    "presentation": {"controller", "controllers", "route", "routes", "router", "routers", "api", "view", "views", "endpoint", "endpoints", "page", "pages", "web", "ui", "resources"},
    "service": {"service", "services", "usecase", "usecases", "use_cases", "application", "business", "logic"},
    "data": {"repository", "repositories", "repo", "repos", "dao", "daos", "persistence", "db", "database", "store", "stores", "infrastructure", "orm", "mapper", "mappers"},
}


LAYER_DIR_TOKENS["presentation"].discard("resources")


LAYER_FILE_PATTERNS = [
    ("presentation", re.compile(r"(?i)(controller|_routes?|\.routes?|_router|\.router|_view)\.\w+$|Controller\.\w+$")),
    ("service", re.compile(r"(?i)(service|usecase|_service|\.service)\.\w+$|Service\.\w+$|UseCase\.\w+$")),
    ("data", re.compile(r"(?i)(repository|_repository|\.repository|_repo|_dao|\.dao)\.\w+$|Repository\.\w+$|Dao\.\w+$")),
]


MAPPING_ONLY_RE = re.compile(
    r"^(org\.springframework\.data\.(annotation|domain|web|relational\.core\.mapping|mongodb\.core\.mapping)\.|(javax|jakarta)\.persistence\.(Entity|Table|Id|Column|GeneratedValue|Embeddable|Embedded|Enumerated|Version|Lob|Temporal|OneToMany|ManyToOne|ManyToMany|OneToOne|JoinColumn|MappedSuperclass|Transient|GenerationType|EnumType|FetchType|CascadeType|Inheritance|Index|UniqueConstraint))"
)


DB_IMPORT_RE = re.compile(
    r"^(sqlite3|psycopg2?|pymysql|MySQLdb|mysql\.connector|pymongo|sqlalchemy|asyncpg|aiosqlite|peewee|tortoise|django\.db|pg|mysql2?|better-sqlite3|mongodb|mongoose|knex|prisma|@prisma/client|typeorm|sequelize|@supabase/supabase-js|drizzle-orm|java\.sql|javax\.persistence|jakarta\.persistence|org\.hibernate|org\.springframework\.jdbc|org\.springframework\.data|org\.mybatis|System\.Data|Microsoft\.EntityFrameworkCore|Dapper|Npgsql|database/sql|gorm\.io|github\.com/jmoiron/sqlx|github\.com/lib/pq|go\.mongodb\.org|Illuminate\\\\Database)"
)


WEB_IMPORT_RE = re.compile(
    r"^(flask|fastapi|django\.http|django\.shortcuts|starlette|aiohttp\.web|express|fastify|koa|next/server|next/headers|hono|javax\.servlet|jakarta\.servlet|org\.springframework\.web|Microsoft\.AspNetCore\.(Mvc|Http|Routing)|net/http|github\.com/gin-gonic/gin|github\.com/labstack/echo|Illuminate\\\\Http)"
)


IMPORT_PATTERNS = {
    Lang.PYTHON: re.compile(r"^[ \t]*(?:from[ \t]+([\w.]+)[ \t]+import|import[ \t]+([\w.]+))", re.MULTILINE),
    Lang.JAVA: re.compile(r"^[ \t]*import[ \t]+(?:static[ \t]+)?([\w.]+)[ \t]*;", re.MULTILINE),
    Lang.CSHARP: re.compile(r"^[ \t]*using[ \t]+(?:static[ \t]+)?([\w.]+)[ \t]*;", re.MULTILINE),
    Lang.GO: re.compile(r'^[ \t]*(?:import[ \t]+)?(?:\w+[ \t]+)?"([\w./\-]+)"[ \t]*$', re.MULTILINE),
    Lang.PHP: re.compile(r"^[ \t]*use[ \t]+([\w\\]+)", re.MULTILINE),
}


JS_IMPORT = re.compile(r"""(?:from\s*|require\(\s*|import\s*\(\s*|import\s+)['"]([^'"]+)['"]""")


def infer_layer(src: SourceFile) -> str | None:
    """어노테이션, 파일명, 경로 순으로 계층을 추정한다. 근거가 없으면 None."""
    path = src.path.as_posix()
    if src.lang is Lang.JAVA:
        if re.search(r"@(Rest)?Controller\b|@(Get|Post|Put|Patch|Delete|Request)Mapping\b", src.text):
            return "presentation"
        if re.search(r"@Repository\b", src.text):
            return "data"
        if re.search(r"@Service\b", src.text):
            return "service"
    for layer, pattern in LAYER_FILE_PATTERNS:
        if pattern.search(path):
            return layer
    if src.lang is Lang.JAVA and re.search(r"@(Rest)?Controller\b", src.text):
        return "presentation"
    for part in reversed(src.path.parts[:-1]):
        token = part.lower()
        for layer, tokens in LAYER_DIR_TOKENS.items():
            if token in tokens:
                return layer
    return None


def external_imports(src: SourceFile) -> list[tuple[str, int]]:
    text = src.code_text
    found: list[tuple[str, int]] = []
    pattern = JS_IMPORT if src.lang in JS_FAMILY else IMPORT_PATTERNS.get(src.lang) if src.lang else None
    if pattern is None:
        return found
    for m in pattern.finditer(text):
        spec = next((g for g in m.groups() if g), "")
        if spec:
            found.append((spec, text.count("\n", 0, m.start()) + 1))
    return found


FUNCTION_TYPE_SET = {t for types in FUNCTION_TYPES.values() for t in types}


EXCEPTION_CALLEE = re.compile(r"^new\w*(Exception|Error)$|^(?:\w+\.)*\w*(Exception|Error)$|(?:^|\.)(badRequest|notFound|forbidden|unauthorized|conflict|abort)$")


CENTRAL_ERROR_FILE = re.compile(r"(?i)(error_?codes?|errors?|error_?messages?|messages?|exception_?messages?|constants?|ErrorCode)\.\w+$")


STANDARD_HEADER_RE = re.compile(
    r"(?i)^(host|referer|referrer|user-agent|content-type|content-length|content-\w+|accept(-\w+)?|authorization|cookie|set-cookie|origin|location|cache-control|etag|if-\w+|x-forwarded-\w+|x-requested-with|connection|upgrade|server|date|pragma|expires|vary|allow)$"
)


KEY_CALLEE = re.compile(r"(?:^|\.)(?:setAttribute|getAttribute|removeAttribute|getHeader|setHeader|addHeader|getItem|setItem|removeItem)$")


REUSABLE_PATTERNS = {
    Lang.JAVA: [
        (re.compile(r'^Pattern\.compile$'), True, "Pattern.compile"),
        (re.compile(r"^newObjectMapper$"), False, "new ObjectMapper()"),
        (re.compile(r"^newGson$"), False, "new Gson()"),
        (re.compile(r"^DateTimeFormatter\.ofPattern$"), True, "DateTimeFormatter.ofPattern"),
        (re.compile(r"^newRestTemplate$"), False, "new RestTemplate()"),
        (re.compile(r"^HttpClient\.new(HttpClient|Builder)$"), False, "HttpClient 생성"),
        (re.compile(r"^newOkHttpClient$"), False, "new OkHttpClient()"),
        (re.compile(r"^newSecureRandom$"), False, "new SecureRandom()"),
        (re.compile(r"^Executors\.new\w*(Pool|Executor)\w*$"), False, "스레드 풀 생성"),
    ],
    Lang.CSHARP: [
        (re.compile(r"^newHttpClient$"), False, "new HttpClient()"),
        (re.compile(r"^newRegex$"), True, "new Regex"),
        (re.compile(r"^newJsonSerializerOptions$"), False, "new JsonSerializerOptions"),
    ],
    Lang.PYTHON: [
        (re.compile(r"^re\.compile$"), True, "re.compile"),
        (re.compile(r"^(httpx\.(Async)?Client|requests\.Session)$"), False, "HTTP 클라이언트 생성"),
    ],
    Lang.GO: [(re.compile(r"^regexp\.MustCompile$"), True, "regexp.MustCompile")],
}


for _l in JS_FAMILY:
    REUSABLE_PATTERNS[_l] = [
        (re.compile(r"^newRegExp$"), True, "new RegExp"),
        (re.compile(r"^axios\.create$"), False, "axios.create"),
        (re.compile(r"^newIntl\.\w+$"), False, "new Intl.*"),
    ]


LOOP_NODE_TYPES = {
    "for_statement",
    "for_in_statement",
    "enhanced_for_statement",
    "foreach_statement",
    "while_statement",
    "do_statement",
    "list_comprehension",
    "generator_expression",
}


DB_RECEIVER = re.compile(
    r"(?i)(repo\w*|repository|\w*Repository|dao\w*|\w*Dao|mapper|\w*Mapper|entityManager|\bem\b|jdbc\w*|^db\b|\.db\b|cursor|\bcur\b|conn\w*|prisma\.\w+|collection|knex|sequelize)|(?-i:\w+Model\b|\b_?db_?[Cc]ontext\b|\b_context\b|\bdbContext\b)"
)


DB_READ = re.compile(r"^(find\w*|get\w*|select\w*|query\w*|fetch\w*|load\w*|read\w*|count\w*|exists\w*|first|filter\w*|where|execute\w*)$", re.IGNORECASE)


DB_WRITE = re.compile(r"^(save\w*|insert\w*|update\w*|delete\w*|remove\w*|create\w*)$", re.IGNORECASE)


REQUEST_HOOK_NAMES = re.compile(r"^(doFilter|doFilterInternal|preHandle|Invoke|InvokeAsync|dispatch|process_request|before_request)$")
