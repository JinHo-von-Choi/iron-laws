"""
오철칙 경량 오염(taint) 분석: 함수 내부의 외부 입력 전파 추적

실행 순서를 따라가는 흐름 분석이다. 문장마다 그 문장이 실행되기 직전의 오염 변수 집합을 계산하고,
분기(if·switch·try)에서는 갈래별로 따로 실행한 뒤 합치며, 반복문은 두 번 돌려 반복 간 전달을 반영한다.
싱크는 자기 위치의 상태로 판정하므로 뒤따르는 재대입이 앞선 위험한 사용을 가리지 않는다.
작성자: 최진호
작성일: 2026-10-04
"""

import re
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum

from tree_sitter import Node

from iron_laws.engine import xfile, xfile_js
from iron_laws.engine.ast_tools import (
    CALL_TYPES,
    FUNCTION_TYPES,
    NESTING_TYPES,
    STRING_TYPES,
    _is_property_position,
    enclosing_function,
    function_parts,
    has_interpolation,
    identifiers_in,
    iter_calls,
    iter_functions,
    walk,
)
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.source import SourceFile

WEB_SOURCE_RE = re.compile(
    r"""(?x)
    \brequest\.(args|form|values|json|data|files|cookies|headers|GET|POST|query_params|
                path_params|get_json|get_data|environ|META|FILES|body|query|params|url|path)\b
    | \b(?:request|req|\w+Request|\w+Req|p[A-Z]?[rR]eq\w*)\.(getParameter\w*|getHeader\w*|getQueryString|getCookies|getInputStream|getReader|getPart\w*|getPathInfo|getPathTranslated|getRequestURI|getRequestURL|getContentType|getRemoteHost)\b
    | \breq\.(query|body|params|cookies|headers|url|originalUrl|path|files|file|hostname)\b
    | \bctx\.(query|request|params|req)\b
    | \bcall\.(parameters|receiveParameters|receiveText|receive)\b | \bcall\.request\.(queryParameters|headers|cookies)\b
    | \bRequest\.(Query|Form|Headers|Cookies|Body|QueryString|Params|Path|Url|RawUrl|Files)\b
    | \bHttpContext\.Request\b
    | \$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\b
    | \br\.(FormValue|PostFormValue|URL\.Query|URL\.Path|Header\.Get|Body|Form|PostForm|MultipartForm)\b
    | \bc\.(Query|Param|PostForm|GetHeader|BindJSON|ShouldBind\w*|DefaultQuery|FormValue|Params)\b
    | \.getOriginalFilename\s*\( | \.FileName\b | \bheader\.Filename\b | \bfile\.filename\b | \bfile\.name\b | \boriginalname\b
    | \bwindow\.location\b | \blocation\.(search|hash|href)\b | \bdocument\.(cookie|URL|referrer)\b
    | \.searchParams\b | \bURLSearchParams\b | \bFromQuery\b | \bFromBody\b | \bFromRoute\b | \bFromForm\b
    | \bweb::(Query|Path|Json|Form)\b | \bquery_params\b | \bpath_params\b
    | \b\w*[eE]xchange\.(getRelativePath|getRequestPath|getRequestURI|getQueryString|getQueryParameters|getPathParameters|getRequestHeaders)\s*\(
    | \b\w*(?:[rR]equest|[cC]ontext|ctx|rc)\.(getPathParameter|getQueryParameter|normalisedPath|normalizedPath|pathParam|queryParam)\s*\(
    | \b\w*(?:[cC]ontext|ctx|rc)\.request\(\)\.(path|uri|getParam|params|absoluteURI)\s*\(
    """,
)
# 압축 파일 항목 이름(`ZipEntry.getName()` 등): 항목 이름에 `../`나 절대 경로가 들어 있을 수 있어 압축을 푸는 쪽에서는 외부 입력이다(Zip Slip).
# 이름이 흔한 메서드라 압축·메일 API를 가져온 파일에서만 적용한다
ARCHIVE_IMPORT_RE = re.compile(
    r"\bimport\s+(?:static\s+)?(?:java\.util\.(?:zip|jar)|org\.apache\.commons\.compress|net\.lingala\.zip4j|org\.codehaus\.plexus\.archiver"
    r"|org\.apache\.tools\.(?:zip|tar)|javax\.mail|jakarta\.mail|org\.rauschig|de\.schlichtherle)"
    r"|^\s*(?:import\s+(?:zipfile|tarfile)\b|from\s+(?:zipfile|tarfile)\s+import)"
    r"|require\(\s*['\"](?:adm-zip|yauzl|unzipper|jszip|tar|tar-stream)['\"]\s*\)|from\s+['\"](?:adm-zip|yauzl|unzipper|jszip|tar|tar-stream)['\"]",
    re.MULTILINE,
)
ARCHIVE_SOURCE_RE = re.compile(
    r"""(?x)
    \.(getNextEntry|getNextJarEntry|getNextTarEntry|getNextZipEntry)\s*\(
    | \b(?:\w*(?:[eE]ntry|[eE]ntries|[hH]eader)|je|ze|te)\.(getName|getFileName)\s*\(
    | \.nextElement\s*\(
    | \b\w*[pP]art\w*\.getFileName\s*\(
    | \.(namelist|infolist|getmembers|getnames)\s*\(
    | \b(?:\w*[eE]ntry|member|zinfo|zip_info|info|tarinfo)\.(entryName|fileName|filename|name|path)\b
    """
)
CLI_SOURCE_RE = re.compile(
    r"""(?x)
    \b(input|raw_input)\s*\( | \bsys\.argv\b | \bprocess\.argv\b | \bos\.Args\b | \bargv\[ | \bstd::env::args\b
    | \bscanf\s*\( | \bgets\s*\( | \bfgets\s*\( | \bgetline\s*\( | \bcin\s*>>
    """,
)
SOURCE_RE = WEB_SOURCE_RE
ANNOTATED_PARAM_RE = re.compile(
    r"@(RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute|QueryParam|PathParam|FormParam)"
    r"|\[(FromQuery|FromBody|FromRoute|FromForm|FromHeader)\b"
)

ASSIGN_TYPES = {
    "assignment",
    "augmented_assignment",
    "variable_declarator",
    "assignment_expression",
    "named_expression",
    "short_var_declaration",
    "assignment_statement",
    "let_declaration",
    "init_declarator",
    "augmented_assignment_expression",
    "compound_assignment_expr",
    "enhanced_for_statement",
    "for_in_statement",
    "foreach_statement",
    "for_statement",
    "range_clause",
    "property_declaration",
}
AUGMENTED_TYPES = ("augmented_assignment", "augmented_assignment_expression", "compound_assignment_expr")
LOOP_ASSIGN_TYPES = {"enhanced_for_statement", "for_in_statement", "foreach_statement", "for_statement", "range_clause"}


def _target_and_value(node: Node) -> tuple[Node | None, Node | None]:
    if node.type == "property_declaration":  # Kotlin val x = 식 (필드 이름이 없다)
        target = next((c for c in node.named_children if c.type == "variable_declaration"), None)
        value = node.named_children[-1] if node.named_children and node.named_children[-1].type not in ("variable_declaration", "user_type", "modifiers") else None
        return target, value
    if node.type == "assignment" and node.child_by_field_name("left") is None and len(node.named_children) == 2:
        return node.named_children[0], node.named_children[1]  # Kotlin 대입
    if node.type in LOOP_ASSIGN_TYPES:
        loop_var = node.child_by_field_name("name") or node.child_by_field_name("left")
        iterable = node.child_by_field_name("value") or node.child_by_field_name("right")
        return loop_var, iterable
    left = node.child_by_field_name("left") or node.child_by_field_name("name") or node.child_by_field_name("pattern")
    right = node.child_by_field_name("right") or node.child_by_field_name("value")
    if left is None and node.type == "init_declarator":
        left = node.child_by_field_name("declarator")
    if right is None and node.type == "variable_declarator":
        seen_equals = False
        for child in node.children:
            if child.type == "equals_value_clause" and child.named_children:
                right = child.named_children[-1]
            elif child.type == "=":
                seen_equals = True
            elif seen_equals and child.is_named:
                right = child
                break
    return left, right


# ---------------------------------------------------------------------------
# 접근 경로: 오염 상태의 이름은 변수(`obj`)이거나 변수에 한 단계를 붙인 경로(`obj.field`, `map[key]`)다.
# 필드·상수 키 한 단계까지만 구분하고, 그보다 깊거나 키가 상수가 아니면 객체 전체로 본다.
# 경로를 읽을 때: 그 경로나 객체 전체가 오염이면 오염. 객체를 통째로 쓸 때: 객체 전체나 그 필드 하나라도 오염이면 오염.
# ---------------------------------------------------------------------------

# (노드 형식, 객체 필드, 속성 필드)
_FIELD_ACCESS = {
    "attribute": ("object", "attribute"),
    "member_expression": ("object", "property"),
    "field_access": ("object", "field"),
    "member_access_expression": ("expression", "name"),
    "selector_expression": ("operand", "field"),
    "field_expression": ("argument", "field"),
}
_INDEX_ACCESS = {
    "subscript": ("value", "subscript"),
    "subscript_expression": ("object", "index"),
    "array_access": ("array", "index"),
    "element_access_expression": ("expression", "subscript"),
    "index_expression": ("operand", "index"),
}
_ROOT_TYPES = {"identifier", "variable_name", "this", "self", "this_expression"}
COLLECTION_GET = frozenset({"get", "getOrDefault", "getProperty"})
COLLECTION_PUT = frozenset({"put", "set", "setdefault", "setProperty", "putIfAbsent"})


def _constant_key(src: SourceFile, node: Node | None) -> str | None:
    if node is None:
        return None
    if node.type in ("argument_list", "bracketed_argument_list") and len(node.named_children) == 1:
        node = node.named_children[0]
    if node.type in ("integer", "number", "decimal_integer_literal", "integer_literal", "int_literal"):
        # Python에서는 d[1]과 d["1"]이 다른 칸이다. JavaScript 등은 숫자 키가 문자열 키와 같은 칸이라 그대로 둔다
        if src.lang is Lang.PYTHON:
            try:
                return "\x00int:" + str(int(src.text_of(node), 0))  # 0x1·1_0 같은 표기를 값으로 맞추고, 문자열 키와 겹치지 않게 한다
            except ValueError:  # iron-laws: ignore[IL-301] 값으로 바꿀 수 없는 표기(예: 0으로 시작하는 정수)는 원문 표기를 키로 쓴다
                return "\x00int:" + src.text_of(node)
        return src.text_of(node)
    if node.type in STRING_TYPES and not has_interpolation(node):
        text = src.text_of(node)
        return text[1:-1] if len(text) >= 2 and text[0] in "'\"`" else None
    return None


def _root_name(src: SourceFile, node: Node) -> str | None:
    if node.type in _ROOT_TYPES or (node.type == "identifier" and node.child_count == 0):
        return src.text_of(node).lstrip("$")
    return None


def access_path(src: SourceFile, node: Node) -> tuple[str, bool] | None:
    """(경로, 정확한지). `obj.f`·`d['k']` → ('obj.f', True)·('d[k]', True). 더 깊거나 키가 상수가 아니면 (객체 루트, False)"""
    root = _root_name(src, node)
    if root is not None:
        return root, True
    spec = _FIELD_ACCESS.get(node.type)
    kind = "."
    if spec is None:
        spec = _INDEX_ACCESS.get(node.type)
        kind = "["
    if spec is None:
        return None
    obj = node.child_by_field_name(spec[0])
    if obj is None:
        return None
    inner = access_path(src, obj)
    if inner is None:
        return None
    base, exact = inner
    if not exact or "." in base or "[" in base:
        return base.split(".", 1)[0].split("[", 1)[0], False
    if kind == ".":
        prop = node.child_by_field_name(spec[1])
        return (f"{base}.{src.text_of(prop)}", True) if prop is not None else (base, False)
    key = _constant_key(src, node.child_by_field_name(spec[1]) or (node.named_children[1] if len(node.named_children) > 1 else None))
    if key is None:
        return base, False
    return (f"{base}.{key}" if src.lang in JS_FAMILY else f"{base}[{key}]"), True


def path_root(name: str) -> str:
    return name.split(".", 1)[0].split("[", 1)[0]


def tainted_roots(names) -> set[str]:
    """오염 상태의 경로들을 변수 이름으로(증거 표시용)"""
    return {path_root(n) for n in names}


def _path_hit(path: str, whole_use: bool, names: set[str]) -> bool:
    if path in names:
        return True
    root = path_root(path)
    if root != path and root in names:
        return True
    if whole_use:
        return any(n.startswith(path + ".") or n.startswith(path + "[") for n in names)
    return False


def _reads(src: SourceFile, node: Node, skip=None) -> list[tuple[str, bool]]:
    """식이 읽는 (경로, 객체 통째로 쓰는지). 메서드 호출의 수신 객체는 통째로 쓰는 것으로 본다(게터가 필드를 돌려줄 수 있다).
    상수 키 조회(`d.get('k')`)는 그 경로만 읽는다."""
    found: list[tuple[str, bool]] = []
    stack = [node]
    while stack:
        n = stack.pop()
        if skip is not None and skip(n):
            continue
        parts = _call_parts(src, n) if src.lang is not None else None
        if parts is not None and "." in parts[0]:
            method = parts[0].rsplit(".", 1)[-1]
            if n.type in ("method_invocation", "member_call_expression"):
                receiver = n.child_by_field_name("object")  # Java·PHP: 수신 객체가 호출 노드의 object 필드에 있다
            else:
                fn = n.child_by_field_name("function")
                receiver = fn.child_by_field_name(_FIELD_ACCESS[fn.type][0]) if fn is not None and fn.type in _FIELD_ACCESS else None
            receiver_path = access_path(src, receiver) if receiver is not None else None
            if receiver_path is not None and receiver_path[1] and method in COLLECTION_GET and parts[1]:
                key = _constant_key(src, parts[1][0])
                if key is not None and "." not in receiver_path[0] and "[" not in receiver_path[0]:
                    found.append((f"{receiver_path[0]}[{key}]", False))
                    stack.extend(parts[1][1:])
                    continue
            if receiver_path is not None:
                found.append((receiver_path[0], True))
                stack.extend(parts[1])
                continue
        path = access_path(src, n) if n.type in _FIELD_ACCESS or n.type in _INDEX_ACCESS else None
        if path is not None:
            found.append((path[0], not path[1] or path[0] == path_root(path[0])))
            spec = _INDEX_ACCESS.get(n.type)
            if spec is not None:  # 상수가 아닌 첨자 식 안의 변수도 읽는다
                index = n.child_by_field_name(spec[1])
                if index is not None:
                    stack.append(index)
            continue
        if n.type in ("identifier", "variable_name", "property_identifier", "field_identifier"):
            if (n.child_count == 0 or n.type == "variable_name") and not _is_property_position(n):
                found.append((src.text_of(n).lstrip("$"), True))
            continue
        if n.type == "string_literal" and src.lang is Lang.KOTLIN:  # "$name" 단순 템플릿
            found += [(m, True) for m in re.findall(r"(?<!\\)\$([A-Za-z_]\w*)", src.text_of(n))]
        stack.extend(n.children)
    return found


def reads_tainted(src: SourceFile, node: Node, names: set[str], skip=None) -> bool:
    if not names:
        return False
    return any(_path_hit(path, whole, names) for path, whole in _reads(src, node, skip))


def _target_names(src: SourceFile, target: Node) -> set[str]:
    """정의 추적용: 변수 전체에 값을 넣는 대입의 변수 이름(필드·첨자 대입은 변수 정의가 아니다)"""
    return identifiers_in(src, target) if target.type not in _FIELD_ACCESS and target.type not in _INDEX_ACCESS else set()


def _target_paths(src: SourceFile, target: Node) -> tuple[set[str], bool]:
    """대입 대상의 경로와, 이 대입이 대상의 이전 값을 덮어쓰는지(강한 갱신). 필드·상수 키는 그 경로만, 그 밖의 첨자는 객체 전체에 약하게 더한다."""
    if target.type in _FIELD_ACCESS or target.type in _INDEX_ACCESS:
        path = access_path(src, target)
        if path is None:
            return set(), False
        return {path[0]}, path[1]
    return identifiers_in(src, target), True


_STRING_FRAGMENT_TYPES = frozenset({"string_fragment", "string_content", "string_value", "escape_sequence", "string_literal_content"})


def _text_without_plain_strings(src: SourceFile, node: Node) -> str:
    """문자열 리터럴 안의 글자를 지운 식의 원문. 문자열 안에 적힌 `request.args` 같은 글자는 코드가 아니다.
    보간(`${...}`, `{...}`, f-string)이 있는 문자열은 고정 조각만 지우고 보간식은 코드로 남긴다."""
    base = node.start_byte
    buf = bytearray(src.data[base : node.end_byte])

    def blank(n: Node) -> None:
        for i in range(max(n.start_byte, base) - base, min(n.end_byte, node.end_byte) - base):
            buf[i] = 32

    for n in walk(node):
        if n.type not in STRING_TYPES:
            continue
        if not has_interpolation(n):
            blank(n)
            continue
        for child in n.children:
            if child.type in _STRING_FRAGMENT_TYPES:
                blank(child)
    return buf.decode("utf-8", errors="replace")


# 규칙이 잠시 더하는 소스 종류(예: LLM 응답 ai_response). 흐름 해석 캐시 키에 종류 이름이 들어가 기본 해석과 섞이지 않는다
_EXTRA_SOURCE: re.Pattern[str] | None = None
_EXTRA_KIND = ""


@contextmanager
def extra_sources(pattern: re.Pattern[str], kind: str):
    """이 블록 안의 오염 판정에 pattern에 맞는 식을 외부 입력으로 더한다."""
    global _EXTRA_SOURCE, _EXTRA_KIND
    saved = (_EXTRA_SOURCE, _EXTRA_KIND)
    _EXTRA_SOURCE, _EXTRA_KIND = pattern, kind
    try:
        yield
    finally:
        _EXTRA_SOURCE, _EXTRA_KIND = saved


def archive_file(src: SourceFile) -> bool:
    """압축·메일 첨부 API를 가져온 파일인가(압축 항목 이름을 외부 입력으로 볼 파일)"""
    return src.memo("archive_imports", lambda: bool(ARCHIVE_IMPORT_RE.search(src.code_text)))


def _source_in(text: str, cli: bool, lang: Lang | None = None, archive: bool = False) -> bool:
    custom = CUSTOM_SOURCES.get(lang) if lang is not None else None
    return bool(
        WEB_SOURCE_RE.search(text)
        or (archive and ARCHIVE_SOURCE_RE.search(text))
        or (cli and CLI_SOURCE_RE.search(text))
        or (_EXTRA_SOURCE is not None and _EXTRA_SOURCE.search(text))
        or (custom is not None and custom.search(text))
    )


def expr_has_source(src: SourceFile, node: Node, cli: bool = False) -> bool:
    text = src.text_of(node)
    if not _source_in(text, cli, src.lang, archive_file(src)):
        return False
    if src.root is None:
        return True
    # 원문에서 입력 원천처럼 보이는 글자가 보이면, 그것이 문자열 리터럴 안의 글자인지 코드인지 가려서 다시 본다
    return _source_in(_text_without_plain_strings(src, node), cli, src.lang, archive_file(src))


# ---------------------------------------------------------------------------
# 정제 함수: 취약점 문맥별로 유효한 정제만 인정한다
# ---------------------------------------------------------------------------


class Ctx(StrEnum):
    """오염된 값이 도달하는 곳의 종류. 정제는 자기가 막는 문맥에서만 인정된다."""

    ANY = "any"
    HTML = "html"
    SQL = "sql"
    SHELL = "shell"
    PATH = "path"
    URL = "url"
    LDAP = "ldap"
    XPATH = "xpath"
    CODE = "code"
    HEADER = "header"


def _fn_re(names: str) -> re.Pattern[str]:
    return re.compile(rf"(?i)(?:^|[._])(?:{names})$")


# 값의 종류를 바꾸거나 값에서 파생된 수치여서 어느 문맥에서든 문자열 주입을 막는 함수
_UNIVERSAL = "parseint|parsefloat|int|float|bool|number|len|length|abs|round|hashpw|hexdigest|digest|uuid\\w*|isdigit|isnumeric"
# 이름이 검증·허용 목록임을 말하는 함수. 무엇을 막는지는 알 수 없으므로 모든 문맥에서 인정한다.
_GENERIC = "sanitiz\\w*|validat\\w*|whitelist\\w*|allowlist\\w*|is_?safe\\w*"
_BY_CONTEXT: dict[Ctx, str] = {
    Ctx.HTML: "escape\\w*|encode_?for_?html\\w*|encode_?html\\w*|for_?html\\w*|htmlspecialchars|htmlentities|esc_html\\w*|dompurify|bleach|clean",
    Ctx.SQL: "escape\\w*|quote\\w*|encode_?for_?sql\\w*|addslashes|real_escape\\w*|format_?sql",
    Ctx.SHELL: "quote\\w*|escapeshell\\w*|shellescape|shellwords|escape\\w*",
    Ctx.PATH: "secure_filename|basename|getname|filepath\\.base|getfilename|sanitize_?filename|safe_?join|safe_?path|clean",
    Ctx.URL: "",
    Ctx.LDAP: "escape\\w*|encode_?for_?ldap\\w*|escape_filter_chars",
    Ctx.XPATH: "escape\\w*|encode_?for_?xpath\\w*|quote\\w*",
    Ctx.CODE: "",
    Ctx.HEADER: "escape\\w*|encode\\w*|quote\\w*|clean",
}
# 문맥을 모르는 호출(기본값)은 위 이름을 모두 인정한다.
_ALL_NAMES = "|".join(
    dict.fromkeys(n for names in [_UNIVERSAL, _GENERIC, "encode\\w*", *_BY_CONTEXT.values()] for n in names.split("|") if n)
)
SANITIZER_FN_RE = _fn_re(_ALL_NAMES)
_CONTEXT_SANITIZERS: dict[Ctx, re.Pattern[str]] = {
    ctx: _fn_re("|".join(n for n in (_UNIVERSAL + "|" + _GENERIC + "|" + names).split("|") if n))
    for ctx, names in _BY_CONTEXT.items()
}


_UNIVERSAL_RE = _fn_re(_UNIVERSAL)
_BASE_SANITIZERS = _fn_re(f"{_UNIVERSAL}|{_GENERIC}")
# HTML 출력용 이스케이프는 이름이 escape라도 SQL·셸·경로에는 아무 보호도 하지 못한다
_HTML_ONLY_RE = re.compile(
    r"(?i)(?:^|\.)(?:html|cgi|markupsafe|saxutils|bleach|dompurify|xml)\.|escape_?html|htmlspecialchars|htmlentities|encode_?for_?html|esc_html|for_?html"
)


# 사람이 검토하고 양성·음성 예제로 확인한 명세(core/custom_spec.py)가 더하는 소스와 정제 함수. 점검 시작 때 한 번 정한다.
# 명세 항목은 적힌 언어에만 적용한다(언어 → 소스 정규식, (언어, 문맥) → 정제 함수 이름 정규식)
CUSTOM_SOURCES: dict[Lang, re.Pattern[str]] = {}
CUSTOM_SANITIZERS: dict[tuple[Lang, Ctx], re.Pattern[str]] = {}
CUSTOM_KIND = ""


def set_custom_spec(sources: dict, sanitizers: dict, kind: str) -> None:
    global CUSTOM_SOURCES, CUSTOM_SANITIZERS, CUSTOM_KIND
    CUSTOM_SOURCES, CUSTOM_SANITIZERS, CUSTOM_KIND = dict(sources), dict(sanitizers), kind


def sanitizer_name_matches(callee: str, ctx: Ctx, lang: Lang | None = None) -> bool:
    custom = CUSTOM_SANITIZERS.get((lang, ctx)) if lang is not None else None
    if custom is not None and custom.search(callee):
        return True
    if ctx is Ctx.ANY:
        return bool(SANITIZER_FN_RE.search(callee))
    if ctx is not Ctx.HTML and _HTML_ONLY_RE.search(callee):
        return bool(_BASE_SANITIZERS.search(callee))
    return bool(_CONTEXT_SANITIZERS[ctx].search(callee))


MUTATING_METHODS = frozenset(
    {"add", "append", "put", "push", "extend", "insert", "offer", "addAll", "putAll", "setdefault", "update", "set", "write", "concat"}
)
CONDITIONAL_TYPES = NESTING_TYPES | {
    "conditional_expression",
    "ternary_expression",
    "catch_clause",
    "except_clause",
    "switch_case",
    "case_clause",
    "match_arm",
    "elif_clause",
    "else_clause",
    "finally_clause",
}
_IN_PROGRESS: set[tuple[str, int, frozenset[str], Ctx]] = set()
_DEPTH = 0
MAX_HELPER_DEPTH = 4
_CUTS: list[tuple[str, int, frozenset[str], Ctx]] = []  # 재귀로 끊은 함수 키. 끊긴 결과는 호출 경로에 따라 달라지므로 캐시하지 않는다
_POINT_ACTIVE = False


class TaintResult(StrEnum):
    TAINTED = "tainted"
    CLEAN = "clean"
    UNKNOWN = "unknown"  # 깊이·예산 한도로 끝까지 따라가지 못했다. 깨끗하다고 보지 않는다


def _call_parts(src: SourceFile, node: Node):
    """호출 노드의 (피호출자 문자열, 인자 노드 목록)을 반환한다. 호출이 아니면 None."""
    if src.lang is None or node.type not in CALL_TYPES.get(src.lang, set()):
        return None
    index = src.memo("call_by_id", lambda: {c.node.id: c for c in iter_calls(src)})
    call = index.get(node.id)
    return (call.callee, call.args) if call is not None else None


def _function_index(src: SourceFile) -> dict[str, list]:
    def build():
        index: dict[str, list] = {}
        for fn in iter_functions(src):
            index.setdefault(fn.name, []).append(fn)
        return index

    return src.memo("fn_index", build)


def param_name(src: SourceFile, param: Node) -> str:
    name = param.child_by_field_name("name") or param.child_by_field_name("pattern")
    if name is not None:
        return src.text_of(name).lstrip("$")
    for n in walk(param):
        if n.type in ("identifier", "variable_name") and n.child_count in (0, 2):
            return src.text_of(n).lstrip("$")
    return ""


def _positional_params(src: SourceFile, fn) -> list[Node]:
    return [p for p in fn.params if src.text_of(p) not in ("self", "cls")]


def resolve_helper(src: SourceFile, callee: str, argc: int):
    """같은 파일에 정의된 함수 중 호출과 이름·인자 수가 맞는 것"""
    last = callee.rsplit(".", 1)[-1]
    receiver = callee.rsplit(".", 1)[0] if "." in callee else ""
    if receiver and not (receiver in ("this", "self") or receiver.startswith("new") or receiver[:1].isupper()):
        return []
    return [fn for fn in _function_index(src).get(last, []) if len(_positional_params(src, fn)) == argc]


def _in_class(fn) -> bool:
    parent = fn.node.parent
    while parent is not None:
        if parent.type == "class_definition":
            return True
        parent = parent.parent
    return False


def _java_local_classes(src: SourceFile) -> set[str]:
    def find() -> set[str]:
        names = set()
        for node in src.nodes:
            if node.type in ("class_declaration", "interface_declaration", "enum_declaration", "record_declaration"):
                ident = node.child_by_field_name("name")
                if ident is not None:
                    names.add(src.text_of(ident))
        return names

    return src.memo("java_local_classes", find)


_PARAM_TYPES = {"parameters", "formal_parameters", "lambda_parameters"}
_LOCAL_BIND_TYPES = {"assignment", "variable_declarator", "for_statement", "for_in_statement"}


def _scoped_names(src: SourceFile) -> set[str]:
    """함수 안에서 묶이는 이름(매개변수, 지역 대입·선언). 이 이름이 import 이름과 같으면 가림이 생길 수 있다."""

    def find() -> set[str]:
        names: set[str] = set()
        functions = FUNCTION_TYPES.get(src.lang, set()) if src.lang else set()
        for node in src.nodes:
            if node.type in _PARAM_TYPES and node.parent is not None and node.parent.type in functions | {"lambda"}:
                for child in node.named_children:
                    name = param_name(src, child) if child.type not in ("identifier",) else src.text_of(child)
                    if name:
                        names.add(name)
            elif node.type in _LOCAL_BIND_TYPES and enclosing_function(node, src.lang) is not None:
                target = node.child_by_field_name("left") or node.child_by_field_name("name")
                if target is not None:
                    names |= identifiers_in(src, target)
        return names

    return src.memo("scoped_names", find)


def _module_rebinds(src: SourceFile, name: str) -> bool:
    """모듈 최상위에서 name에 값을 대입하면 그 이름이 가리키는 함수를 정할 수 없다."""
    if src.root is None:
        return False
    for stmt in src.root.named_children:
        node = stmt.named_children[0] if stmt.type == "expression_statement" and stmt.named_children else stmt
        if node.type in ("assignment", "augmented_assignment"):
            left = node.child_by_field_name("left")
            targets = [left] if left is not None and left.type == "identifier" else (left.named_children if left is not None and left.type in ("pattern_list", "tuple_pattern", "list_pattern") else [])
            if any(t.type == "identifier" and src.text_of(t) == name for t in targets):
                return True
    return False


def resolve_any(src: SourceFile, callee: str, argc: int) -> list[tuple[SourceFile, object]]:
    """호출 대상 함수 후보. Python은 이름의 바인딩을 먼저 본다: import로 묶인 이름이면 import 대상,
    같은 파일 정의면 그 함수, 둘 다 있으면 양쪽을 모두 후보로 둔다(어느 쪽이든 오염을 돌려주면 오염).
    모듈 최상위에서 이름을 다시 대입하면 대상을 정할 수 없어 후보를 내지 않는다. 다른 언어는 같은 파일 함수가 우선이다."""
    local = [(src, fn) for fn in resolve_helper(src, callee, argc)]
    if src.lang is Lang.JAVA and "." in callee:
        receiver = callee.rsplit(".", 1)[0]
        if receiver[:1].isupper() and receiver not in _java_local_classes(src):
            return xfile.resolve_external(src, callee, argc)  # 다른 클래스의 static 호출은 같은 이름의 이 파일 메서드가 아니다
    head = callee.split(".", 1)[0]
    if src.lang in JS_FAMILY:
        if head in _scoped_names(src) and head in xfile_js.imports(src):
            return []  # 매개변수·지역 변수가 import 이름을 가리면 어느 쪽이 호출되는지 정할 수 없다
        return local or xfile.resolve_external(src, callee, argc)
    if src.lang is not Lang.PYTHON:
        return local or xfile.resolve_external(src, callee, argc)
    if head in _scoped_names(src) and head in xfile.imported_names(src):
        return []
    if "." not in callee:
        if _module_rebinds(src, callee):
            return []
        local = [(s, fn) for s, fn in local if not _in_class(fn)]  # 메서드는 맨 이름 호출로 불리지 않는다
    if local and head not in xfile.imported_names(src):
        return local
    external = xfile.resolve_external(src, callee, argc)
    return local + [t for t in external if t not in local]


# ---------------------------------------------------------------------------
# 실행 순서를 따르는 흐름 해석기
# ---------------------------------------------------------------------------

RETURN_TYPES = {"return_statement", "return_expression"}
DEAD_END_TYPES = {"raise_statement", "throw_statement", "throw_expression"}
IF_TYPES = {"if_statement", "if_expression", "elif_clause", "else_if_clause"}
CHAIN_TYPES = {"elif_clause", "else_if_clause"}
ELSE_TYPES = {"else_clause", "else"}
SWITCH_TYPES = {
    "switch_statement",
    "switch_expression",
    "expression_switch_statement",
    "type_switch_statement",
    "match_expression",
    "match_statement",
    "select_statement",
}
CASE_TYPES = {
    "switch_case",
    "switch_default",
    "switch_block_statement_group",
    "switch_section",
    "case_clause",
    "expression_case",
    "default_case",
    "type_case",
    "communication_case",
    "match_arm",
    "switch_rule",
}
LOOP_TYPES = {
    "for_statement",
    "for_in_statement",
    "for_of_statement",
    "foreach_statement",
    "enhanced_for_statement",
    "while_statement",
    "do_statement",
    "loop_expression",
    "for_expression",
    "while_expression",
}
TRY_TYPES = {"try_statement", "try_expression"}
MARK_SUFFIXES = ("statement", "declaration", "_clause", "_arm", "_case", "_rule", "_section", "block")
SCOPE_ROOT_TYPES = {"module", "program", "source_file", "translation_unit", "compilation_unit"}
STATEMENT_PARENTS = SCOPE_ROOT_TYPES | {"statements", "block", "lambda_literal"}  # 블록·람다 바로 아래의 문장(Kotlin은 문장 노드 이름이 따로 없다)

State = frozenset[str] | None  # None은 이 경로가 끝났음(return·throw)을 뜻한다


def _join(*states: State) -> State:
    live = [s for s in states if s is not None]
    if not live:
        return None
    merged: set[str] = set()
    for s in live:
        merged |= s
    return frozenset(merged)


@dataclass
class Analysis:
    before: dict[int, frozenset[str]]
    returns: list[tuple[Node, frozenset[str]]]


class _Flow:
    def __init__(self, src: SourceFile, scope: Node, cli: bool, seeds: frozenset[str], ctx: Ctx):
        self.src = src
        self.scope = scope
        self.cli = cli
        self.seeds = seeds
        self.ctx = ctx
        self.before: dict[int, frozenset[str]] = {}
        self.returns: list[tuple[Node, frozenset[str]]] = []
        self.fn_types = FUNCTION_TYPES.get(src.lang, set()) if src.lang else set()
        self.call_types = CALL_TYPES.get(src.lang, set()) if src.lang else set()

    # -- 진입점 --
    def run(self) -> Analysis:
        initial = frozenset(self.seeds) | self._annotated()
        self.before[self.scope.id] = initial
        is_function = self.scope.type in self.fn_types
        if is_function:
            body = function_parts(self.src, self.scope)[1]
            if body is None:
                return Analysis(self.before, self.returns)
            if body.type not in ("block", "statement_block", "compound_statement"):
                self.returns.append((body, initial))  # 식 본문 함수(화살표 함수 등)
                self.exec(body, initial)
            else:
                out = self._seq(body.named_children, initial)
                self._tail_expression(body, out)
        else:
            self._seq(self.scope.named_children, initial)
        return Analysis(self.before, self.returns)

    def _tail_expression(self, body: Node, out: State) -> None:
        """Rust처럼 마지막 식이 반환값인 언어"""
        if self.src.lang is None or self.src.lang.value != "rust" or not body.named_children:
            return
        last = body.named_children[-1]
        if last.type not in ("expression_statement", "let_declaration") and "comment" not in last.type:
            state = self.before.get(last.id)
            if state is not None:
                self.returns.append((last, state))

    def _annotated(self) -> frozenset[str]:
        if self.scope.type not in self.fn_types:
            return frozenset()
        params = function_parts(self.src, self.scope)[0]
        if params is None:
            declarator = self.scope.child_by_field_name("declarator")
            params = declarator.child_by_field_name("parameters") if declarator is not None else None
        if params is None:
            return frozenset()
        names: set[str] = set()
        children = params.named_children
        for i, n in enumerate(children):
            if not ANNOTATED_PARAM_RE.search(self.src.text_of(n)):
                continue
            if n.type == "parameter_modifiers" and i + 1 < len(children):  # Kotlin: 애너테이션이 매개변수 앞 형제 노드에 있다
                name = next((c for c in children[i + 1].named_children if c.type == "identifier"), None)
                if name is not None:
                    names.add(self.src.text_of(name))
            else:
                names |= identifiers_in(self.src, n)
        return frozenset(names)

    # -- 기록 --
    def _mark(self, node: Node, state: frozenset[str]) -> None:
        if node.id in self.before:
            self.before[node.id] = self.before[node.id] | state
        elif node.type.endswith(MARK_SUFFIXES) or (node.parent is not None and node.parent.type in STATEMENT_PARENTS):
            self.before[node.id] = state

    # -- 실행 --
    def _seq(self, nodes, state: State) -> State:
        for child in nodes:
            if state is None:
                return None
            if "comment" in child.type:
                continue
            state = self.exec(child, state)
        return state

    def exec(self, node: Node, state: State) -> State:
        if state is None:
            return None
        t = node.type
        if "comment" in t:
            return state
        if t in self.fn_types:
            return state  # 중첩 함수는 자기 범위에서 따로 분석한다
        self._mark(node, state)
        if t in RETURN_TYPES:
            return self._return(node, state)
        if t in DEAD_END_TYPES:
            return None
        if t in IF_TYPES:
            return self._if(node, state)
        if t in SWITCH_TYPES:
            return self._switch(node, state)
        if t in TRY_TYPES:
            return self._try(node, state)
        if t in LOOP_TYPES:
            return self._loop(node, state)
        return self._generic(node, state)

    def _generic(self, node: Node, state: State) -> State:
        for child in node.children:
            if state is None:
                return None
            if child.is_named:
                state = self.exec(child, state)
        return self._apply(node, state)

    def _return(self, node: Node, state: frozenset[str]) -> State:
        values = [c for c in node.named_children if "comment" not in c.type]
        for v in values:
            state = self.exec(v, state) or state
        if values:
            self.returns.append((values[0], state))
        return None

    def _if(self, node: Node, state: frozenset[str]) -> State:
        branch_fields = ("consequence", "alternative", "body")
        branches = [c for f in branch_fields for c in node.children_by_field_name(f)]
        branch_ids = {b.id for b in branches}
        header_state: State = state
        for child in node.named_children:
            if child.id in branch_ids or "comment" in child.type:
                continue
            header_state = self.exec(child, header_state) if header_state is not None else None
        if header_state is None:
            return None
        if not branches:
            return header_state
        outs = [self.exec(b, header_state) for b in branches]
        merged = _join(*outs)
        if node.type in CHAIN_TYPES:
            return merged
        if not self._has_final_else(node):
            merged = _join(merged, header_state)
        return merged

    def _has_final_else(self, node: Node) -> bool:
        alts = node.children_by_field_name("alternative")
        if not alts:
            return False
        last = alts[-1]
        if last.type in CHAIN_TYPES:
            return False
        if last.type in IF_TYPES:
            return self._has_final_else(last)
        if last.type in ELSE_TYPES:
            inner = [c for c in last.named_children if "comment" not in c.type]
            if len(inner) == 1 and inner[0].type in IF_TYPES:
                return self._has_final_else(inner[0])
            return True
        return True

    def _switch(self, node: Node, state: frozenset[str]) -> State:
        cases: list[Node] = []
        stack = list(reversed(node.children))
        while stack:
            n = stack.pop()
            if n.type in CASE_TYPES:
                cases.append(n)
                continue
            if n.type in SWITCH_TYPES or n.type in self.fn_types:
                continue
            stack.extend(reversed(n.children))
        case_ids = {c.id for c in cases}
        header: State = state
        for child in node.named_children:
            if child.type in ("switch_body", "switch_block", "match_block", "block", "body") or child.id in case_ids:
                continue
            header = self.exec(child, header) if header is not None else None
        if header is None:
            return None
        if not cases:
            return self._generic_children(node, header)
        outs = [self._seq(c.named_children, header) for c in cases]
        has_default = any("default" in c.type or self.src.text_of(c).lstrip().startswith("default") or self.src.text_of(c).lstrip().startswith("_ ") for c in cases)
        return _join(*outs) if has_default else _join(*outs, header)

    def _generic_children(self, node: Node, state: frozenset[str]) -> State:
        return self._seq(node.named_children, state)

    def _try(self, node: Node, state: frozenset[str]) -> State:
        body = node.child_by_field_name("body")
        handlers: list[Node] = []
        else_clause = None
        finally_clause = None
        header: State = state
        for child in node.named_children:
            if child.id == (body.id if body is not None else -1) or "comment" in child.type:
                continue
            if "catch" in child.type or "except" in child.type:
                handlers.append(child)
            elif "finally" in child.type:
                finally_clause = child
            elif child.type in ELSE_TYPES:
                else_clause = child
            else:
                header = self.exec(child, header) if header is not None else None
        if header is None:
            return None
        try_out = self.exec(body, header) if body is not None else header
        entry = _join(header, try_out) or header
        outs: list[State] = [self.exec(else_clause, try_out) if else_clause is not None and try_out is not None else try_out]
        outs.extend(self.exec(h, entry) for h in handlers)
        merged = _join(*outs)
        if finally_clause is not None:
            return self.exec(finally_clause, _join(merged, entry) or entry)
        return merged

    def _loop(self, node: Node, state: frozenset[str]) -> State:
        body = node.child_by_field_name("body")
        alternative = node.child_by_field_name("alternative")  # Python for-else
        header: State = state
        if node.type in LOOP_ASSIGN_TYPES:
            header = self._assign(node, header, kill=False)
        for child in node.named_children:
            if (body is not None and child.id == body.id) or (alternative is not None and child.id == alternative.id):
                continue
            if "comment" in child.type or header is None:
                continue
            header = self.exec(child, header)
        if header is None:
            return None
        if body is None:
            return header
        first = self.exec(body, header)
        second = self.exec(body, _join(header, first) or header)
        merged = _join(header, first, second) or header
        if alternative is not None:
            merged = _join(merged, self.exec(alternative, merged))
        return merged

    # -- 문장 효과 --
    def _apply(self, node: Node, state: State) -> State:
        if state is None:
            return None
        if node.type in ASSIGN_TYPES and node.type not in LOOP_ASSIGN_TYPES:
            return self._assign(node, state, kill=node.type not in AUGMENTED_TYPES)
        if node.type in self.call_types:
            parts = _call_parts(self.src, node)
            if parts and "." in parts[0] and parts[0].rsplit(".", 1)[-1] in MUTATING_METHODS:
                receiver = parts[0].rsplit(".", 1)[0]
                m = re.match(r"[A-Za-z_$][\w$]*", receiver)
                method = parts[0].rsplit(".", 1)[-1]
                key = _constant_key(self.src, parts[1][0]) if method in COLLECTION_PUT and len(parts[1]) >= 2 and re.fullmatch(r"[A-Za-z_$][\w$]*", receiver) else None
                if key is not None:
                    path = f"{receiver.lstrip('$')}[{key}]"
                    if any(expr_tainted(self.src, a, set(state), self.cli, self.ctx) for a in parts[1][1:]):
                        return state | {path}
                    return state - {path}  # 상수 키에 깨끗한 값을 넣으면 그 키는 깨끗하다
                if m and any(expr_tainted(self.src, a, set(state), self.cli, self.ctx) for a in parts[1]):
                    return state | {m.group(0).lstrip("$")}
        return state

    def _assign(self, node: Node, state: State, kill: bool) -> State:
        if state is None:
            return None
        left, right = _target_and_value(node)
        if left is None or right is None:
            return state
        names, strong = _target_paths(self.src, left)
        if not names:
            return state
        if node.type in LOOP_ASSIGN_TYPES and self.src.lang is Lang.PYTHON:
            callee = (_call_parts(self.src, right) or ("", []))[0]
            if callee == "range":
                return state  # range()가 만드는 반복 변수는 정수라 문자열 주입 경로가 아니다
            if callee == "enumerate":
                first = re.match(r"\s*\(?\s*([A-Za-z_]\w*)", self.src.text_of(left))
                if first:
                    names = names - {first.group(1)}  # enumerate의 첫 값(순번)은 정수다
        if expr_tainted(self.src, right, set(state), self.cli, self.ctx):
            return state | names
        if kill and strong:
            # 변수 전체를 새 값으로 바꾸면 그 변수의 필드 경로도 함께 지운다
            whole = {n for n in names if n == path_root(n)}
            return frozenset(n for n in state if n not in names and path_root(n) not in whole)
        return state


def _analysis(src: SourceFile, scope: Node, cli: bool, seeds: frozenset[str], ctx: Ctx, own=None) -> Analysis:
    """흐름 해석 결과. 남은 깊이에 따라 결과가 달라지므로 깊이를 키에 넣는다.
    캐시에는 해석에 든 비용과 한도 도달 횟수를 함께 두고, 다시 쓸 때 같은 비용을 치른다. 그래서 같은 관심 지점은
    앞서 무엇을 분석했는지와 무관하게 같은 결과를 낸다. 예산이 바닥났거나 바깥 함수의 재귀를 끊은 결과는 캐시하지 않는다."""
    cache = src.__dict__.setdefault("_taint_cache", {})
    key = (scope.id, cli, seeds, ctx, _DEPTH, _EXTRA_KIND, CUSTOM_KIND)
    index = xfile.get_index()
    if key in cache:
        analysis, cost, limits = cache[key]
        if index is not None:
            for limit in limits:
                index.note(limit)
            if index.metering and cost:
                index.spend(cost)
        return analysis
    mark = len(_CUTS)
    charged = index.charged if index is not None else 0
    limits: set = set()
    if index is not None:
        index._collectors.append(limits)
    try:
        analysis = _Flow(src, scope, cli, seeds, ctx).run()
    finally:
        if index is not None:
            index._collectors.pop()
    if index is not None and index.exhausted:
        return analysis
    if set(_CUTS[mark:]) - {own}:
        return analysis
    if index is None:
        cache[key] = (analysis, 0, frozenset())
    else:
        cache[key] = (analysis, index.charged - charged, frozenset(limits))
    return analysis


def taint_state(
    src: SourceFile,
    node: Node,
    cli: bool = False,
    seeds: frozenset[str] = frozenset(),
    ctx: Ctx = Ctx.ANY,
) -> frozenset[str]:
    """node가 실행되기 직전에 오염되어 있는 변수 이름의 집합"""
    scope = enclosing_function(node, src.lang) or src.root
    if scope is None:
        return frozenset()
    analysis = _analysis(src, scope, cli, seeds, ctx)
    current: Node | None = node
    while current is not None:
        found = analysis.before.get(current.id)
        if found is not None:
            return found
        current = current.parent
    return frozenset()


def _returns_tainted(src: SourceFile, fn_node: Node, seeds: frozenset[str], cli: bool, ctx: Ctx = Ctx.ANY) -> TaintResult:
    global _DEPTH
    key = (src.path.as_posix(), fn_node.id, seeds, ctx)
    if key in _IN_PROGRESS:
        # 오염된 인자가 재귀로 넘어가면 보수적으로 오염으로 본다. 오염된 인자 없이 도는 재귀(디렉터리 순회 등)는 '오염 없음'에서 시작해
        # 다른 반환 경로의 오염을 따른다(최소 고정점). 끊긴 결과는 호출 경로에 따라 달라 캐시하지 않는다
        _CUTS.append(key)
        return TaintResult.TAINTED if seeds else TaintResult.CLEAN
    if _DEPTH >= MAX_HELPER_DEPTH:
        xfile.note_limit(src.path.as_posix(), fn_node.start_byte, "depth")
        return TaintResult.UNKNOWN
    index = xfile.get_index()
    _IN_PROGRESS.add(key)
    _DEPTH += 1
    try:
        analysis = _analysis(src, fn_node, cli, seeds, ctx, own=key)
        tainted = any(expr_tainted(src, expr, set(state), cli, ctx) for expr, state in analysis.returns)
        if index is not None and index.exhausted:
            return TaintResult.UNKNOWN
        return TaintResult.TAINTED if tainted else TaintResult.CLEAN
    finally:
        _DEPTH -= 1
        _IN_PROGRESS.discard(key)


# ---------------------------------------------------------------------------
# 식의 오염 판정
# ---------------------------------------------------------------------------


def _call_is_clean(src: SourceFile, parts, names: set[str], cli: bool, ctx: Ctx, by_name: bool = True) -> bool | None:
    """호출 결과가 외부 입력을 담지 않는지 판정한다. 프로젝트에 정의된 함수는 이름이 아니라 본문 동작을 따른다.
    True=깨끗함, False=오염된 값을 돌려줌, None=판단 근거 없음
    가장 바깥 호출 하나가 관심 지점이며, 그 안의 함수 간·파일 간 해석은 지점마다 같은 예산을 쓴다."""
    global _POINT_ACTIVE
    index = xfile.get_index()
    if _POINT_ACTIVE:
        return _call_is_clean_in_point(src, parts, names, cli, ctx, by_name)
    _POINT_ACTIVE = True
    start = index.limit_hits if index is not None else 0
    point = (src.path.as_posix(), parts[1][0].start_byte if parts[1] else 0, "budget:" + parts[0])
    if index is not None:
        index.begin_point()
    try:
        return _call_is_clean_in_point(src, parts, names, cli, ctx, by_name)
    finally:
        _POINT_ACTIVE = False
        _CUTS.clear()
        if index is not None:
            exhausted = index.exhausted
            index.end_point()
            if exhausted:
                index.limit_hits = start  # 예산 소진은 지점마다 한 번만 센다. 소진 전 기록은 분석 순서에 따라 달라진다
                index.note(point)


def _call_is_clean_in_point(src: SourceFile, parts, names: set[str], cli: bool, ctx: Ctx, by_name: bool) -> bool | None:
    callee, args = parts
    helpers = resolve_any(src, callee, len(args))
    index = xfile.get_index()
    if index is not None and index.exhausted:
        return None
    if helpers:
        result = _helper_returns_tainted(src, helpers, args, names, cli, ctx)
        if result is TaintResult.UNKNOWN:
            return None  # 끝까지 따라가지 못한 함수는 깨끗하다고 보지 않고, 인자의 오염이 결과로 전해진다고 본다
        return result is TaintResult.CLEAN
    if archive_file(src) and (
        ARCHIVE_SOURCE_RE.search(callee + "(")
        or (re.search(r"\.(getName|getFileName)$", callee) and callee.rsplit(".", 1)[0] in names)
    ):
        return False  # 압축 항목 이름(`entry.getName()`)은 이름이 정제 함수처럼 보여도 `../`가 든 외부 입력이다
    if by_name and sanitizer_name_matches(callee, ctx, src.lang):
        return True
    if not by_name and _UNIVERSAL_RE.search(callee):
        return True  # 중첩된 호출이라도 len()·int() 같은 값의 종류를 바꾸는 호출은 문자열 주입 경로가 아니다
    return None


def _helper_returns_tainted(src: SourceFile, helpers, args: list[Node], names: set[str], cli: bool, ctx: Ctx) -> TaintResult:
    outcome = TaintResult.CLEAN
    for hsrc, fn in helpers:
        params = _positional_params(hsrc, fn)
        # 인자 자리의 식도 같은 기준으로 판정한다: 인자가 오염된 값을 돌려주는 다른 함수 호출이어도 매개변수가 오염된다
        seeds = frozenset(param_name(hsrc, p) for p, a in zip(params, args, strict=False) if expr_tainted(src, a, names, cli, ctx))
        result = _returns_tainted(hsrc, fn.node, seeds, cli, ctx)
        if result is TaintResult.TAINTED:
            return result
        if result is TaintResult.UNKNOWN:
            outcome = result
    return outcome


def _clean_ranges(src: SourceFile, node: Node, names: set[str], cli: bool, ctx: Ctx) -> list[tuple[int, int]] | None:
    """식 안에 중첩된, 결과가 깨끗한 호출(프로젝트에 정의된 함수)의 바이트 범위.
    중첩된 프로젝트 함수 호출이 오염된 값을 돌려주면(함수 안에서 외부 입력을 읽는 경우 포함) None"""
    ranges: list[tuple[int, int]] = []
    stack = list(node.children)
    while stack:
        n = stack.pop()
        parts = _call_parts(src, n)
        # 도달하는 문맥이 정해져 있으면(셸·경로·SQL 등) 그 문맥에 유효한 정제 함수 호출은 중첩되어 있어도 그 호출 범위만 깨끗하다. 문맥을 모르면(ANY) 이름만으로 인정하지 않는다
        clean = _call_is_clean(src, parts, names, cli, ctx, by_name=ctx is not Ctx.ANY) if parts is not None else None
        if clean:
            ranges.append((n.start_byte, n.end_byte))
            continue
        if clean is False:
            return None
        stack.extend(n.children)
    return ranges


def expr_tainted(src: SourceFile, node: Node, names: set[str], cli: bool = False, ctx: Ctx = Ctx.ANY) -> bool:
    """이미 계산된 오염 변수 집합을 기준으로 식의 오염 여부를 판정한다."""
    parts = _call_parts(src, node)
    if parts is not None:
        clean = _call_is_clean(src, parts, names, cli, ctx)
        if clean is not None:
            return not clean
    ranges = _clean_ranges(src, node, names, cli, ctx)
    if ranges is None:
        return True
    if ranges:
        buf = bytearray(src.data[node.start_byte : node.end_byte])
        for a, b in ranges:
            for i in range(max(a, node.start_byte) - node.start_byte, min(b, node.end_byte) - node.start_byte):
                buf[i] = 32
        remaining = buf.decode("utf-8", errors="replace")
        if _source_in(remaining, cli, src.lang, archive_file(src)):
            return True
        return reads_tainted(src, node, names, skip=lambda n: any(a <= n.start_byte and n.end_byte <= b for a, b in ranges))
    if expr_has_source(src, node, cli):
        return True
    return reads_tainted(src, node, names)


def is_tainted(
    src: SourceFile,
    node: Node,
    cli: bool = False,
    seeds: frozenset[str] = frozenset(),
    ctx: Ctx = Ctx.ANY,
) -> bool:
    """식이 외부 입력에서 유래했는지(직접 사용 또는 함수 내 전파) 판정한다. cli=True면 명령행·표준입력도 포함한다.
    seeds는 오염된 것으로 가정할 변수 이름(함수 매개변수 효과 요약에 쓴다). ctx는 도달하는 곳의 종류."""
    if src.root is None:
        return expr_has_source(src, node, cli)
    state = taint_state(src, node, cli, seeds, ctx)
    return expr_tainted(src, node, set(state), cli, ctx)


# ---------------------------------------------------------------------------
# 정의 추적 (문자열 조합 여부 판정용)
# ---------------------------------------------------------------------------


def _unconditional(node: Node, scope: Node) -> bool:
    current = node.parent
    while current is not None and current.id != scope.id:
        if current.type in CONDITIONAL_TYPES:
            return False
        current = current.parent
    return True


def reaching_definitions(src: SourceFile, scope: Node, name: str, before: int) -> list[Node]:
    """before 위치의 name에 도달하는 대입 우변들. 무조건 실행되는 마지막 대입 뒤에는 그 이전 대입이 도달하지 못한다."""
    defs = definitions(src, scope, name)
    prior = sorted((d for d in defs if d.end_byte <= before), key=lambda d: d.start_byte)
    if not prior:
        return defs
    last_sure = -1
    for i, d in enumerate(prior):
        holder = d.parent
        if _unconditional(d, scope) and not (holder is not None and holder.type in AUGMENTED_TYPES):
            last_sure = i
    return prior[last_sure:] if last_sure >= 0 else prior


def definitions(src: SourceFile, scope: Node, name: str) -> list[Node]:
    """범위 안에서 name에 대입되는 우변 식들을 반환한다."""
    cache = src.__dict__.setdefault("_defs_cache", {})
    key = scope.id
    if key not in cache:
        table: dict[str, list[Node]] = {}
        for n in walk(scope):
            if n.type in ASSIGN_TYPES:
                left, right = _target_and_value(n)
                if left is None or right is None:
                    continue
                for ident in _target_names(src, left):
                    table.setdefault(ident, []).append(right)
        cache[key] = table
    return cache[key].get(name, [])
