import re
from contextlib import contextmanager

from tree_sitter import Node

import iron_laws.engine.taint.sanitizers as sanitizers
from iron_laws.engine.ast_tools import STRING_TYPES, has_interpolation, walk
from iron_laws.engine.languages import Lang
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


_HIT_CACHE_MAX = 50_000


_HIT_CACHE_MAX_TEXT = 200


_WEB_SOURCE_HITS: dict[str, bool] = {}


_ARCHIVE_SOURCE_HITS: dict[str, bool] = {}


_CLI_SOURCE_HITS: dict[str, bool] = {}


def _hit(cache: dict, key, text: str, pattern: re.Pattern[str]) -> bool:
    """정규식 검색 결과를 기억한다. 긴 문자열은 매번 다르므로 기억하지 않는다."""
    found = cache.get(key)
    if found is None:
        found = pattern.search(text) is not None
        if len(text) <= _HIT_CACHE_MAX_TEXT:
            if len(cache) >= _HIT_CACHE_MAX:
                cache.clear()
            cache[key] = found
    return found


def _source_in(text: str, cli: bool, lang: Lang | None = None, archive: bool = False) -> bool:
    if _hit(_WEB_SOURCE_HITS, text, text, WEB_SOURCE_RE):
        return True
    if archive and _hit(_ARCHIVE_SOURCE_HITS, text, text, ARCHIVE_SOURCE_RE):
        return True
    if cli and _hit(_CLI_SOURCE_HITS, text, text, CLI_SOURCE_RE):
        return True
    if _EXTRA_SOURCE is not None and _EXTRA_SOURCE.search(text):
        return True
    custom = sanitizers.CUSTOM_SOURCES.get(lang) if lang is not None else None
    if custom is not None and custom.search(text):
        return True
    return False


def expr_has_source(src: SourceFile, node: Node, cli: bool = False) -> bool:
    text = src.text_of(node)
    if not _source_in(text, cli, src.lang, archive_file(src)):
        return False
    if src.root is None:
        return True
    # 원문에서 입력 원천처럼 보이는 글자가 보이면, 그것이 문자열 리터럴 안의 글자인지 코드인지 가려서 다시 본다
    return _source_in(_text_without_plain_strings(src, node), cli, src.lang, archive_file(src))
