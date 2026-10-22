import re
from enum import StrEnum

from iron_laws.engine.languages import Lang

_HIT_CACHE_MAX = 50_000


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


_UNIVERSAL = "parseint|parsefloat|int|float|bool|number|len|length|abs|round|hashpw|hexdigest|digest|uuid\\w*|isdigit|isnumeric"


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


_HTML_ONLY_RE = re.compile(
    r"(?i)(?:^|\.)(?:html|cgi|markupsafe|saxutils|bleach|dompurify|xml)\.|escape_?html|htmlspecialchars|htmlentities|encode_?for_?html|esc_html|for_?html"
)


CUSTOM_SOURCES: dict[Lang, re.Pattern[str]] = {}


CUSTOM_SANITIZERS: dict[tuple[Lang, Ctx], re.Pattern[str]] = {}


CUSTOM_KIND = ""


_SANITIZER_HITS: dict[tuple[str, "Ctx"], bool] = {}


def set_custom_spec(sources: dict, sanitizers: dict, kind: str) -> None:
    global CUSTOM_KIND
    # 다른 모듈이 이 객체를 참조하고 있으므로 갈아끼우지 않고 내용만 바꾼다
    CUSTOM_SOURCES.clear()
    CUSTOM_SOURCES.update(sources)
    CUSTOM_SANITIZERS.clear()
    CUSTOM_SANITIZERS.update(sanitizers)
    CUSTOM_KIND = kind


def custom_sanitizer_match(callee: str, ctx: Ctx, lang: Lang | None = None) -> bool:
    """사용자가 명세로 선언한 정제 함수인지 확인한다. 도구가 이미 아는 정제 함수와 구분한다.
    선언한 정제 함수는 근거가 아니라 사람이 한 약속이다."""
    if lang is None:
        return False
    custom = CUSTOM_SANITIZERS.get((lang, ctx))
    return custom is not None and bool(custom.search(callee))


def _builtin_sanitizer_hit(callee: str, ctx: "Ctx") -> bool:
    key = (callee, ctx)
    found = _SANITIZER_HITS.get(key)
    if found is None:
        if ctx is Ctx.ANY:
            found = bool(SANITIZER_FN_RE.search(callee))
        elif ctx is not Ctx.HTML and _HTML_ONLY_RE.search(callee):
            found = bool(_BASE_SANITIZERS.search(callee))
        else:
            found = bool(_CONTEXT_SANITIZERS[ctx].search(callee))
        if len(_SANITIZER_HITS) >= _HIT_CACHE_MAX:
            _SANITIZER_HITS.clear()
        _SANITIZER_HITS[key] = found
    return found


def sanitizer_name_matches(callee: str, ctx: Ctx, lang: Lang | None = None) -> bool:
    custom = CUSTOM_SANITIZERS.get((lang, ctx)) if lang is not None else None
    if custom is not None and custom.search(callee):
        return True
    return _builtin_sanitizer_hit(callee, ctx)
