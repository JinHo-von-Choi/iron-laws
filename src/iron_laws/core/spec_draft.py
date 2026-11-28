"""
오철칙 사용자 명세 초안: 코드에서 소스·싱크·정제 함수 후보를 찾는다. 초안은 사람이 검토하고 예제를 채우기 전에는 불러오지 않는다.

- 싱크 후보: 매개변수를 기존 싱크(명령·SQL·경로·코드 실행)에 그대로 넘기는 프로젝트 함수(감싼 함수)
- 정제 후보: 이름이 clean·sanitize·escape·validate·safe·quote·normalize로 시작하거나 끝나는 프로젝트 함수(문맥은 사람이 정한다)
- 소스 후보: AWS Lambda 처리기의 event, 메시지 소비자의 body·payload처럼 웹 요청이 아닌 입력 경로
- 외부 호출 후보(candidates): 프로젝트가 import한 외부 패키지의 호출 가운데 외부 입력이 인자로 들어가는 호출,
  반환값이 싱크로 가는 호출, 문자열을 받아 실행·해석하는 호출. 계열(CWE)별로 모아 `--llm-cmd`에 계열마다 따로 묻는다
- 설정 후보(config_hints): 로그인 인터셉터가 검사를 건너뛰는 애너테이션(auth.exempt_markers 후보)과,
  로그인 사용자의 소속을 읽는 식(tenancy.principal 후보). 명세로 불러오지 않으며 사람이 확인해 설정 파일에 옮긴다
작성자: 최진호
작성일: 2026-10-12
"""

import json
import re
from collections.abc import Sequence

import yaml

from iron_laws.engine.ast_tools import iter_calls, iter_functions
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.source import SourceFile

LANG_NAME = {Lang.PYTHON: "python", Lang.JAVASCRIPT: "javascript", Lang.TYPESCRIPT: "typescript", Lang.TSX: "typescript", Lang.JAVA: "java", Lang.CSHARP: "csharp", Lang.GO: "go", Lang.PHP: "php"}
SANITIZER_NAME = re.compile(r"(?i)^(clean|sanitiz|escape|validate|safe|quote|normaliz)|(clean|sanitize[sd]?|escape[sd]?|validate[sd]?|safe|quoted?|normalized?)$")
FAMILY_RULES = (("command", "CommandInjectionRule"), ("sql", "SqlInjectionRule"), ("path", "PathTraversalRule"), ("code", "CodeInjectionRule"))


def _rules():
    from iron_laws.rules import injection_execution, injection_paths

    return [(family, getattr(injection_execution, name, None) or getattr(injection_paths, name)) for family, name in FAMILY_RULES]


FAMILY_NAME_HINTS = (
    ("command", re.compile(r"(?i)(^|\.)(exec\w*|spawn\w*|run|popen|shell\w*|system|call)$")),
    ("sql", re.compile(r"(?i)(^|\.)(\w*query\w*|\w*sql\w*|execute\w*|raw)$")),
    ("path", re.compile(r"(?i)(^|\.)(\w*open\w*|\w*file\w*|\w*path\w*|read\w*|write\w*|load\w*|save\w*|extract\w*|unzip\w*)$")),
    ("code", re.compile(r"(?i)(^|\.)(eval\w*|compile\w*|render\w*|template\w*|\w*expression\w*|script\w*|interpret\w*)$")),
    ("xpath", re.compile(r"(?i)(^|\.)(\w*xpath\w*|select\w*)$")),
    ("ldap", re.compile(r"(?i)(^|\.)(\w*ldap\w*|search\w*)$")),
)
CANDIDATE_LIMIT = 30


def _family_of_name(callee: str) -> str | None:
    return next((family for family, pattern in FAMILY_NAME_HINTS if pattern.search(callee)), None)


def _imported_head(src: SourceFile, callee: str) -> bool:
    """호출 이름의 첫 조각이 import로 묶인 외부 이름인지(프로젝트 함수로 풀리지 않는 호출만 후보로 남긴다)"""
    head = callee.split(".", 1)[0]
    if src.lang is Lang.PYTHON:
        from iron_laws.engine.xfile_python import imports

        return head in imports(src)
    if src.lang in JS_FAMILY:
        from iron_laws.engine.xfile_js import imports

        return head in imports(src)
    if src.lang in (Lang.JAVA, Lang.KOTLIN):
        from iron_laws.engine.xfile_java import imports

        named, _wildcard = imports(src)
        return head in named or (head[:1].isupper() and "." in callee)
    return False


def external_candidates(sources: list[SourceFile], rules: list | None = None) -> dict[str, list[dict]]:
    """외부 패키지 호출 가운데 오염 흐름에 걸리는 것: 외부 입력이 인자로 들어가는 호출(receives_input),
    반환값이 기존 싱크의 인자로 가는 호출(feeds_sink), 문자열을 받아 실행·해석하는 이름의 호출(interprets_string)"""
    from iron_laws.engine.ast_tools import is_literal
    from iron_laws.engine.taint import WEB_SOURCE_RE, is_tainted, resolve_any

    rules = rules if rules is not None else [(family, cls()) for family, cls in _rules()]
    found: dict[str, list[dict]] = {}
    seen: set[tuple[str, str]] = set()
    for src in sources:
        lang = LANG_NAME.get(src.lang) if src.lang else None
        if lang is None or src.is_test:
            continue
        calls = list(iter_calls(src))
        sink_args: dict[int, str] = {}
        for call in calls:
            for family, rule in rules:
                if any(src.lang in s.langs and s.callee.search(call.callee) for s in rule.sinks):
                    for arg in call.args:
                        sink_args[arg.id] = family
        has_input = WEB_SOURCE_RE.search(src.code_text) is not None
        for call in calls:
            if not call.args or not _imported_head(src, call.callee) or resolve_any(src, call.callee, len(call.args), at=call.node):
                continue
            if any(src.lang in s.langs and s.callee.search(call.callee) for _f, r in rules for s in r.sinks):
                continue  # 이미 아는 싱크다
            reason, family = None, None
            parent = call.node
            while parent is not None and parent.id not in sink_args and (parent.id == call.node.id or parent.type in ("argument_list", "arguments", "parenthesized_expression", "binary_expression", "binary_operator")):
                parent = parent.parent
            if parent is not None and parent.id in sink_args:
                reason, family = "feeds_sink", sink_args[parent.id]
            elif has_input and any(not is_literal(a) and is_tainted(src, a) for a in call.args):
                reason, family = "receives_input", _family_of_name(call.callee)
            elif any(not is_literal(a) for a in call.args) and _family_of_name(call.callee) == "code":
                reason, family = "interprets_string", "code"
            if reason is None or family is None or (lang, call.callee) in seen:
                continue
            seen.add((lang, call.callee))
            bucket = found.setdefault(family, [])
            if len(bucket) < CANDIDATE_LIMIT:
                bucket.append({"callee": call.callee, "language": lang, "reason": reason, "evidence": f"{src.path.as_posix()}:{call.line}"})
    return found


def build_draft(sources: list[SourceFile]) -> dict:
    from iron_laws.engine.taint import param_name

    sinks, sanitizers, inputs = [], [], []
    seen: set[str] = set()
    rules = [(family, cls()) for family, cls in _rules()]
    for src in sources:
        lang = LANG_NAME.get(src.lang) if src.lang else None
        if lang is None:
            continue
        calls = list(iter_calls(src))
        for fn in iter_functions(src):
            if fn.name in ("<anonymous>", "") or fn.name in seen:
                continue
            params = [param_name(src, p) for p in fn.params]
            params = [p for p in params if p and p not in ("self", "cls", "this")]
            inner = [c for c in calls if fn.node.start_byte <= c.node.start_byte and c.node.end_byte <= fn.node.end_byte]
            for family, rule in rules:
                hit = next((c for c in inner for s in rule.sinks if src.lang in s.langs and s.callee.search(c.callee) and any(re.search(rf"\b{re.escape(p)}\b", src.text_of(a)) for a in c.args for p in params)), None)
                if hit is not None:
                    seen.add(fn.name)
                    sinks.append({"id": f"wrapper-{fn.name}", "family": family, "languages": [lang], "callee": rf"(^|\.){re.escape(fn.name)}$", "arg": 0,
                                  "origin": "code", "evidence": f"{src.path.as_posix()}:{src.line_of(fn.node)}에서 매개변수를 {hit.callee}에 넘긴다", "positive": "", "negative": ""})
                    break
            if SANITIZER_NAME.search(fn.name) and fn.name not in seen:
                seen.add(fn.name)
                sanitizers.append({"id": f"sanitizer-{fn.name}", "family": "command", "context": "", "languages": [lang], "name": rf"(^|\.){re.escape(fn.name)}$",
                                   "origin": "code", "evidence": f"{src.path.as_posix()}:{src.line_of(fn.node)}", "positive": "", "negative": ""})
            if src.lang is Lang.PYTHON and fn.name in ("handler", "lambda_handler") and params[:2] == ["event", "context"] and "event" not in {i["id"] for i in inputs}:
                inputs.append({"id": "lambda-event", "family": "command", "languages": [lang], "pattern": r"\bevent\s*\[|\bevent\.get\(",
                               "origin": "code", "evidence": f"{src.path.as_posix()}:{src.line_of(fn.node)} AWS Lambda 처리기", "positive": "", "negative": ""})
        if src.lang in JS_FAMILY and re.search(r"\.on\(\s*['\"]message['\"]", src.code_text) and "ws-message" not in {i["id"] for i in inputs}:
            inputs.append({"id": "ws-message", "family": "command", "languages": [lang], "pattern": r"\bmessage\.(?:data|toString\(\))",
                           "origin": "code", "evidence": f"{src.path.as_posix()} 웹소켓 메시지 처리", "positive": "", "negative": ""})
    return {"version": 1, "sources": inputs, "sinks": sinks, "sanitizers": sanitizers, "validators": [], "summaries": [],
            "candidates": external_candidates(sources, rules), "config_hints": config_hints(sources)}


EXEMPT_ANNOTATION = re.compile(r"(?:getMethodAnnotation|hasMethodAnnotation|isAnnotationPresent|getAnnotation)\(\s*(\w+)\.class")
PRINCIPAL_CALL = re.compile(r"\b((?:\w+\.)?get(?:Login|Session|Current|Auth)\w*\(\)\.get(?:Mid|Merchant\w*Id|Tenant\w*|Org\w*Id|Company\w*Id|Shop\w*Id|Store\w*Id|Partner\w*Id|Agency\w*Id)\(\))")


def config_hints(sources: list[SourceFile]) -> dict[str, list[dict]]:
    """설정 파일에 옮길 후보. exempt_markers: HandlerInterceptor가 확인하는 애너테이션, principal: 로그인 사용자의 소속을 읽는 호출식"""
    markers: dict[str, str] = {}
    principals: dict[str, list[str]] = {}
    for src in sources:
        if src.lang not in (Lang.JAVA, Lang.KOTLIN):
            continue
        text = src.code_text
        if re.search(r"HandlerInterceptor|preHandle\s*\(", text):
            for m in EXEMPT_ANNOTATION.finditer(text):
                markers.setdefault(f"@{m.group(1)}", f"{src.path.as_posix()}:{text.count(chr(10), 0, m.start()) + 1} 인터셉터가 이 애너테이션을 확인한다")
        for m in PRINCIPAL_CALL.finditer(text):
            principals.setdefault(m.group(1), []).append(f"{src.path.as_posix()}:{text.count(chr(10), 0, m.start()) + 1}")
    return {
        "auth.exempt_markers": [{"value": k, "evidence": v} for k, v in sorted(markers.items())],
        "tenancy.principal": [{"value": k, "evidence": f"{len(v)}곳에서 쓴다(예: {v[0]})"} for k, v in sorted(principals.items(), key=lambda kv: -len(kv[1]))[:10]],
    }


FAMILY_TOPIC = {
    "command": "운영체제 명령 실행(CWE-78)", "sql": "SQL 실행(CWE-89)", "path": "파일 경로 접근(CWE-22)", "code": "코드·표현식 실행(CWE-94)",
    "xpath": "XPath 질의(CWE-643)", "ldap": "LDAP 질의(CWE-90)", "xss": "HTML 출력(CWE-79)", "redirect": "주소 이동(CWE-601)",
}


def llm_prompt(draft: dict, sources: list[SourceFile], budget: int = 12000, lessons: Sequence[str] = (), family: str | None = None) -> str:
    """LLM에 보낼 지시문. family를 주면 그 계열(CWE)의 외부 호출 후보만 묻는다"""
    excerpts = []
    used = 0
    for src in sources:
        if src.lang is None or used > budget:
            continue
        piece = src.code_text[:2000]
        used += len(piece)
        excerpts.append(f"--- {src.path.as_posix()}\n{piece}")
    known = ""
    if lessons:
        known = (
            "이 프로젝트에서 이미 확인한 사실(교훈). 같은 실수를 반복하지 말고, 이미 확인한 이름과 조건을 그대로 쓰십시오.\n"
            + "\n".join(f"- {lesson}" for lesson in lessons)
            + "\n\n"
        )
    shown = {k: v for k, v in draft.items() if k != "candidates"}
    focus = ""
    if family is not None:
        candidates = (draft.get("candidates") or {}).get(family, [])
        focus = (
            f"이번에는 {FAMILY_TOPIC.get(family, family)} 계열(family: {family})만 본다. 아래 외부 호출 후보마다, 그 호출이 원천·싱크·정제 함수·"
            "검사 함수(validators)·전달 요약(summaries: propagate, from_arg, to)·정규화 요약(summaries: normalize) 가운데 무엇인지 판단하라. "
            "해당하지 않으면 넣지 마라.\n후보:\n" + yaml.safe_dump(candidates, allow_unicode=True, sort_keys=False) + "\n"
        )
    return (
        known
        + focus
        + "아래 코드에서 웹 요청 외의 외부 입력(소스), 명령·SQL·경로·코드 실행으로 이어지는 프로젝트 감싼 함수(싱크), 정제 함수를 찾아 "
        "오철칙 명세 YAML(version, sources, sinks, sanitizers, validators, summaries; 각 항목 id·family·languages·pattern|callee|name·context, "
        "검사 함수는 arg·success, 요약은 summary·from_arg·to)만 출력하라. "
        "각 항목에 positive(이 항목이 있으면 지적되어야 하는 최소 코드 파일 전체)와 negative(지적되면 안 되는 비슷한 코드 파일 전체)를 넣어라. "
        "싱크·정제 함수·검사 함수·요약 항목의 예제는 오철칙이 이미 외부 입력으로 아는 웹 요청 값에서 시작하라"
        "(Java `HttpServletRequest.getParameter`, Python Flask `request.args`, JavaScript Express `req.query`). "
        "환경 변수·파일 내용·상수에서 시작한 예제는 지적되지 않는다. 소스 항목의 예제는 그 소스에서 읽은 값을 이미 아는 싱크"
        "(Java `Runtime.getRuntime().exec`, Python `os.system`)에 넘겨라. "
        "context에는 shell·sql·path·code·html·url·ldap·xpath·header·any 가운데 하나만 적고 설명을 넣지 마라. "
        "확실하지 않은 항목은 넣지 마라.\n\n현재 초안:\n"
        + yaml.safe_dump(shown, allow_unicode=True, sort_keys=False) + "\n코드:\n" + "\n".join(excerpts)
    )


def merge_llm(draft: dict, text: str) -> int:
    """LLM 출력(YAML 또는 JSON)에서 형식이 맞는 항목만 초안에 더한다. 제안한 예제는 proposed_positive·proposed_negative에 두고,
    check_llm_entries가 확인한 뒤에만 positive·negative로 옮긴다."""
    body = re.sub(r"^```\w*\n|```\s*$", "", text.strip(), flags=re.MULTILINE)
    try:
        data = yaml.safe_load(body)
    except yaml.YAMLError:  # iron-laws: ignore[IL-301] YAML로 읽지 못하면 JSON으로 다시 읽는다
        try:
            data = json.loads(body)
        except ValueError:  # iron-laws: ignore[IL-301] 읽을 수 없는 LLM 출력은 제안 0건으로 보고하고 코드 후보 초안은 그대로 둔다
            return 0
    if not isinstance(data, dict):
        return 0
    added = 0
    keys = {"sources": "pattern", "sinks": "callee", "sanitizers": "name", "validators": "name", "summaries": "name"}
    for kind, field in keys.items():
        existing = {e["id"] for e in draft.setdefault(kind, [])}
        for entry in data.get(kind) or []:
            if not isinstance(entry, dict) or not entry.get("id") or not entry.get(field) or entry["id"] in existing:
                continue
            try:
                re.compile(str(entry[field]))
            except re.error:  # iron-laws: ignore[IL-301] 정규식으로 컴파일되지 않는 LLM 제안 항목은 초안에 넣지 않는다
                continue
            clean = {k: entry[k] for k in ("id", "family", "languages", field, "arg", "context", "success", "summary", "from_arg", "to", "negative_expect") if k in entry}
            clean.update({"origin": "llm", "positive": "", "negative": ""})
            for form in ("positive", "negative"):
                if (isinstance(entry.get(form), str) and entry[form].strip()) or isinstance(entry.get(form), dict):
                    clean[f"proposed_{form}"] = entry[form]
            draft[kind].append(clean)
            added += 1
    return added


def check_llm_entries(draft: dict) -> dict[str, int]:
    """LLM이 제안한 항목을 제안한 예제로 판정한다.
    - 예제가 없거나 기대대로 판정되지 않은 항목은 초안에서 빼 rejected 목록으로 옮긴다(사유 포함).
    - 소스·싱크는 지적을 늘리기만 하므로 예제가 맞으면 positive·negative를 채운다.
    - 정제 함수·검사 함수·정규화 요약은 지적을 지우거나 낮추므로 예제가 맞아도 positive·negative를 비워 둔다.
      사람이 제안 예제를 확인해 옮겨야 불러온다."""
    from iron_laws.core.config import ConfigError
    from iron_laws.core.custom_spec import SpecEntry, entry_results, lowers
    from iron_laws.core.scanner import scan_examples

    counts = {"passed": 0, "rejected": 0, "needs_review": 0}
    rejected = draft.setdefault("rejected", [])
    for kind in ("sources", "sinks", "sanitizers", "validators", "summaries"):
        kept = []
        for entry in draft.get(kind, []):
            if entry.get("origin") != "llm":
                kept.append(entry)
                continue
            positive, negative = entry.get("proposed_positive", ""), entry.get("proposed_negative", "")
            try:
                candidate = SpecEntry(**{**{k: v for k, v in entry.items() if not k.startswith("proposed_") and k != "origin"}, "positive": positive, "negative": negative})
                results = entry_results(kind, candidate, scan_examples)
            except (ConfigError, ValueError, TypeError) as e:
                rejected.append({**entry, "kind": kind, "why": f"예제로 확인할 수 없다: {e}"})
                counts["rejected"] += 1
                continue
            failed = [f"{form}: {why}" for _name, form, ok, why in results if not ok]
            if failed:
                rejected.append({**entry, "kind": kind, "why": "제안한 예제가 기대대로 판정되지 않았다(" + "; ".join(failed) + ")"})
                counts["rejected"] += 1
                continue
            if lowers(kind, candidate):
                entry["check"] = "예제 통과, 지적을 낮추는 항목이라 사람이 확인한 뒤 positive·negative로 옮겨야 불러온다"
                counts["needs_review"] += 1
            else:
                entry.update({"positive": positive, "negative": negative, "check": "제안한 예제가 기대대로 판정됐다"})
                counts["passed"] += 1
            kept.append(entry)
        draft[kind] = kept
    if not rejected:
        draft.pop("rejected")
    return counts
