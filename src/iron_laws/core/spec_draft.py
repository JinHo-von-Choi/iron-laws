"""
오철칙 사용자 명세 초안: 코드에서 소스·싱크·정제 함수 후보를 찾는다. 초안은 사람이 검토하고 예제를 채우기 전에는 불러오지 않는다.

- 싱크 후보: 매개변수를 기존 싱크(명령·SQL·경로·코드 실행)에 그대로 넘기는 프로젝트 함수(감싼 함수)
- 정제 후보: 이름이 clean·sanitize·escape·validate·safe·quote·normalize로 시작하거나 끝나는 프로젝트 함수(문맥은 사람이 정한다)
- 소스 후보: AWS Lambda 처리기의 event, 메시지 소비자의 body·payload처럼 웹 요청이 아닌 입력 경로
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
    return {"version": 1, "sources": inputs, "sinks": sinks, "sanitizers": sanitizers}


def llm_prompt(draft: dict, sources: list[SourceFile], budget: int = 12000, lessons: Sequence[str] = ()) -> str:
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
    return (
        known
        + "아래 코드에서 웹 요청 외의 외부 입력(소스), 명령·SQL·경로·코드 실행으로 이어지는 프로젝트 감싼 함수(싱크), 정제 함수를 찾아 "
        "오철칙 명세 YAML(version, sources, sinks, sanitizers; 각 항목 id·family·languages·pattern|callee|name·context)만 출력하라. "
        "각 항목에 positive(이 항목이 있으면 지적되어야 하는 최소 코드 파일 전체)와 negative(지적되면 안 되는 비슷한 코드 파일 전체)를 넣어라. "
        "확실하지 않은 항목은 넣지 마라.\n\n현재 초안:\n"
        + yaml.safe_dump(draft, allow_unicode=True, sort_keys=False) + "\n코드:\n" + "\n".join(excerpts)
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
    keys = {"sources": "pattern", "sinks": "callee", "sanitizers": "name"}
    for kind, field in keys.items():
        existing = {e["id"] for e in draft[kind]}
        for entry in data.get(kind) or []:
            if not isinstance(entry, dict) or not entry.get("id") or not entry.get(field) or entry["id"] in existing:
                continue
            try:
                re.compile(str(entry[field]))
            except re.error:  # iron-laws: ignore[IL-301] 정규식으로 컴파일되지 않는 LLM 제안 항목은 초안에 넣지 않는다
                continue
            clean = {k: entry[k] for k in ("id", "family", "languages", field, "arg", "context") if k in entry}
            clean.update({"origin": "llm", "positive": "", "negative": ""})
            for form in ("positive", "negative"):
                if isinstance(entry.get(form), str) and entry[form].strip():
                    clean[f"proposed_{form}"] = entry[form]
            draft[kind].append(clean)
            added += 1
    return added


def check_llm_entries(draft: dict) -> dict[str, int]:
    """LLM이 제안한 항목을 제안한 예제로 판정한다.
    - 예제가 없거나 기대대로 판정되지 않은 항목은 초안에서 빼 rejected 목록으로 옮긴다(사유 포함).
    - 소스·싱크는 지적을 늘리기만 하므로 예제가 맞으면 positive·negative를 채운다.
    - 정제 함수는 지적을 지우는 유일한 통로라 예제가 맞아도 positive·negative를 비워 둔다. 사람이 제안 예제를 확인해 옮겨야 불러온다."""
    from iron_laws.core.config import ConfigError
    from iron_laws.core.custom_spec import SpecEntry, entry_results

    counts = {"passed": 0, "rejected": 0, "needs_review": 0}
    rejected = draft.setdefault("rejected", [])
    for kind in ("sources", "sinks", "sanitizers"):
        kept = []
        for entry in draft[kind]:
            if entry.get("origin") != "llm":
                kept.append(entry)
                continue
            positive, negative = entry.get("proposed_positive", ""), entry.get("proposed_negative", "")
            try:
                candidate = SpecEntry(**{**{k: v for k, v in entry.items() if not k.startswith("proposed_") and k != "origin"}, "positive": positive, "negative": negative})
                results = entry_results(kind, candidate)
            except (ConfigError, ValueError, TypeError) as e:
                rejected.append({**entry, "kind": kind, "why": f"예제로 확인할 수 없다: {e}"})
                counts["rejected"] += 1
                continue
            failed = [f"{form}: {why}" for _name, form, ok, why in results if not ok]
            if failed:
                rejected.append({**entry, "kind": kind, "why": "제안한 예제가 기대대로 판정되지 않았다(" + "; ".join(failed) + ")"})
                counts["rejected"] += 1
                continue
            if kind == "sanitizers":
                entry["check"] = "예제 통과, 정제 함수라 사람이 확인한 뒤 positive·negative로 옮겨야 불러온다"
                counts["needs_review"] += 1
            else:
                entry.update({"positive": positive, "negative": negative, "check": "제안한 예제가 기대대로 판정됐다"})
                counts["passed"] += 1
            kept.append(entry)
        draft[kind] = kept
    if not rejected:
        draft.pop("rejected")
    return counts
