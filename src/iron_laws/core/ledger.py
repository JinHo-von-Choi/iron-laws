"""
오철칙 검사 공백 장부(CoverageLedger) 작성
보안 관심 지점(Python의 명령 실행·경로 접근·SQL 조립 호출)마다 요구한 분석 근거를 확보했는지 기록한다.
- 근거 충족: 모든 입력이 닫혀 있다(상수·닫힌 값) 또는 외부 입력 도달이 확인되어 지적이 났다
- 미지원: 호출은 보이는데 규칙에 모델이 없다
- 해석 미확정: 입력의 출처를 확정하지 못했다(호출자 없는 매개변수·미해석 호출·객체 속성 등). 깨끗함으로 바꾸지 않는다
- 예산 초과: 해석 한도에 닿았다
- 정책 제외: 신뢰된 정책(계약 제외 경로·사유 있는 억제 주석)이 제외했다
작성자: 최진호
작성일: 2026-10-04
"""

import fnmatch
import hashlib
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from tree_sitter import Node

from iron_laws.core.config import IronLawsConfig
from iron_laws.core.contract import Contract, PointState, contract_digest
from iron_laws.core.models import CoverageLedger, FamilyTally, InterestPoint, LedgerFile
from iron_laws.engine import xfile
from iron_laws.engine.ast_tools import (
    CALL_TYPES,
    Call,
    enclosing_function,
    is_literal,
    iter_calls,
    iter_functions,
)
from iron_laws.engine.languages import Lang
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import (
    WEB_SOURCE_RE,
    Ctx,
    definitions,
    param_name,
    reaching_definitions,
    resolve_any,
    sanitizer_name_matches,
)
from iron_laws.rules.injection import (
    CommandInjectionRule,
    PathTraversalRule,
    SinkRule,
    SqlInjectionRule,
)
from iron_laws.rules.sinks import Flow, assess

FAMILY_RULES: dict[str, type[SinkRule]] = {
    "command": CommandInjectionRule,
    "path": PathTraversalRule,
    "sql": SqlInjectionRule,
}
# 규칙이 모델로 가진 호출 말고도 같은 계열의 관심 지점으로 보이는 호출. 여기에만 걸리면 '미지원'이다.
BROAD_PATTERNS: dict[str, re.Pattern[str]] = {
    "command": re.compile(
        r"^(?:os|subprocess|pty|commands|sh|plumbum|pexpect|fabric|invoke)\."
        r"(?:system|popen\w*|spawn\w*|exec\w*|call|run|check_output|check_call|Popen|getoutput|getstatusoutput|"
        r"startfile|posix_spawn\w*)$"
        r"|^asyncio\.create_subprocess_(?:exec|shell)$"
        r"|^(?:Popen|check_output|check_call|getoutput|getstatusoutput|startfile)$"
    ),
    "path": re.compile(
        r"^(?:os\.(?:rename|replace|chmod|chown|symlink|link|stat|lstat|walk|scandir|listdir|makedirs|mkdir|remove|unlink|rmdir|"
        r"truncate|utime|access|readlink|open)|shutil\.\w+|glob\.\w+|io\.open|codecs\.open|zipfile\.\w+|tarfile\.\w+|"
        r"tempfile\.\w+|fileinput\.\w+|gzip\.open|bz2\.open|lzma\.open)$|\.(?:open|rglob|glob|iterdir|unlink|rmdir|mkdir|"
        r"rename|touch|chmod|symlink_to|hardlink_to|extractall|extract)$"
    ),
    "sql": re.compile(
        r"(?:^|\.)(?:execute\w*|exec_driver_sql|read_sql\w*|raw|extra|text|mogrify|copy_expert|copy_from|copy_to|fetch(?:row|val|many|_all)?)$"
    ),
}
# 값의 출처를 따질 필요 없이 결과가 닫혀 있는 호출. 인자가 닫혀 있을 때만 결과도 닫힌다.
PURE_CALLS = frozenset(
    {
        "str", "int", "float", "bool", "repr", "len", "abs", "round", "min", "max", "sum", "sorted", "list", "tuple",
        "dict", "set", "frozenset", "range", "enumerate", "zip", "reversed", "bytes", "bytearray", "chr", "ord", "hex",
        "format", "ascii", "any", "all", "map", "filter", "isinstance", "type",
        "os.path.join", "os.path.basename", "os.path.dirname", "os.path.abspath", "os.path.normpath", "os.path.realpath",
        "os.path.splitext", "os.path.split", "os.path.expanduser", "os.path.exists", "os.path.isfile", "os.path.isdir",
        "os.getcwd", "pathlib.Path", "Path", "shlex.quote", "shlex.split", "json.dumps", "uuid.uuid4", "time.time",
        "datetime.now", "datetime.datetime.now", "text", "sa.text", "sqlalchemy.text",
    }
)
STR_METHODS = frozenset(
    {
        "format", "join", "strip", "lstrip", "rstrip", "lower", "upper", "title", "replace", "split", "rsplit", "splitlines",
        "encode", "decode", "startswith", "endswith", "zfill", "ljust", "rjust", "center", "casefold", "capitalize",
        "joinpath", "with_suffix", "with_name", "resolve", "absolute", "parent", "name", "stem", "suffix", "as_posix",
        "get", "items", "keys", "values", "append", "extend", "copy",
    }
)
ENV_ACCESS_RE = re.compile(r"^os\.(?:environ|getenv)|^environ")
CLI_INPUT_RE = re.compile(r"\bsys\.argv\b|\binput\s*\(|\bargparse\b|\bsys\.stdin\b")
MAX_CLOSED_DEPTH = 8
LIMITATIONS = [
    "관심 지점은 호출 이름으로 찾는다. import 별칭, getattr 같은 동적 호출, 프레임워크가 감춘 호출은 지점으로 발견되지 않을 수 있다.",
    "'근거 충족'은 그 지점에서 계약이 요구한 분석 근거를 확보했다는 뜻이며 프로그램 전체가 안전하다는 뜻이 아니다.",
    "전체 코드의 몇 %가 안전하다는 점수는 만들지 않는다. 아래 분모(발견한 지점 수, 분류하지 못한 파일)와 함께 읽는다.",
]


@dataclass
class _Context:
    contract: Contract
    callers: dict[tuple[str, int], list[tuple[SourceFile, Call]]] = field(default_factory=dict)
    modeled: dict[str, list] = field(default_factory=dict)
    rules: dict[str, SinkRule] = field(default_factory=dict)


class _Closed:
    """식의 모든 입력이 상수이거나 확인된 닫힌 값인지 판정한다. 확정하지 못하면 (False, 이유)를 돌려준다."""

    def __init__(self, src: SourceFile, ctx: _Context, taint_ctx: Ctx = Ctx.ANY):
        self.src = src
        self.ctx = ctx
        self.taint_ctx = taint_ctx  # 이 지점이 속한 계열(명령·경로·SQL)에서 유효한 정제만 인정한다

    def check(self, node: Node, depth: int = 0, seen: frozenset[int] = frozenset()) -> tuple[bool, str]:
        if depth > MAX_CLOSED_DEPTH:
            return False, "해석 깊이 한도에 도달했다"
        if node.id in seen:
            return True, ""
        seen = seen | {node.id}
        src = self.src
        t = node.type
        text = src.text_of(node)
        if is_literal(node) or t in ("integer", "float", "true", "false", "none", "ellipsis"):
            return True, ""
        if t in CALL_TYPES.get(Lang.PYTHON, set()) and self._sanitized_call(node):
            return True, ""
        if WEB_SOURCE_RE.search(text):
            return False, "외부 입력이 섞여 있다"
        if t == "identifier":
            return self._identifier(node, depth, seen)
        if t in ("attribute", "subscript"):
            return self._attribute_or_subscript(node, text, depth, seen)
        if t in CALL_TYPES.get(Lang.PYTHON, set()):
            return self._call(node, depth, seen)
        if t == "conditional_expression" and len(node.named_children) >= 3:
            branches = [node.named_children[0], node.named_children[-1]]  # 값이 되는 두 갈래. 어느 쪽을 고르는 조건은 값의 닫힘과 무관하다
            for branch in branches:
                ok, reason = self.check(branch, depth + 1, seen)
                if not ok:
                    return False, reason
            return True, ""
        if t in ("lambda", "generator_expression", "yield", "await"):
            return False, f"{t} 식의 값을 추적하지 않는다"
        # 문자열 보간·이항 연산·조건식·컨테이너 등은 하위 식이 모두 닫혀 있으면 닫혀 있다
        for child in node.named_children:
            if "comment" in child.type:
                continue
            ok, reason = self.check(child, depth + 1, seen)
            if not ok:
                return False, reason
        return True, ""

    def _sanitized_call(self, node: Node) -> bool:
        """int()·정제 함수처럼 이 계열에서 값을 무해하게 만드는 호출(프로젝트에 정의된 함수는 제외 — 본문을 따른다)"""
        index = self.src.memo("call_by_id", lambda: {c.node.id: c for c in iter_calls(self.src)})
        call = index.get(node.id)
        if call is None or resolve_any(self.src, call.callee, len(call.args)):
            return False
        return sanitizer_name_matches(call.callee, self.taint_ctx)

    def _identifier(self, node: Node, depth: int, seen: frozenset[int]) -> tuple[bool, str]:
        name = self.src.text_of(node)
        if name in ("True", "False", "None", "__file__", "__name__"):
            return True, ""
        scope = enclosing_function(node, Lang.PYTHON) or self.src.root
        if scope is None:
            return False, f"변수 {name}의 범위를 알 수 없다"
        defs = reaching_definitions(self.src, scope, name, node.start_byte)
        if defs:
            for d in defs:
                ok, reason = self.check(d, depth + 1, seen)
                if not ok:
                    return False, reason
            return True, ""
        # 함수 매개변수
        fn = enclosing_function(node, Lang.PYTHON)
        if fn is not None:
            params = fn.child_by_field_name("parameters")
            names = [param_name(self.src, p) for p in (params.named_children if params else [])]
            if name in names:
                return self._parameter(fn, name, depth, seen)
        # 모듈 수준 상수
        module_defs = [d for d in definitions(self.src, self.src.root, name) if enclosing_function(d, Lang.PYTHON) is None] if self.src.root else []
        if module_defs:
            for d in module_defs:
                ok, reason = self.check(d, depth + 1, seen)
                if not ok:
                    return False, reason
            return True, ""
        return False, f"변수 {name}의 값이 어디서 오는지 확정하지 못했다(가져온 이름·전역·내포식 변수 등)"

    def _parameter(self, fn: Node, name: str, depth: int, seen: frozenset[int]) -> tuple[bool, str]:
        func = next((f for f in iter_functions(self.src) if f.node.id == fn.id), None)
        if func is None:
            return False, f"매개변수 {name}의 호출자를 찾지 못했다"
        sites = self.ctx.callers.get((self.src.path.as_posix(), fn.id), [])
        if not sites:
            return False, f"매개변수 {name}를 넘기는 호출자를 프로젝트에서 찾지 못했다(외부에서 호출되는 함수일 수 있다)"
        params = [p for p in func.params if self.src.text_of(p) not in ("self", "cls")]
        index = next((i for i, p in enumerate(params) if param_name(self.src, p) == name), None)
        if index is None:
            return False, f"매개변수 {name}의 위치를 알 수 없다"
        for caller_src, call in sites:
            if index >= len(call.args):
                return False, f"호출자가 매개변수 {name}를 넘기지 않아 기본값에 의존한다"
            ok, reason = _Closed(caller_src, self.ctx, self.taint_ctx).check(call.args[index], depth + 1, seen)
            if not ok and WEB_SOURCE_RE.search(caller_src.text_of(call.args[index])):
                continue  # 호출자에서 외부 입력이 닿는 흐름은 지적으로 따로 나타난다
            if not ok:
                return False, f"호출자 {caller_src.path.as_posix()}:{call.line}의 인자가 닫혀 있지 않다: {reason}"
        return True, ""

    def _attribute_or_subscript(self, node: Node, text: str, depth: int, seen: frozenset[int]) -> tuple[bool, str]:
        compact = re.sub(r"\s+", "", text)
        if ENV_ACCESS_RE.match(compact):
            if "env" in self.ctx.contract.trusted_sources:
                return True, ""
            return False, "환경변수 값은 신뢰된 출처로 선언되지 않았다"
        if CLI_INPUT_RE.search(text):
            return False, "명령행·표준입력 값이다"
        if node.type == "subscript":
            base = node.child_by_field_name("value")
            index = node.child_by_field_name("subscript")
            parts = [p for p in (base, index) if p is not None]
            for part in parts:
                ok, reason = self.check(part, depth + 1, seen)
                if not ok:
                    return False, reason
            return True, ""
        obj = node.child_by_field_name("object")
        if obj is not None and obj.type == "identifier" and self.src.text_of(obj) in ("self", "cls"):
            return False, f"객체 속성 {compact}의 값을 추적하지 않는다"
        if obj is not None:
            ok, reason = self.check(obj, depth + 1, seen)
            if ok:
                return True, ""  # 닫힌 객체의 속성(예: 문자열·경로의 속성)
        return False, f"{compact}의 값을 추적하지 않는다(모듈·객체 속성)"

    def _call(self, node: Node, depth: int, seen: frozenset[int]) -> tuple[bool, str]:
        index = self.src.memo("call_by_id", lambda: {c.node.id: c for c in iter_calls(self.src)})
        call = index.get(node.id)
        if call is None:
            return False, "호출을 해석하지 못했다"
        callee = call.callee
        text = self.src.text_of(node)
        if ENV_ACCESS_RE.match(re.sub(r"\s+", "", callee)):
            if "env" in self.ctx.contract.trusted_sources:
                return True, ""
            return False, "환경변수 값은 신뢰된 출처로 선언되지 않았다"
        if CLI_INPUT_RE.search(text):
            return False, "명령행·표준입력 값이다"
        helpers = resolve_any(self.src, callee, len(call.args))
        args_ok = self._args_closed(call, depth, seen)
        if helpers:
            for hsrc, fn in helpers:
                ok, reason = self._helper_returns_closed(hsrc, fn, depth, seen)
                if not ok:
                    return False, reason
            return (True, "") if args_ok[0] else args_ok
        if sanitizer_name_matches(callee, self.taint_ctx):
            return True, ""
        last = callee.rsplit(".", 1)[-1]
        if callee in PURE_CALLS or (("." in callee) and last in STR_METHODS):
            if "." in callee and callee not in PURE_CALLS:
                func = node.child_by_field_name("function")
                receiver = func.child_by_field_name("object") if func is not None else None
                if receiver is not None:
                    ok, reason = self.check(receiver, depth + 1, seen)
                    if not ok:
                        return False, reason
            return args_ok
        return False, f"미해석 호출 {callee}()의 반환값을 확인하지 못했다"

    def _args_closed(self, call: Call, depth: int, seen: frozenset[int]) -> tuple[bool, str]:
        for arg in call.args:
            ok, reason = self.check(arg, depth + 1, seen)
            if not ok:
                return False, reason
        return True, ""

    def _helper_returns_closed(self, hsrc: SourceFile, fn, depth: int, seen: frozenset[int]) -> tuple[bool, str]:
        if hsrc.root is None:
            return False, "다른 파일 함수를 읽지 못했다"
        returns = [n for n in _walk(fn.node) if n.type == "return_statement" and n.named_children]
        if not returns:
            return True, ""
        checker = _Closed(hsrc, self.ctx, self.taint_ctx)
        for r in returns:
            ok, reason = checker.check(r.named_children[0], depth + 1, seen)
            if not ok:
                return False, f"{fn.name}()의 반환값: {reason}"
        return True, ""


def _walk(node: Node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _build_callers(sources: list[SourceFile]) -> dict[tuple[str, int], list[tuple[SourceFile, Call]]]:
    callers: dict[tuple[str, int], list[tuple[SourceFile, Call]]] = defaultdict(list)
    for src in sources:
        if src.lang is not Lang.PYTHON:
            continue
        for call in iter_calls(src):
            for hsrc, fn in resolve_any(src, call.callee, len(call.args)):
                callers[(hsrc.path.as_posix(), fn.node.id)].append((src, call))
    return callers


@dataclass
class _Verdict:
    state: str
    reason: str
    finding_ids: list[str] = field(default_factory=list)
    evidence_kind: str = "none"


def _classify(
    src: SourceFile,
    call: Call,
    family: str,
    ctx: _Context,
    findings: dict[tuple[str, str, int], list[str]],
) -> _Verdict:
    """한 관심 지점의 상태. 지적은 규칙이 실제로 낸 확정 지적(finding_id)에서만 가져온다.
    장부가 흐름을 따로 평가해 지적이 있다고 추정하지 않는다: 지적 없이 '근거 충족'이 되려면 닫힌 값이거나 규칙이 인정한 안전 조건이 있어야 한다."""
    rule = ctx.rules[family]
    sink = next((s for s in rule.sinks if src.lang in s.langs and s.callee.search(call.callee)), None)
    if sink is None:
        return _Verdict(PointState.UNSUPPORTED.value, f"{call.callee}() 호출은 이 계열의 관심 지점으로 보이지만 규칙에 모델이 없다")
    index = xfile.get_index()
    before = index.limit_hits if index else 0
    args = rule.select_args(src, call, sink)
    finding_ids = list(findings.get((rule.rule_id, src.path.as_posix(), call.line), []))
    unresolved: str | None = None
    guarded = False
    for arg in args:
        if is_literal(arg):
            continue
        flow = assess(src, arg, rule.include_cli_sources, ctx=rule.taint_ctx)
        if flow is Flow.TAINTED:
            if finding_ids:
                continue
            # 오염 흐름이 보이는데 규칙이 지적하지 않았다. 규칙이 인정한 안전 조건이 있을 때만 근거로 삼는다.
            if rule._allowlisted(src, call, arg):
                guarded = True
                continue
            if family != "sql" and rule.skip_hit(src, call, arg, flow):
                guarded = True
                continue
            if unresolved is None:
                unresolved = "외부 입력이 닿는 흐름이 보이지만 규칙은 지적하지 않았다. 규칙이 안전하다고 본 근거를 사람이 확인해야 한다"
            continue
        if family != "sql" and rule.skip_hit(src, call, arg, flow):
            guarded = True
            continue  # 규칙이 안전한 호출 형태로 판정 (예: 셸을 거치지 않는 인자 배열, 정규화·범위 검사를 거친 경로). SQL의 skip은 소음 억제라 안전 근거가 아니다
        ok, reason = _Closed(src, ctx, rule.taint_ctx).check(arg)
        if not ok and unresolved is None:
            unresolved = reason
    after = index.limit_hits if index else 0
    if finding_ids:
        return _Verdict(PointState.EVIDENCE_MET.value, "외부 입력 도달이 확인되어 지적으로 보고되었다", finding_ids, "finding")
    if after > before:
        return _Verdict(PointState.BUDGET_EXCEEDED.value, "함수 간·파일 간 해석 한도에 도달해 흐름을 끝까지 따라가지 못했다")
    if unresolved is not None:
        return _Verdict(PointState.UNRESOLVED.value, unresolved)
    if guarded:
        return _Verdict(PointState.EVIDENCE_MET.value, "규칙이 인정한 안전 조건(허용 목록·범위 검증·셸을 거치지 않는 호출)이 확인되었다", [], "guard")
    return _Verdict(PointState.EVIDENCE_MET.value, "모든 입력이 상수이거나 닫힌 값으로 확인되었다", [], "closed_value")


def _point_id(family: str, path: str, line: int, column: int, callee: str) -> str:
    """같은 줄에 같은 호출이 둘 이상 있을 수 있으므로 열 위치까지 넣어 지점마다 유일하게 만든다."""
    return hashlib.sha256(f"{family}|{path}|{line}|{column}|{callee}".encode()).hexdigest()[:12]


def build_ledger(
    sources: list[SourceFile],
    skipped: list[dict[str, str]],
    contract: Contract,
    contract_source: str,
    config: IronLawsConfig,
    findings: dict[tuple[str, str, int], list[str]],
    suppressed_lines: set[tuple[str, int, str]],
    changed_files: set[str] | None,
    digests: dict[str, str],
    policy_changed: bool = False,
    lookup_budget: int = 2000,
) -> CoverageLedger:
    """계약이 요구한 보안 관심 지점의 분석 근거 장부를 만든다. xfile 색인이 설정된 상태에서 호출한다."""
    ctx = _Context(contract=contract)
    for family, rule_cls in FAMILY_RULES.items():
        rule = rule_cls()
        rule.configure(config)
        ctx.rules[family] = rule
    index = xfile.get_index()
    if index is not None:
        saved_cache = index._resolve_cache
        index._resolve_cache = {}
        index.budget = 10**9  # 호출자 지도를 만드는 일은 모든 호출을 한 번씩 해석하므로 상한을 두지 않는다
    ctx.callers = _build_callers(sources)
    if index is not None:
        index._resolve_cache = saved_cache  # 지점별 해석은 이 지도의 결과를 재사용하지 않고 설정한 상한 안에서 따로 해석한다
        index.budget = lookup_budget

    points: list[InterestPoint] = []
    files: list[LedgerFile] = []
    for src in sorted(sources, key=lambda s: s.path.as_posix()):
        path = src.path.as_posix()
        changed = changed_files is None or path in changed_files
        if src.lang is None:
            files.append(LedgerFile(path=path, classification="out_of_scope", reason=f"점검 계약 범위 밖의 파일 종류({src.kind})", changed=changed))
            continue
        language = src.lang.value
        if language not in contract.languages:
            files.append(LedgerFile(path=path, classification="unsupported_language", reason=f"계약이 {language}를 지원하지 않는다", changed=changed))
            continue
        if src.is_test and not contract.include_tests:
            files.append(LedgerFile(path=path, classification="out_of_scope", reason="시험 코드", changed=changed))
            continue
        excluded = any(fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(src.path.name, pat) for pat in contract.exclude_paths)
        file_points = 0
        for call in iter_calls(src):
            for family, rule in ctx.rules.items():
                if family not in contract.families:
                    continue
                modeled = any(src.lang in s.langs and s.callee.search(call.callee) for s in rule.sinks)
                if not modeled and not BROAD_PATTERNS[family].search(call.callee):
                    continue
                if resolve_any(src, call.callee, len(call.args)):
                    continue  # 프로젝트가 정의한 함수의 호출은 라이브러리 관심 지점이 아니다. 그 함수 안의 호출이 지점으로 잡힌다
                if family == "path" and not modeled and call.callee.rsplit(".", 1)[-1] in ("get", "values", "items"):
                    continue
                verdict = _classify(src, call, family, ctx, findings)
                state, reason = verdict.state, verdict.reason
                if family == "path" and ctx.rules["path"].BUILDER_RE.search(call.callee) and not verdict.finding_ids and state == PointState.EVIDENCE_MET.value:
                    continue  # 경로를 조립만 하는 호출은 접근 지점이 아니다. 접근하는 호출이 따로 지점으로 잡힌다
                family_rule_id = rule.rule_id
                suppressed_here = [family_rule_id] if (path, call.line, family_rule_id) in suppressed_lines else []
                if excluded:
                    state, reason = PointState.POLICY_EXCLUDED.value, f"계약 제외 경로({contract.exclusion_reason.strip()})"
                elif suppressed_here:
                    # 억제는 그 계열 규칙의 지적에만 적용한다. 같은 줄의 다른 계열 지점으로 넓히지 않는다
                    state, reason = PointState.POLICY_EXCLUDED.value, f"사유가 있는 억제 주석이 이 지점의 {family_rule_id} 지적을 제외했다"
                points.append(
                    InterestPoint(
                        id=_point_id(family, path, call.line, call.node.start_point[1] + 1, call.callee),
                        column=call.node.start_point[1] + 1,
                        family=family,
                        path=path,
                        line=call.line,
                        callee=call.callee,
                        state=state,
                        reason=reason,
                        in_scope=changed if contract.scope == "changed" else True,
                        finding=bool(verdict.finding_ids),
                        finding_ids=verdict.finding_ids,
                        evidence_kind=verdict.evidence_kind if state == PointState.EVIDENCE_MET.value else "none",
                        suppressed_rules=suppressed_here,
                    )
                )
                file_points += 1
        files.append(
            LedgerFile(
                path=path,
                classification="policy_excluded" if excluded else "analyzed",
                reason=f"계약 제외: {contract.exclusion_reason.strip()}" if excluded else "",
                changed=changed,
                interest_points=file_points,
            )
        )
        src.release()

    for item in skipped:
        path = item.get("path", "")
        if path.startswith("("):
            continue
        files.append(
            LedgerFile(path=path, classification="unclassified", reason=item.get("reason", ""), changed=changed_files is None or path in changed_files)
        )

    tallies: list[FamilyTally] = []
    blockers: list[str] = []
    for family, requirement in contract.families.items():
        fam_points = [p for p in points if p.family == family]
        scoped = [p for p in fam_points if p.in_scope]
        tally = FamilyTally(
            family=family,
            required=requirement.required,
            total=len(fam_points),
            in_scope=len(scoped),
            by_state=dict(Counter(p.state for p in scoped)),
        )
        tallies.append(tally)
        if requirement.required:
            blocking_states = {s.value for s in requirement.block_on}
            for p in scoped:
                if p.state in blocking_states:
                    blockers.append(f"[{family}] {p.path}:{p.line} {p.callee}() — {p.state}: {p.reason}")

    unclassified_changed = sorted(f.path for f in files if f.classification == "unclassified" and f.changed)
    for path in unclassified_changed:
        blockers.append(f"[분류 불가 변경 파일] {path} — 점검하지 못했다")
    analyzed = [f for f in files if f.classification in ("analyzed", "policy_excluded")]
    limitations = list(LIMITATIONS)
    if contract.scope == "changed" and changed_files is None:
        limitations.append("계약 범위가 changed인데 --changed-since가 없어 전체를 대상으로 판정했다.")
    if config.excludes:
        limitations.append("점검 설정의 제외 대상(excludes)에 걸리는 파일은 장부에 나타나지 않는다. 제외 건수는 metadata.excluded_summary에 있다.")

    if policy_changed:
        status = "policy_change_review"
        blockers.insert(0, "[정책 변경] 계약 파일이 이번 변경에 포함되어 있다. 후보 변경이 정책을 바꾼 것이므로 별도의 정책 변경 검토가 필요하다")
    elif blockers:
        status = "unmet"  # 필수 차단 사유가 하나라도 있으면 비적용·충족보다 먼저 보인다
    elif not analyzed:
        status = "not_applicable"
    else:
        status = "met"

    return CoverageLedger(
        contract_version=contract.version,
        contract_mode=contract.mode,
        contract_scope=contract.scope,
        contract_digest=contract_digest(contract),
        contract_source=contract_source,
        languages=list(contract.languages),
        digests=digests,
        families=tallies,
        points=points,
        files=files,
        unclassified_changed_files=unclassified_changed,
        status=status,
        requirements={f: {"required": r.required, "block_on": sorted(x.value for x in r.block_on)} for f, r in contract.families.items()},
        run_id="R-" + hashlib.sha256("|".join(f"{k}={digests[k]}" for k in sorted(digests)).encode()).hexdigest()[:12],
        blockers=blockers,
        limitations=limitations,
    )
