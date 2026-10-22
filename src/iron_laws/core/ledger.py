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

from iron_laws.core.config import IronLawsConfig
from iron_laws.core.contract import Contract, PointState, contract_digest
from iron_laws.core.ledger_values import _Closed, _Context
from iron_laws.core.models import CoverageLedger, FamilyTally, InterestPoint, LedgerFile
from iron_laws.engine import xfile
from iron_laws.engine.ast_tools import (
    Call,
    is_literal,
    iter_calls,
)
from iron_laws.engine.languages import Lang
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import (
    resolve_any,
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
LIMITATIONS = [
    "관심 지점은 호출 이름으로 찾는다. import 별칭, getattr 같은 동적 호출, 프레임워크가 감춘 호출은 지점으로 발견되지 않을 수 있다.",
    "'근거 충족'은 그 지점에서 계약이 요구한 분석 근거를 확보했다는 뜻이며 프로그램 전체가 안전하다는 뜻이 아니다.",
    "전체 코드의 몇 %가 안전하다는 점수는 만들지 않는다. 아래 분모(발견한 지점 수, 분류하지 못한 파일)와 함께 읽는다.",
]



def _build_callers(sources: list[SourceFile]) -> dict[tuple[str, int], list[tuple[SourceFile, Call]]]:
    callers: dict[tuple[str, int], list[tuple[SourceFile, Call]]] = defaultdict(list)
    for src in sources:
        if src.lang is not Lang.PYTHON:
            continue
        for call in iter_calls(src):
            for hsrc, fn in resolve_any(src, call.callee, len(call.args)):
                callers[(hsrc.path.as_posix(), fn.node.id)].append((src, call))
    return callers


def _findings_of(src: SourceFile, call: Call, rule_id: str, ctx: _Context) -> tuple[list[str], list[int]]:
    """이 호출의 지적. 열까지 같은 호출의 지적이 기본이다. 같은 줄의 다른 호출이 낸 지적은 근거로 쓰지 않되,
    그 호출과 이 호출이 서로 안에 들어 있는(`open(os.path.join(...))`) 같은 흐름이면 한 지적으로 함께 본다. 나란히 있는 호출(`a(); b()`)은 따로 본다."""
    path = src.path.as_posix()
    column = call.node.start_point[1] + 1
    entries = ctx.findings_by_line.get((rule_id, path, call.line), ())
    exact = next((ids for col, ids in entries if col == column), None)
    if exact:
        return list(exact), []
    linked: list[str] = []
    columns: list[int] = []
    for col, ids in entries:
        if col == column:
            continue
        for other in _calls_on_line(src, call.line):
            if other.node.start_point[1] + 1 == col and _nested(call.node, other.node):
                linked.extend(ids)
                columns.append(col)
                break
    return linked, sorted(set(columns))


def _nested(a, b) -> bool:
    """두 호출 노드 중 하나가 다른 하나를 포함한다."""
    return (a.start_byte <= b.start_byte and b.end_byte <= a.end_byte) or (b.start_byte <= a.start_byte and a.end_byte <= b.end_byte)


def _calls_on_line(src: SourceFile, line: int) -> list[Call]:
    by_line = src.memo("calls_by_line", lambda: _group_calls(src))
    return by_line.get(line, [])


def _group_calls(src: SourceFile) -> dict[int, list[Call]]:
    grouped: dict[int, list[Call]] = {}
    for c in iter_calls(src):
        grouped.setdefault(c.line, []).append(c)
    return grouped


@dataclass
class _Verdict:
    state: str
    reason: str
    finding_ids: list[str] = field(default_factory=list)
    evidence_kind: str = "none"
    linked_columns: list[int] = field(default_factory=list)


def _classify(
    src: SourceFile,
    call: Call,
    family: str,
    ctx: _Context,
    findings: dict[tuple[str, str, int, int], list[str]],
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
    finding_ids, linked_columns = _findings_of(src, call, rule.rule_id, ctx)
    unresolved: str | None = None
    guarded = False
    declared: list[str] = []
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
        closed = _Closed(src, ctx, rule.taint_ctx)
        ok, reason = closed.check(arg)
        if not ok:
            if unresolved is None:
                unresolved = reason
            continue
        # 닫힘의 이유가 사용자가 선언한 정제 함수라면 근거가 아니라 약속이다. 구분해 남긴다.
        declared_sanitizer = closed.declared_sanitizer(arg)
        if declared_sanitizer is not None:
            declared.append(declared_sanitizer)
    after = index.limit_hits if index else 0
    if finding_ids:
        return _Verdict(PointState.EVIDENCE_MET.value, "외부 입력 도달이 확인되어 지적으로 보고되었다", finding_ids, "finding", linked_columns)
    if after > before:
        return _Verdict(PointState.BUDGET_EXCEEDED.value, "함수 간·파일 간 해석 한도에 도달해 흐름을 끝까지 따라가지 못했다")
    if unresolved is not None:
        return _Verdict(PointState.UNRESOLVED.value, unresolved)
    if guarded:
        return _Verdict(PointState.EVIDENCE_MET.value, "규칙이 인정한 안전 조건(허용 목록·범위 검증·셸을 거치지 않는 호출)이 확인되었다", [], "guard")
    if declared:
        names = ", ".join(sorted(set(declared)))
        return _Verdict(
            PointState.EVIDENCE_MET.value,
            f"사용자가 선언한 정제 함수 {names}()가 이 흐름을 막는다고 선언되어 있다. 선언이 사실을 대신하지는 않는다.",
            [],
            "declared_sanitizer",
        )
    return _Verdict(PointState.EVIDENCE_MET.value, "모든 입력이 상수이거나 닫힌 값으로 확인되었다", [], "closed_value")


def _point_id(family: str, path: str, line: int, column: int, callee: str) -> str:
    """같은 줄에 같은 호출이 둘 이상 있을 수 있으므로 열 위치까지 넣어 지점마다 유일하게 만든다."""
    return hashlib.sha256(f"{family}|{path}|{line}|{column}|{callee}".encode()).hexdigest()[:12]


@dataclass
class LedgerInputs:
    sources: list[SourceFile]
    skipped: list[dict[str, str]]
    contract: Contract
    contract_source: str
    config: IronLawsConfig
    findings: dict[tuple[str, str, int, int], list[str]]
    suppressed_lines: set[tuple[str, int, str]]
    changed_files: set[str] | None
    digests: dict[str, str]
    policy_changed: bool
    lookup_budget: int
    rules: list | None = None


def build_ledger(
    sources: list[SourceFile],
    skipped: list[dict[str, str]],
    contract: Contract,
    contract_source: str,
    config: IronLawsConfig,
    findings: dict[tuple[str, str, int, int], list[str]],
    suppressed_lines: set[tuple[str, int, str]],
    changed_files: set[str] | None,
    digests: dict[str, str],
    policy_changed: bool = False,
    lookup_budget: int = 2000,
    rules: list | None = None,
) -> CoverageLedger:
    """계약이 요구한 보안 관심 지점의 분석 근거 장부를 만든다. xfile 색인이 설정된 상태에서 호출한다.
    rules를 주면 그 인스턴스를 그대로 쓴다. 사용자 명세가 싱크를 더한 규칙 인스턴스라 장부가 그 싱크를 안다."""
    inputs = LedgerInputs(sources, skipped, contract, contract_source, config, findings, suppressed_lines,
                          changed_files, digests, policy_changed, lookup_budget, rules)
    ctx = _prepare_context(inputs)
    files, points = _collect_points(inputs, ctx)
    return _assemble_ledger(inputs, files, points)


def _rule_for(family: str, rule_cls: type[SinkRule], active: list | None) -> SinkRule:
    """활성 규칙 인스턴스를 그대로 쓰면 명세가 더한 싱크도 보인다. 없으면 기본 인스턴스를 만든다."""
    if active:
        for rule in active:
            if getattr(rule, "rule_id", None) == rule_cls.rule_id:
                return rule
    return rule_cls()


def _prepare_context(inputs: LedgerInputs) -> _Context:
    contract, config, sources, lookup_budget = inputs.contract, inputs.config, inputs.sources, inputs.lookup_budget
    ctx = _Context(contract=contract)
    for family, rule_cls in FAMILY_RULES.items():
        rule = _rule_for(family, rule_cls, inputs.rules)
        rule.configure(config)
        ctx.rules[family] = rule
        if inputs.rules:
            # 활성 인스턴스에는 사용자 명세가 더한 싱크가 기본 싱크 뒤에 붙는다. 그 부분만 따로 기억한다.
            ctx.spec_sinks[family] = list(rule.sinks)[len(rule_cls.sinks):]
    index = xfile.get_index()
    if index is not None:
        saved_cache = index._resolve_cache
        index._resolve_cache = {}
        index.budget = 10**9  # 호출자 지도를 만드는 일은 모든 호출을 한 번씩 해석하므로 상한을 두지 않는다
    try:
        ctx.callers = _build_callers(sources)
    finally:
        if index is not None:
            index._resolve_cache = saved_cache  # 지점별 해석은 설정한 상한 안에서 따로 해석한다
            index.budget = lookup_budget

    ctx.findings_by_line = _index_findings_by_line(inputs.findings)
    return ctx


def _index_findings_by_line(findings: dict[tuple[str, str, int, int], list[str]]) -> dict[tuple[str, str, int], list[tuple[int, list[str]]]]:
    """지적을 (규칙, 경로, 줄)별로 모은다. 지점마다 모든 지적을 훑지 않도록 하기 위한 색인이다."""
    index: dict[tuple[str, str, int], list[tuple[int, list[str]]]] = {}
    for (rule_id, path, line, column), ids in findings.items():
        index.setdefault((rule_id, path, line), []).append((column, ids))
    return index


def _collect_points(inputs: LedgerInputs, ctx: _Context) -> tuple[list[LedgerFile], list[InterestPoint]]:
    sources, skipped, contract = inputs.sources, inputs.skipped, inputs.contract
    findings, suppressed_lines, changed_files = inputs.findings, inputs.suppressed_lines, inputs.changed_files
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
                if resolve_any(src, call.callee, len(call.args)) and not ctx.is_spec_sink(family, call.callee):
                    continue  # 프로젝트가 정의한 함수의 호출은 라이브러리 관심 지점이 아니다. 그 함수 안의 호출이 지점으로 잡힌다. 사용자가 명세로 선언한 싱크는 예외다
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
                        linked_columns=verdict.linked_columns if state == PointState.EVIDENCE_MET.value else [],
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

    return files, points


def _assemble_ledger(inputs: LedgerInputs, files: list[LedgerFile], points: list[InterestPoint]) -> CoverageLedger:
    contract, config, changed_files = inputs.contract, inputs.config, inputs.changed_files
    digests, policy_changed, contract_source = inputs.digests, inputs.policy_changed, inputs.contract_source
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
    declared = [p for p in points if p.evidence_kind == "declared_sanitizer"]
    if declared:
        limitations.append(
            f"근거 충족 {len(declared)}건은 사용자가 선언한 정제 함수에 기대고 있다. 선언이 사실을 대신하지는 않으므로 그 함수를 확인해야 합니다."
        )
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
