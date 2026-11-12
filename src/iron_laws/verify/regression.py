"""
오철칙 결함을 구별하는 최소 회귀시험 (Python의 명령 실행·경로 접근·SQL 조립·서버 측 요청 위조(SSRF)·HTML 출력(XSS) 다섯 계열)
- 지적의 입력 유입·전파·싱크 근거에서 시험 후보(명세)를 제안한다. 제안은 검증 근거가 아니며, 사람이 입력·기대 결과·가짜 sink를
  확인해 `confirmed: true`로 바꾼 명세만 신뢰된 harness가 실행한다.
- 검증 순서: 수정 전 원본에서 결함 때문에 실패 → 수정 후 후보에서 통과하고 정상 대조군 유지 → 보안 수정을 되돌린 유효한 mutant에서 다시 실패
  → 세 번 반복해 같은 결과. 문법 오류·의존성 누락·환경 실패·정상 입력까지 막는 수정은 성공 근거가 아니다.
- 실제 셸·네트워크·작업영역 밖 파일 접근은 하지 않고 mock sink와 임시 폴더 경계에서 관측한다.
- 정적 분석기의 탐지 결과만 assertion으로 쓰는 시험은 만들지 않는다. 시험은 코드를 실제로 실행해 관측한 동작만 판정한다.
작성자: 최진호
작성일: 2026-10-04
"""

import json
import re
import secrets
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NamedTuple

from iron_laws.core.redaction import limit, redact_text
from iron_laws.verify.harness_template import HARNESS_SOURCE
from iron_laws.verify.receipt import CheckResult, CheckState
from iron_laws.verify.regression_spec import RegressionSpec, load_spec
from iron_laws.verify.runner import RunLimits, Runner
from iron_laws.verify.snapshot import scan_tree

HARNESS_DIR = "_iron_laws_harness"
RESULT_PREFIX = "IRON_LAWS_RESULT "
MAX_MUTANTS = 8
REPEATS = 3
STATEMENT_START_RE = re.compile(r"^\s*(?:def|class|if|elif|else|for|while|try|except|finally|with|@|import|from|return|raise|assert|pass|#)\b|^\s*(?:#|@)")
# ---------------------------------------------------------------------------
# harness 실행과 결과 해석
# ---------------------------------------------------------------------------


@dataclass
class HarnessRun:
    outcome: str  # defect_reproduced / passed / control_failed / error / not_run
    reason: str = ""
    sink_calls: int = 0
    run_status: str = ""
    limit_reached: bool = False
    notes: list[str] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)  # harness가 기록한 위험 호출(최대 20개)


def install_harness(directory: Path, spec: RegressionSpec) -> None:
    target = directory / HARNESS_DIR
    target.mkdir(exist_ok=True)
    (target / "run.py").write_text(HARNESS_SOURCE, encoding="utf-8")
    (target / "spec.json").write_text(json.dumps(spec.model_dump(mode="json"), ensure_ascii=False), encoding="utf-8")
    base = target / "base"
    base.mkdir(exist_ok=True)
    # 격리 환경의 비특권 사용자가 쓸 수 있는 곳은 harness의 임시 기준 폴더뿐이다. 프로젝트 파일은 읽기만 된다
    target.chmod(0o755)
    base.chmod(0o777)


def parse_result(excerpt_source: str, seal: str | None = None) -> dict[str, Any] | None:  # iron-laws: ignore[ARC-208] harness 결과 JSON과 검증 기록(Receipt)의 근거 JSON을 읽고 쓰는 경계라 dict를 그대로 다룬다
    """마지막 결과 줄을 읽는다. seal을 주면 그 봉인값이 붙은 줄만 harness가 쓴 결과로 받아들인다."""
    prefix = RESULT_PREFIX + (f"{seal} " if seal is not None else "")
    for line in reversed(excerpt_source.splitlines()):
        if line.startswith(prefix):
            try:
                parsed = json.loads(line[len(prefix) :])
            except json.JSONDecodeError:  # iron-laws: ignore[IL-301] 해석하지 못한 결과 줄은 None으로 알리고 호출부가 '결과를 내지 못했다' 오류로 기록한다
                return None
            if not isinstance(parsed, dict):  # iron-laws: ignore[IL-307] 결과 줄 형식이 아니면 None으로 알리고 호출부가 결과를 내지 못했다는 오류로 기록한다
                return None
            if parsed.get("outcome") not in ("passed", "defect_reproduced", "control_failed", "error"):  # iron-laws: ignore[IL-307] 결과 줄 형식이 아니면 None으로 알리고 호출부가 결과를 내지 못했다는 오류로 기록한다
                return None
            if not isinstance(parsed.get("reason", ""), str):  # iron-laws: ignore[IL-307] 결과 줄 형식이 아니면 None으로 알리고 호출부가 결과를 내지 못했다는 오류로 기록한다
                return None
            count = parsed.get("sink_calls", 0)
            if type(count) is not int or count < 0:  # iron-laws: ignore[IL-307] 결과 줄 형식이 아니면 None으로 알리고 호출부가 결과를 내지 못했다는 오류로 기록한다
                return None
            return parsed
    return None


def run_harness(runner: Runner, directory: Path, mode: str, limits: RunLimits) -> HarnessRun:
    command = ["python", "-B", f"{HARNESS_DIR}/run.py", f"{HARNESS_DIR}/spec.json", mode]
    base = directory / HARNESS_DIR / "base"
    seal, probe = secrets.token_hex(16), secrets.token_hex(8)
    if base.is_dir():
        (base / "seal").write_text(seal, encoding="utf-8")
        (base / "probe").write_text(probe, encoding="utf-8")
    canary = base / f"canary_{probe}"
    try:
        result = runner.run(directory, command, limits, [["python", "-B", f"{HARNESS_DIR}/run.py"]])
    finally:
        bypassed = canary.exists()
        for leftover in (base / "seal", base / "probe", canary):
            leftover.unlink(missing_ok=True)
    if result.status in ("isolation_unavailable", "not_allowed", "infrastructure_error"):
        return HarnessRun("not_run", result.notes[0] if result.notes else result.status, run_status=result.status, notes=result.notes)
    if bypassed and mode.startswith("attack"):
        return HarnessRun("defect_reproduced", "기록 장치를 거치지 않은 실제 셸이 공격 입력을 실행했다(카나리아 파일이 생겼다)", run_status=result.status)
    if result.limit_reached:
        return HarnessRun("not_run", "시간·출력·자원 상한에 도달했다", run_status=result.status, limit_reached=True, notes=result.notes)
    parsed = parse_result(result.excerpt, seal)
    if parsed is None:
        return HarnessRun("error", "harness가 봉인된 결과를 내지 못했다(문법 오류·형식 오류·충돌, 또는 후보 코드가 결과를 흉내 냈거나 출력을 막았다)", run_status=result.status)
    calls = [c for c in parsed.get("calls", []) if isinstance(c, dict)] if isinstance(parsed.get("calls"), list) else []
    return HarnessRun(parsed["outcome"], limit(redact_text(parsed.get("reason", "")), 500), parsed.get("sink_calls", 0), run_status=result.status, calls=calls)


# ---------------------------------------------------------------------------
# mutant: 보안 수정을 되돌린 유효한 변형
# ---------------------------------------------------------------------------


@dataclass
class Mutant:
    kind: str  # hunk_reverse / line_delete
    description: str
    directory: Path
    valid: bool = True
    problem: str = ""


def split_hunks(patch_text: str, target_file: str) -> list[tuple[str, str]]:
    """target_file에 대한 patch를 hunk 하나짜리 patch로 쪼갠다. (설명, patch 본문) 목록. `diff --git` 형식과 일반 unified diff를 모두 받는다."""
    sections = re.split(r"(?m)^(?=diff --git |--- (?:a/|/dev/null))", patch_text)
    hunks: list[tuple[str, str]] = []
    seen: set[str] = set()
    for section in sections:
        if not section.strip():
            continue
        lines = section.splitlines(keepends=True)
        plus = next((line for line in lines if line.startswith("+++ ")), "")
        header_text = "".join(lines[:4])
        if f"b/{target_file}" not in plus and f"b/{target_file}" not in header_text:
            continue
        first_hunk = next((i for i, line in enumerate(lines) if line.startswith("@@")), None)
        if first_hunk is None:
            continue
        header = "".join(lines[:first_hunk])
        key = header + "".join(lines[first_hunk:])
        if key in seen:
            continue
        seen.add(key)
        current: list[str] = []
        for line in lines[first_hunk:]:
            if line.startswith("@@") and current:
                hunks.append((current[0].strip(), header + "".join(current)))
                current = []
            current.append(line)
        if current:
            hunks.append((current[0].strip(), header + "".join(current)))
    return hunks


def _python_compiles(path: Path) -> tuple[bool, str]:
    try:
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
    except SyntaxError as e:
        return False, f"문법 오류: {e.msg} (줄 {e.lineno})"
    return True, ""


def build_mutants(candidate: Path, patch_text: str, target_file: str, work: Path) -> list[Mutant]:
    mutants: list[Mutant] = []
    # (a) 수정 hunk를 하나씩 되돌린다
    for index, (description, hunk_patch) in enumerate(split_hunks(patch_text, target_file)):
        if len(mutants) >= MAX_MUTANTS:
            break
        directory = work / f"mutant-hunk-{index}"
        shutil.copytree(candidate, directory, symlinks=True)
        patch_file = work / f"mutant-hunk-{index}.diff"
        patch_file.write_text(hunk_patch, encoding="utf-8")
        applied = subprocess.run(["git", "apply", "-R", "--whitespace=nowarn", str(patch_file)], cwd=directory, capture_output=True, text=True, timeout=60)  # noqa: S603, S607
        mutant = Mutant("hunk_reverse", f"수정 {description}를 되돌림", directory)
        if applied.returncode != 0:
            mutant.valid, mutant.problem = False, "되돌리는 patch를 적용하지 못했다"
        else:
            ok, problem = _python_compiles(directory / target_file)
            mutant.valid, mutant.problem = ok, problem
        mutants.append(mutant)
    # (b) patch가 추가한 단순 문장을 하나씩 지운다(pass로 대체)
    added: list[str] = []
    for _desc, hunk_patch in split_hunks(patch_text, target_file):
        for line in hunk_patch.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                text = line[1:]
                if text.strip() and not STATEMENT_START_RE.match(text) and not text.rstrip().endswith(":"):
                    added.append(text)
    target_text = (candidate / target_file).read_text(encoding="utf-8")
    for index, text in enumerate(added):
        if len(mutants) >= MAX_MUTANTS:
            break
        if text not in target_text:
            continue
        directory = work / f"mutant-line-{index}"
        shutil.copytree(candidate, directory, symlinks=True)
        indent = text[: len(text) - len(text.lstrip())]
        mutated = target_text.replace(text, f"{indent}pass", 1)
        (directory / target_file).write_text(mutated, encoding="utf-8")
        ok, problem = _python_compiles(directory / target_file)
        mutants.append(Mutant("line_delete", f"추가한 문장 `{text.strip()[:60]}`을 지움", directory, ok, problem))
    return mutants


# ---------------------------------------------------------------------------
# 검증: 원본 실패 → 후보 통과 → mutant 재실패 → 반복 일치
# ---------------------------------------------------------------------------


@dataclass
class _VariantOutcome:
    evidence: dict[str, Any]
    result: tuple[CheckState, str] | None = None  # (결과, 사유). 판정을 끝내야 하면 채운다


class OriginalRuns(NamedTuple):
    attacks: list[HarnessRun]
    control: HarnessRun
    variants: dict[int, HarnessRun]


@dataclass
class _Session:
    """회귀시험 한 번에 같이 쓰는 명세·실행기·실행 상한"""

    spec: RegressionSpec
    runner: Runner
    limits: RunLimits

    def run(self, directory: Path, mode: str) -> HarnessRun:
        return run_harness(self.runner, directory, mode, self.limits)

    def many(self, directory: Path, mode: str, times: int) -> list[HarnessRun]:
        return [self.run(directory, mode) for _ in range(times)]


@dataclass
class _OriginalMemo:
    """같은 원본·같은 명세의 원본 실행 결과. 여러 후보를 비교할 때 원본 단계를 다시 돌리지 않으려고 둔다."""

    store: dict[str, OriginalRuns] | None
    key: str = ""
    cached: OriginalRuns | None = None


def _variant_phase(session: _Session, original: Path, candidate: Path, memo: _OriginalMemo) -> _VariantOutcome | None:
    """명세의 변형 입력마다 원본에서 결함이 재현되는지 보고, 재현되는 입력이 후보에서도 재현되면 실패로 본다.
    원본에서 재현되지 않는 입력도 후보에서는 돌린다. '../'를 한 번만 지우는 수정처럼 수정이 원본에 없던 우회 입력을 만들 수 있다.
    그런 입력이 후보에서 재현되면 실패이고, 재현되지 않으면 이 결함에 적용되지 않는 입력으로 남긴다."""
    spec = session.spec
    if not spec.input.variants:
        return None
    original_runs: dict[int, HarnessRun] = memo.cached.variants if memo.cached else {}
    checked: list[int] = []
    inapplicable: list[int] = []
    for index in range(1, len(spec.input.variants) + 1):
        if index not in original_runs:
            original_runs[index] = session.run(original, f"attack:{index}")
        if original_runs[index].outcome == "not_run":
            return _VariantOutcome({"checked": checked, "inapplicable": inapplicable}, ("unknown", f"변형 입력을 실행하지 못했다: {original_runs[index].reason}"))
    if memo.store is not None and memo.cached is not None:
        memo.store[memo.key] = OriginalRuns(memo.cached.attacks, memo.cached.control, original_runs)
    for index, run in original_runs.items():
        candidate_run = session.run(candidate, f"attack:{index}")
        if run.outcome != "defect_reproduced":
            if candidate_run.outcome == "defect_reproduced":
                return _VariantOutcome(
                    {"checked": checked, "inapplicable": inapplicable, "failed": index},
                    ("fail", f"후보가 원본에서는 결함이 나지 않던 입력({spec.input.variants[index - 1]!r})에서 결함을 만든다(입력 일부만 지우는 필터가 우회 입력을 만든다)"),
                )
            inapplicable.append(index)
            continue
        if candidate_run.outcome == "not_run":
            return _VariantOutcome({"checked": checked, "inapplicable": inapplicable}, ("unknown", f"후보에서 변형 입력을 실행하지 못했다: {candidate_run.reason}"))
        if candidate_run.outcome == "defect_reproduced":
            return _VariantOutcome(
                {"checked": checked, "inapplicable": inapplicable, "failed": index},
                ("fail", f"후보가 시험 입력은 막지만 같은 결함을 건드리는 다른 입력({spec.input.variants[index - 1]!r})에서는 결함이 재현된다(수정이 특정 입력에만 통한다)"),
            )
        if candidate_run.outcome == "error":
            return _VariantOutcome({"checked": checked, "inapplicable": inapplicable}, ("unknown", f"후보에서 변형 입력 시험이 실행되지 않았다: {candidate_run.reason}"))
        checked.append(index)
    return _VariantOutcome({"checked": checked, "inapplicable": inapplicable, "total": len(spec.input.variants)})


def _check(result: CheckState, reason: str = "", executed: bool = True, **evidence: Any) -> CheckResult:  # iron-laws: ignore[TYP-302] 검사마다 다른 근거 값을 그대로 담는 키워드 인자다
    return CheckResult(id="regression_test", title="결함을 구별하는 회귀시험(원본 실패·후보 통과·mutant 재실패)", result=result, reason=reason, required=True, executed=executed, evidence=evidence)


BEHAVIOR_KEYS = ("api", "command", "interpreted", "path", "mode", "sql", "params", "method", "url", "html")


def benign_behavior(original: list[dict[str, Any]], candidate: list[dict[str, Any]]) -> dict[str, Any]:
    """정상 입력에서 원본과 수정본이 위험 호출에 넘긴 내용(호출 순서·명령·경로·SQL)을 비교한다.
    인자 배열로 바꾸는 수정처럼 안전해지면서 모양이 달라지는 경우도 다름으로 나오므로 기본은 표시만 한다."""
    def shape(calls):
        return [tuple((k, str(c.get(k))) for k in BEHAVIOR_KEYS if k in c) for c in calls]

    before, after = shape(original), shape(candidate)
    differences = []
    for index in range(max(len(before), len(after))):
        left = dict(before[index]) if index < len(before) else None
        right = dict(after[index]) if index < len(after) else None
        if left != right:
            differences.append(f"{index + 1}번째 호출: 원본 {left} / 수정본 {right}")
    return {"same": not differences, "differences": [limit(redact_text(d), 300) for d in differences[:10]], "original_calls": len(before), "candidate_calls": len(after)}


class RegressionDirs(NamedTuple):
    """회귀시험 한 번이 쓰는 폴더: 원본 사본, patch를 적용한 후보 사본, mutant를 만들 작업 폴더"""

    original: Path
    candidate: Path
    work: Path


def run_regression_check(
    spec_path: Path,
    dirs: RegressionDirs,
    runner: Runner,
    limits: RunLimits,
    patch_path: Path | None = None,
    bypass_count: int = 0,
    original_memo: dict[str, OriginalRuns] | None = None,
) -> CheckResult:
    original, candidate, work = dirs
    spec = load_spec(spec_path)
    if not spec.confirmed:
        return _check("unknown", "회귀시험 명세가 아직 검토·확정되지 않았다(입력·기대 결과·가짜 sink를 확인한 뒤 confirmed: true). 제안은 검증 근거가 아니다", executed=False, finding=spec.finding)
    for directory in (original, candidate):
        install_harness(directory, spec)
    session = _Session(spec, runner, limits)
    evidence: dict[str, Any] = {"finding": spec.finding, "family": spec.family, "repeats": REPEATS, "fake_sink": spec.fake_sink}
    memo = _OriginalMemo(original_memo)
    if original_memo is not None:
        memo.key = scan_tree(original).digest + json.dumps(spec.model_dump(mode="json"), sort_keys=True)
        memo.cached = original_memo.get(memo.key)
    control = _original_phase(session, original, memo, evidence)
    if isinstance(control, CheckResult):
        return control
    failed = _candidate_phase(session, candidate, control, evidence)
    if failed is not None:
        return failed
    # 시험 입력은 막지만 다른 입력에는 뚫리는 수정을 가려낸다(기본 입력이 통과한 뒤에만 실행한다)
    variants = _variant_phase(session, original, candidate, memo)
    if variants is not None:
        evidence["variants"] = variants.evidence
        if variants.result is not None:
            return _check(variants.result[0], variants.result[1], **evidence)
    return _mutant_phase(session, candidate, patch_path, work, evidence, bypass_count)


def _original_phase(session: _Session, original: Path, memo: _OriginalMemo, evidence: dict[str, Any]) -> HarnessRun | CheckResult:
    """원본에서 공격 입력이 세 번 모두 결함을 재현하고 정상 입력은 통과하는지 본다. 통과하면 원본의 정상 입력 실행 결과를 돌려준다."""
    original_attack = memo.cached.attacks if memo.cached else session.many(original, "attack", REPEATS)
    evidence["original_attack"] = [r.outcome for r in original_attack]
    not_run = next((r for r in original_attack if r.outcome == "not_run"), None)
    if not_run is not None:
        return _check("unknown", f"격리 실행을 하지 못했다: {not_run.reason}", executed=False, **evidence)
    if len({r.outcome for r in original_attack}) != 1:
        return _check("unknown", "같은 시험을 세 번 실행했는데 결과가 달라 신뢰할 수 없다(flaky)", **evidence)
    outcome = original_attack[0].outcome
    if outcome == "error":
        return _check("unknown", f"원본에서 시험이 실행되지 않았다. 문법 오류·의존성 누락·환경 실패는 결함 재현으로 세지 않는다: {original_attack[0].reason}", **evidence)
    if outcome != "defect_reproduced":
        return _check("unknown", "원본에서 결함이 재현되지 않았다. 이 명세는 시험 후보로 남긴다(입력·기대 결과를 다시 검토하십시오)", **evidence)
    evidence["original_failure_reason"] = original_attack[0].reason
    original_control = memo.cached.control if memo.cached else session.run(original, "benign")
    if memo.store is not None and memo.cached is None and original_control.outcome != "not_run":
        memo.cached = memo.store[memo.key] = OriginalRuns(original_attack, original_control, {})
    evidence["original_control"] = original_control.outcome
    if original_control.outcome != "passed":
        return _check("unknown", f"원본에서 정상 입력이 싱크에 닿지 않아 시험이 정상 동작을 구별하지 못한다: {original_control.reason}", **evidence)
    return original_control


def _candidate_phase(session: _Session, candidate: Path, original_control: HarnessRun, evidence: dict[str, Any]) -> CheckResult | None:
    """후보에서 공격 입력은 막히고 정상 입력은 통과하는지 본다. 판정을 끝내야 하면 그 결과를, 다음 단계로 가면 None을 돌려준다."""
    spec = session.spec
    candidate_attack = session.many(candidate, "attack", REPEATS)
    candidate_control = session.many(candidate, "benign", REPEATS)
    evidence["candidate_attack"] = [r.outcome for r in candidate_attack]
    evidence["candidate_control"] = [r.outcome for r in candidate_control]
    if any(r.outcome == "not_run" for r in candidate_attack + candidate_control):
        return _check("unknown", "후보 실행이 상한·격리 문제로 끝나지 않았다", executed=False, **evidence)
    if len({r.outcome for r in candidate_attack}) != 1 or len({r.outcome for r in candidate_control}) != 1:
        return _check("unknown", "후보에서 같은 시험의 결과가 반복마다 달라 신뢰할 수 없다(flaky)", **evidence)
    if candidate_attack[0].outcome == "defect_reproduced":
        return _check("fail", f"후보에서도 결함이 재현된다: {candidate_attack[0].reason}", **evidence)
    if candidate_attack[0].outcome == "error":
        return _check("unknown", f"후보에서 시험이 실행되지 않았다(문법 오류·충돌·허용되지 않은 예외): {candidate_attack[0].reason}", **evidence)
    if candidate_control[0].outcome != "passed":
        return _check("fail", f"수정이 정상 입력까지 막는다(위험한 기능을 전부 막는 것은 정답이 아니다): {candidate_control[0].reason}", **evidence)
    behavior = benign_behavior(original_control.calls, candidate_control[0].calls)
    evidence["benign_behavior"] = behavior
    if not behavior["same"] and spec.expect.benign_behavior == "require":
        return _check("fail", "정상 입력에서 위험 호출의 내용이 원본과 달라졌다(명세가 동작 보존을 요구한다): " + "; ".join(behavior["differences"][:3]), **evidence)
    return None


def _mutant_phase(session: _Session, candidate: Path, patch_path: Path | None, work: Path, evidence: dict[str, Any], bypass_count: int) -> CheckResult:
    """보안 수정을 되돌린 mutant에서 시험이 다시 실패하는지 본다. 하나라도 다시 실패해야 시험이 수정을 구별한다고 인정한다."""
    spec = session.spec
    mutants: list[Mutant] = []
    if patch_path is not None:
        mutants = build_mutants(candidate, patch_path.read_text(encoding="utf-8", errors="replace"), spec.target.file, work)
    killed, survived, invalid = [], [], []
    for mutant in mutants:
        if not mutant.valid:
            invalid.append({"description": mutant.description, "problem": mutant.problem})
            continue
        install_harness(mutant.directory, spec)
        run = session.run(mutant.directory, "attack")
        if run.outcome == "defect_reproduced":
            killed.append(mutant.description)
        elif run.outcome == "passed":
            survived.append(mutant.description)
        else:
            invalid.append({"description": mutant.description, "problem": f"{run.outcome}: {run.reason}"[:140]})
    evidence["mutants"] = {"killed": killed, "survived": survived, "invalid": invalid, "total": len(mutants)}
    if not killed:
        return _check(
            "unknown",
            "보안 수정을 되돌린 유효한 mutant에서 시험이 다시 실패하는지 확인하지 못했다(유효한 mutant가 없거나 모두 살아남았다). 이 시험이 수정을 구별하는지 알 수 없다",
            **evidence,
        )
    reason = ""
    if survived:
        reason = f"mutant {len(survived)}개가 살아남았다(수정과 무관하거나 기능적으로 동등한 변경일 수 있어 별도 검토 필요)"
    if bypass_count:
        reason = (reason + "; " if reason else "") + "우회 변경이 함께 있어 종합 판정은 별도 항목을 따른다"
    return _check("pass", reason, **evidence)
