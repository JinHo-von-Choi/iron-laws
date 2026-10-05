"""
오철칙 결함을 구별하는 최소 회귀시험 (Python의 명령 실행·경로 접근·SQL 조립 세 계열)
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
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from iron_laws.core.config import ConfigError
from iron_laws.core.models import Violation
from iron_laws.engine.ast_tools import enclosing_function, iter_functions
from iron_laws.engine.source import SourceFile
from iron_laws.verify.harness_template import HARNESS_SOURCE
from iron_laws.verify.receipt import CheckResult
from iron_laws.verify.runner import RunLimits, Runner
from iron_laws.verify.snapshot import scan_tree

HARNESS_DIR = "_iron_laws_harness"
RESULT_PREFIX = "IRON_LAWS_RESULT "
MAX_MUTANTS = 8
REPEATS = 3
FAMILY_OF_RULE = {"IL-504": "command", "IL-502": "path", "IL-513": "path", "IL-501": "sql"}
PAYLOADS = {
    "command": ("x; touch IRON_LAWS_PWNED", "readme.txt"),
    "path": ("../../etc/passwd", "report.txt"),
    "sql": ("' OR '1'='1", "alice"),
}
# 수정이 시험의 입력 하나만 막는지 보려고 같은 결함을 건드리는 다른 입력을 함께 시험한다(명세에 적혀 사람이 확인한다).
VARIANT_PAYLOADS = {
    "command": ("x && touch IRON_LAWS_PWNED", "x | touch IRON_LAWS_PWNED", "$(touch IRON_LAWS_PWNED)", "`touch IRON_LAWS_PWNED`"),
    "path": ("/etc/passwd", "sub/../../../../../etc/passwd", "../../../../../../../../etc/passwd"),  # 허용 폴더가 어디든 밖으로 나가는 입력만 쓴다
    "sql": ("1 OR 1=1", "\" OR \"1\"=\"1", "'; DROP TABLE t--", "' UNION SELECT NULL--"),
}
CURSOR_NAMES = {"cur", "cursor", "c"}
CONNECTION_NAMES = {"conn", "connection", "db", "database", "con"}
REQUEST_RE = re.compile(r"\brequest\.(?:args|form|values|json|cookies|headers|get_json|data)\b")
STATEMENT_START_RE = re.compile(r"^\s*(?:def|class|if|elif|else|for|while|try|except|finally|with|@|import|from|return|raise|assert|pass|#)\b|^\s*(?:#|@)")


class SourceSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["param", "request"]
    param: str = ""  # kind=param: 입력이 들어오는 매개변수 이름


class TargetSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    module: str
    function: str
    file: str


class InputSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload: str = Field(..., min_length=1, description="결함을 건드리는 입력")
    benign: str = Field(..., min_length=1, description="정상 대조군 입력")
    variants: list[str] = Field(default_factory=list, description="같은 결함을 건드리는 다른 입력. 수정이 시험 입력 하나만 막는 것을 가려낸다")


class ExpectSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base: str = Field(default="", description="path 계열: 접근해도 되는 폴더. 비우면 임시 기준 폴더")
    summary: str = Field(default="", description="사람이 읽는 기대 결과")


class RegressionSpec(BaseModel):
    """검토 가능한 회귀시험 명세. 입력·기대 결과·가짜 sink가 모두 드러나 있다."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    family: Literal["command", "path", "sql"]
    finding: str = ""
    target: TargetSpec
    source: SourceSpec
    input: InputSpec
    expect: ExpectSpec = Field(default_factory=ExpectSpec)
    call_args: dict[str, Any] = Field(default_factory=dict)
    fake_globals: dict[str, Any] = Field(default_factory=dict)
    allowed_exceptions: list[str] = Field(default_factory=lambda: ["ValueError", "PermissionError", "RuntimeError"])
    fake_sink: list[str] = Field(default_factory=list, description="가짜로 바꾸는 API. 사람이 확인할 목록이며 harness가 계열별로 설치한다")
    review_notes: list[str] = Field(default_factory=list)
    confirmed: bool = False


FAKE_SINKS = {
    "command": ["os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.getoutput", "subprocess.Popen"],
    "path": ["builtins.open", "io.open", "pathlib.Path.open/read_text/read_bytes/write_text/write_bytes", "os.remove/unlink/listdir/makedirs/mkdir/rmdir/stat"],
    "sql": ["sqlite3.connect", "주입된 커서·연결 객체(execute/executemany/executescript 기록)"],
}


def load_spec(path: Path) -> RegressionSpec:
    if not path.is_file():
        raise ConfigError(f"회귀시험 명세 파일이 없습니다: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return RegressionSpec(**(data or {}))
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValidationError, TypeError) as e:
        raise ConfigError(f"회귀시험 명세를 읽을 수 없습니다: {path} ({e})") from e


def dump_spec(spec: RegressionSpec) -> str:
    return yaml.safe_dump(spec.model_dump(mode="json"), allow_unicode=True, sort_keys=False)


# ---------------------------------------------------------------------------
# 제안: 지적의 근거에서 시험 후보를 만든다 (지원하지 못하는 모양은 이유와 함께 거절한다)
# ---------------------------------------------------------------------------


@dataclass
class Proposal:
    spec: RegressionSpec | None
    reason: str = ""


def _module_name(rel: str) -> str:
    parts = list(Path(rel).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _literal_base(call_text: str) -> str:
    """싱크 호출 식에 적힌 절대 경로 문자열에서 접근 허용 폴더를 추정한다.
    '/srv/uploads/' + name → /srv/uploads, f'/data/{name}' → /data. 추정이 틀릴 수 있어 사람이 확인하도록 명세에 남긴다."""
    for literal in re.findall(r"""['"](/[^'"]*)['"]""", call_text):
        prefix = re.split(r"[{%]", literal, maxsplit=1)[0]
        if not prefix:
            continue
        return (prefix.rstrip("/") if prefix.endswith("/") else str(Path(prefix).parent)) or "/"
    return ""


def propose_spec(root: Path, violation: Violation) -> Proposal:
    family = FAMILY_OF_RULE.get(violation.rule_id)
    if family is None:
        return Proposal(None, f"{violation.rule_id}는 회귀시험을 지원하는 계열(명령 실행·경로 접근·SQL 조립)이 아니다")
    rel = violation.file_path.as_posix()
    if not rel.endswith(".py"):
        return Proposal(None, "Python 파일만 지원한다")
    path = root / rel
    if not path.is_file():
        return Proposal(None, f"파일을 읽을 수 없다: {rel}")
    src = SourceFile(Path(rel), path.read_text(encoding="utf-8", errors="replace"))
    if src.root is None:
        return Proposal(None, "구문 분석하지 못했다")
    line_start = None
    node = None
    for n in src.nodes:
        if n.start_point[0] + 1 == violation.line_number and n.type in ("call", "expression_statement"):
            node = n
            break
    if node is None:
        return Proposal(None, "지적된 줄의 호출을 찾지 못했다")
    fn_node = enclosing_function(node, src.lang)
    if fn_node is None:
        return Proposal(None, "함수 밖의 코드는 지원하지 않는다(모듈 수준 실행)")
    func = next((f for f in iter_functions(src) if f.node.id == fn_node.id), None)
    if func is None:
        return Proposal(None, "함수를 해석하지 못했다")
    parent = fn_node.parent
    while parent is not None:
        if parent.type == "class_definition":
            return Proposal(None, "클래스의 메서드는 지원하지 않는다(객체 생성 조건을 알 수 없다)")
        parent = parent.parent
    if src.text_of(fn_node).lstrip().startswith("async def"):
        return Proposal(None, "async 함수는 지원하지 않는다")
    if fn_node.parent is not None and fn_node.parent.type == "decorated_definition":
        decorators = " ".join(src.text_of(d) for d in fn_node.parent.named_children if d.type == "decorator")
        if re.search(r"fastapi|django|@(?:app|router)\.(?:get|post)\(.*\bDepends\b", decorators):
            return Proposal(None, "Flask 계열이 아닌 프레임워크의 핸들러는 지원하지 않는다")
    text = src.text_of(fn_node)
    if re.search(r"\bdjango\b|\brequest\.(?:GET|POST)\b|\bfastapi\b", src.text):
        return Proposal(None, "Flask 계열이 아닌 요청 객체(Django·FastAPI)는 지원하지 않는다")
    params = [src.text_of(p).split(":")[0].split("=")[0].strip() for p in func.params]
    payload, benign = PAYLOADS[family]
    if REQUEST_RE.search(text):
        source = SourceSpec(kind="request")
    else:
        candidate = None
        sink_text = src.text_of(node)
        for name in params:
            if name in CURSOR_NAMES | CONNECTION_NAMES or name in ("self", "cls"):
                continue
            if re.search(rf"\b{re.escape(name)}\b", text) and (candidate is None or re.search(rf"\b{re.escape(name)}\b", sink_text)):
                candidate = name
        if candidate is None:
            return Proposal(None, "입력이 들어오는 요청 값이나 매개변수를 찾지 못했다")
        source = SourceSpec(kind="param", param=candidate)
    call_args: dict[str, Any] = {}
    notes = [
        f"입력({payload!r})이 {'요청 값' if source.kind == 'request' else '매개변수 ' + source.param}으로 들어간다고 가정한다. 실제 호출 방식과 맞는지 확인하십시오.",
        "정상 대조군 입력이 실제 업무에서 쓰는 값과 비슷한지 확인하십시오. 수정이 정상 기능까지 막으면 통과하지 못합니다.",
    ]
    base = ""
    if family == "sql":
        for name in params:
            if name in CURSOR_NAMES:
                call_args[name] = "$cursor"
            elif name in CONNECTION_NAMES:
                call_args[name] = "$connection"
        if not call_args:
            return Proposal(None, "SQL을 실행하는 커서·연결 객체를 매개변수로 주입할 수 없다(전역 연결 등)")
        notes.append("커서·연결 객체는 호출을 기록하는 가짜 객체로 바꿔 넣는다. 실제 DB에는 접속하지 않는다.")
    if family == "path":
        base = _literal_base(src.text_of(node))
        notes.append(f"접근해도 되는 폴더(expect.base)를 {'`' + base + '`' if base else '임시 기준 폴더'}로 가정한다. 맞는지 확인하십시오.")
    if family == "command":
        notes.append("실제 셸은 실행하지 않는다. os.system·subprocess 호출은 기록만 하며, 셸이 해석하는 문자열에 입력이 그대로 들어가면 결함으로 본다.")
    for name in params:
        if name not in call_args and not (source.kind == "param" and name == source.param) and name not in ("self", "cls"):
            notes.append(f"매개변수 {name}는 None으로 호출한다. 다른 값이 필요하면 call_args에 적으십시오.")
    expect_summary = {
        "command": "입력이 셸이 해석하는 명령 문자열에 그대로 들어가면 안 된다(인자 배열로 넘기거나 입력을 검증해야 한다).",
        "path": "접근한 경로가 허용 폴더 밖으로 나가면 안 된다(정규화 뒤 허용 폴더 안인지 확인해야 한다).",
        "sql": "입력이 SQL 문자열에 들어가면 안 된다(파라미터 바인딩을 써야 한다).",
    }[family]
    spec = RegressionSpec(
        family=family,  # type: ignore[arg-type]
        finding=f"{violation.rule_id}@{rel}:{violation.line_number}",
        target=TargetSpec(module=_module_name(rel), function=func.name, file=rel),
        source=source,
        input=InputSpec(payload=payload, benign=benign, variants=list(VARIANT_PAYLOADS[family])),
        expect=ExpectSpec(base=base, summary=expect_summary),
        call_args=call_args,
        fake_sink=FAKE_SINKS[family],
        review_notes=notes,
        confirmed=False,
    )
    del line_start
    return Proposal(spec)


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


def parse_result(excerpt_source: str) -> dict[str, Any] | None:
    for line in reversed(excerpt_source.splitlines()):
        if line.startswith(RESULT_PREFIX):
            try:
                return json.loads(line[len(RESULT_PREFIX) :])
            except json.JSONDecodeError:  # iron-laws: ignore[IL-301] 해석하지 못한 결과 줄은 None으로 알리고 호출부가 '결과를 내지 못했다' 오류로 기록한다
                return None
    return None


def run_harness(runner: Runner, directory: Path, mode: str, limits: RunLimits) -> HarnessRun:
    command = ["python", "-B", f"{HARNESS_DIR}/run.py", f"{HARNESS_DIR}/spec.json", mode]
    result = runner.run(directory, command, limits, [["python", "-B", f"{HARNESS_DIR}/run.py"]])
    if result.status in ("isolation_unavailable", "not_allowed", "infrastructure_error"):
        return HarnessRun("not_run", result.notes[0] if result.notes else result.status, run_status=result.status, notes=result.notes)
    if result.limit_reached:
        return HarnessRun("not_run", "시간·출력·자원 상한에 도달했다", run_status=result.status, limit_reached=True, notes=result.notes)
    parsed = parse_result(result.excerpt)
    if parsed is None:
        return HarnessRun("error", "harness가 결과를 내지 못했다(문법 오류·충돌 가능성): " + (result.excerpt.splitlines()[-1][:120] if result.excerpt else ""), run_status=result.status)
    return HarnessRun(parsed.get("outcome", "error"), parsed.get("reason", ""), int(parsed.get("sink_calls", 0) or 0), run_status=result.status)


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
    result: tuple[str, str] | None = None  # (결과, 사유). 판정을 끝내야 하면 채운다


def _variant_phase(
    spec: RegressionSpec,
    runner: Runner,
    original: Path,
    candidate: Path,
    limits: RunLimits,
    cached: Any,
    original_memo: dict[str, Any] | None,
    memo_key: str,
) -> _VariantOutcome | None:
    """명세의 변형 입력마다 원본에서 결함이 재현되는지 보고, 재현되는 입력이 후보에서도 재현되면 실패로 본다.
    원본에서 재현되지 않는 입력은 이 결함에 적용되지 않는 입력이므로 건너뛰고 그 사실을 남긴다."""
    if not spec.input.variants:
        return None
    original_runs: dict[int, HarnessRun] = cached[2] if cached and len(cached) > 2 else {}
    checked: list[int] = []
    inapplicable: list[int] = []
    for index in range(1, len(spec.input.variants) + 1):
        if index not in original_runs:
            original_runs[index] = run_harness(runner, original, f"attack:{index}", limits)
        if original_runs[index].outcome == "not_run":
            return _VariantOutcome({"checked": checked, "inapplicable": inapplicable}, ("unknown", f"변형 입력을 실행하지 못했다: {original_runs[index].reason}"))
    if original_memo is not None and cached is not None:
        original_memo[memo_key] = (cached[0], cached[1], original_runs)
    for index, run in original_runs.items():
        if run.outcome != "defect_reproduced":
            inapplicable.append(index)
            continue
        candidate_run = run_harness(runner, candidate, f"attack:{index}", limits)
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


def _check(result: str, reason: str = "", executed: bool = True, **evidence: Any) -> CheckResult:
    return CheckResult(id="regression_test", title="결함을 구별하는 회귀시험(원본 실패·후보 통과·mutant 재실패)", result=result, reason=reason, required=True, executed=executed, evidence=evidence)  # type: ignore[arg-type]


def run_regression_check(
    spec_path: Path,
    original: Path,
    candidate: Path,
    work: Path,
    runner: Runner,
    limits: RunLimits,
    allowed: list[list[str]],
    patch_path: Path | None = None,
    bypass_count: int = 0,
    original_memo: dict[str, Any] | None = None,
) -> CheckResult:
    spec = load_spec(spec_path)
    if not spec.confirmed:
        return _check("unknown", "회귀시험 명세가 아직 검토·확정되지 않았다(입력·기대 결과·가짜 sink를 확인한 뒤 confirmed: true). 제안은 검증 근거가 아니다", executed=False, finding=spec.finding)
    for directory in (original, candidate):
        install_harness(directory, spec)
    evidence: dict[str, Any] = {"finding": spec.finding, "family": spec.family, "repeats": REPEATS, "fake_sink": spec.fake_sink}

    def many(directory: Path, mode: str, times: int) -> list[HarnessRun]:
        return [run_harness(runner, directory, mode, limits) for _ in range(times)]

    # 같은 원본·같은 명세의 결과는 후보가 달라도 같으므로, 여러 후보를 비교할 때는 원본 단계를 다시 돌리지 않고 재사용할 수 있다.
    memo_key = ""
    if original_memo is not None:
        memo_key = scan_tree(original).digest + json.dumps(spec.model_dump(mode="json"), sort_keys=True)
    cached = original_memo.get(memo_key) if original_memo is not None else None
    original_attack = cached[0] if cached else many(original, "attack", REPEATS)
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
    original_control = cached[1] if cached else run_harness(runner, original, "benign", limits)
    if original_memo is not None and cached is None and original_control.outcome != "not_run":
        original_memo[memo_key] = (original_attack, original_control, {})
        cached = original_memo[memo_key]
    evidence["original_control"] = original_control.outcome
    if original_control.outcome != "passed":
        return _check("unknown", f"원본에서 정상 입력이 싱크에 닿지 않아 시험이 정상 동작을 구별하지 못한다: {original_control.reason}", **evidence)

    candidate_attack = many(candidate, "attack", REPEATS)
    candidate_control = many(candidate, "benign", REPEATS)
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

    # 시험 입력은 막지만 다른 입력에는 뚫리는 수정을 가려낸다(기본 입력이 통과한 뒤에만 실행한다)
    variants = _variant_phase(spec, runner, original, candidate, limits, cached, original_memo, memo_key)
    if variants is not None:
        evidence["variants"] = variants.evidence
        if variants.result is not None:
            return _check(variants.result[0], variants.result[1], **evidence)

    mutants: list[Mutant] = []
    if patch_path is not None:
        mutants = build_mutants(candidate, patch_path.read_text(encoding="utf-8", errors="replace"), spec.target.file, work)
    killed, survived, invalid = [], [], []
    for mutant in mutants:
        if not mutant.valid:
            invalid.append({"description": mutant.description, "problem": mutant.problem})
            continue
        install_harness(mutant.directory, spec)
        run = run_harness(runner, mutant.directory, "attack", limits)
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
