"""
오철칙 사용자 명세: 프로젝트 고유의 소스·싱크·정제 함수·검사 함수·라이브러리 요약을 더한다. 사람이 검토하고 예제로 확인한 명세만 불러온다.

명세 파일(YAML):
    version: 1
    sources:     [{id, pattern(코드 정규식), family, languages, positive, negative}]
    sinks:       [{id, callee(호출 이름 정규식), family 또는 context, languages, arg(0부터, null이면 모든 인자), positive, negative}]
    sanitizers:  [{id, name(호출 이름 정규식), context, family, languages, positive, negative}]
    validators:  [{id, name, arg(검사하는 인자), success(참이면 안전한지, 기본 true), context, family, languages, positive, negative}]
    summaries:   [{id, name, summary: propagate|normalize, from_arg(원본 인자), to(return 또는 인자 위치), family, languages, positive, negative}]

- family: command·sql·path·code·xpath·ldap·xss·redirect 중 하나. 예제를 그 계열 규칙으로 확인한다.
  싱크는 family 대신 context(shell·sql·path·code·xpath·ldap·html·url)를 적어도 된다.
- 검사 함수는 `if not 검사(x): return`처럼 실행을 끊는 분기에서 쓰일 때, 통과한 경로의 x를 그 문맥에서 안전하다고 본다.
- 전달 요약(propagate)은 원본 인자의 오염을 반환값이나 다른 인자로 옮긴다. 정규화 요약(normalize)은 경로를 정규화하는 함수라는
  뜻이고 정제가 아니다. 그 값을 기준 폴더와 비교하는 검사가 있을 때 정규화 근거로만 쓴다.
- positive: 이 명세를 적용했을 때 그 규칙의 지적이 나와야 하는 코드. negative: 나오지 않아야 하는 코드.
  지적을 낮추는 항목(정제·검사 함수·정규화 요약)은 positive에 낮추지 않는 흐름을, negative에 낮추는 흐름을 둔다.
  언어가 둘 이상이면 예제를 언어별 사전(`{python: ..., java: ...}`)으로 준다.
- expect(기본 confirmed): positive 예제가 받아야 하는 판정. negative_expect(기본 review): negative 예제가 받을 수 있는
  가장 강한 판정이다. 지적이 전혀 없어야 하면 none으로 적는다. positive_line을 주면 그 줄에 지적이 있어야 한다.
- 예제는 항목 하나만 넣은 명세와 명세 없는 상태로 각각 점검한다. 판정이 그 항목 때문에 바뀌어야 맞은 것으로 본다.
- 모든 항목의 예제가 기대대로 판정될 때만 명세를 불러온다. 하나라도 어긋나면 불러오지 않고 오류로 끝낸다(조용히 빼지 않는다).
작성자: 최진호
작성일: 2026-10-12
"""

import hashlib
import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError

from iron_laws.core.config import ConfigError, IronLawsConfig, Policies
from iron_laws.core.models import AuditReport

FAMILY_RULE = {
    "command": "IL-504", "sql": "IL-501", "path": "IL-502", "code": "IL-503",
    "xpath": "IL-527", "ldap": "IL-508", "xss": "IL-505", "redirect": "IL-507",
}
CONTEXT_FAMILY = {"shell": "command", "sql": "sql", "path": "path", "code": "code", "xpath": "xpath", "ldap": "ldap", "html": "xss", "url": "redirect"}
LANG_EXT = {"python": ".py", "javascript": ".js", "typescript": ".ts", "java": ".java", "csharp": ".cs", "go": ".go", "php": ".php"}
KINDS = ("sources", "sinks", "sanitizers", "validators", "summaries")
LOWERING = frozenset({"sanitizers", "validators"})  # 지적을 없애거나 낮추는 항목(정규화 요약도 여기에 든다)
_VALIDATING = False
# 예제 폴더를 주어진 설정으로 점검하는 함수. 점검기(scanner.py)가 넘겨 준다. 명세 모듈이 점검기를 직접 가져오면 순환 의존이 생긴다.
ScanFn = Callable[[Path, IronLawsConfig], AuditReport]


class SpecEntry(BaseModel):
    id: str
    family: str = ""
    languages: list[str] = Field(default_factory=lambda: ["python"])
    positive: str | dict[str, str]
    negative: str | dict[str, str]
    pattern: str | None = None  # 소스
    callee: str | None = None  # 싱크
    arg: int | None = 0
    name: str | None = None  # 정제 함수·검사 함수·요약
    context: str | None = None
    success: bool = True  # 검사 함수: 참을 돌려주면 안전하다
    summary: str | None = None  # 요약: propagate | normalize
    from_arg: int = 0
    to: str = "return"
    expect: str = "confirmed"  # positive 예제가 받아야 하는 판정
    negative_expect: str = "review"  # negative 예제가 받을 수 있는 가장 강한 판정(none·review). 확정이 아니어야 한다는 뜻이 기본이다
    positive_line: int | None = None


class CustomSpec(BaseModel):
    version: int = 1
    sources: list[SpecEntry] = Field(default_factory=list)
    sinks: list[SpecEntry] = Field(default_factory=list)
    sanitizers: list[SpecEntry] = Field(default_factory=list)
    validators: list[SpecEntry] = Field(default_factory=list)
    summaries: list[SpecEntry] = Field(default_factory=list)


@dataclass
class LoadedSpec:
    spec: CustomSpec
    digest: str


_CACHE: dict[str, LoadedSpec] = {}
_CURRENT: LoadedSpec | None = None


def current_spec() -> LoadedSpec | None:
    """이번 점검이 반영한 사용자 명세. 명세가 없으면 None이다."""
    return _CURRENT


def lowers(kind: str, entry: SpecEntry) -> bool:
    """지적을 없애거나 낮추는 항목인지. 정제·검사 함수와 정규화 요약이다"""
    return kind in LOWERING or (kind == "summaries" and entry.summary == "normalize")


def _check_entry(kind: str, entry: SpecEntry) -> None:
    if not entry.family and kind == "sinks" and entry.context in CONTEXT_FAMILY:
        entry.family = CONTEXT_FAMILY[entry.context]
    if entry.family not in FAMILY_RULE:
        raise ConfigError(f"명세 {kind}.{entry.id}: family는 {', '.join(FAMILY_RULE)} 중 하나여야 합니다")
    unknown = [lang for lang in entry.languages if lang not in LANG_EXT]
    if unknown or not entry.languages:
        raise ConfigError(f"명세 {kind}.{entry.id}: 지원하지 않는 언어 {unknown}")
    field_name = {"sources": "pattern", "sinks": "callee", "sanitizers": "name", "validators": "name", "summaries": "name"}[kind]
    value = getattr(entry, field_name)
    if not value:
        raise ConfigError(f"명세 {kind}.{entry.id}: {field_name}가 필요합니다")
    try:
        re.compile(value)
    except re.error as e:
        raise ConfigError(f"명세 {kind}.{entry.id}: 정규식 오류 {e}") from e
    if kind == "summaries" and entry.summary not in ("propagate", "normalize"):
        raise ConfigError(f"명세 summaries.{entry.id}: summary는 propagate·normalize 중 하나여야 합니다")
    if kind == "summaries" and entry.summary == "propagate" and not (entry.to == "return" or entry.to.isdigit()):
        raise ConfigError(f"명세 summaries.{entry.id}: to는 return 또는 인자 위치(0부터)여야 합니다")
    if entry.expect not in ("confirmed", "review") or entry.negative_expect not in ("none", "review"):
        raise ConfigError(f"명세 {kind}.{entry.id}: expect는 confirmed·review, negative_expect는 none·review 중 하나여야 합니다")
    for form in ("positive", "negative"):
        examples = getattr(entry, form)
        if isinstance(examples, str):
            if len(entry.languages) > 1:
                raise ConfigError(f"명세 {kind}.{entry.id}: 언어가 둘 이상이면 {form} 예제를 언어별로 주십시오")
            examples = {entry.languages[0]: examples}
        missing = [lang for lang in entry.languages if not str(examples.get(lang, "")).strip()]
        if missing:
            raise ConfigError(f"명세 {kind}.{entry.id}: 양성·음성 예제가 모든 언어에 있어야 불러옵니다(빠진 언어 {missing})")


def _examples(entry: SpecEntry, form: str) -> dict[str, str]:
    examples = getattr(entry, form)
    return {entry.languages[0]: examples} if isinstance(examples, str) else dict(examples)


def read_spec(path: Path) -> LoadedSpec:
    try:
        raw = path.read_bytes()
        spec = CustomSpec(**(yaml.safe_load(raw.decode("utf-8")) or {}))
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValidationError, TypeError) as e:
        raise ConfigError(f"명세 파일을 읽을 수 없습니다: {path} ({e})") from e
    for kind in KINDS:
        for entry in getattr(spec, kind):
            _check_entry(kind, entry)
    return LoadedSpec(spec, hashlib.sha256(raw).hexdigest())


def _single_entry_spec(entry: SpecEntry, kind: str) -> CustomSpec:
    """항목 하나만 담은 명세. 항목끼리 간섭하지 않게 예제를 확인할 때 쓴다."""
    spec = CustomSpec(version=1)
    getattr(spec, kind).append(entry)
    return spec


def example_results(path: Path, scan: ScanFn) -> list[tuple[str, str, bool, str]]:
    """(항목, positive|negative, 맞았는지, 설명). 항목 하나만 명세에 넣어 예제마다 해당 계열 규칙의 판정을 본다."""
    loaded = read_spec(path)
    return [result for kind in KINDS for entry in getattr(loaded.spec, kind) for result in entry_results(kind, entry, scan)]


def _verdicts(scan: ScanFn, code_dir: Path, rule_id: str, spec_file: Path | None) -> dict[str, dict[int, str]]:
    """파일 → (줄 → 가장 강한 판정). 판정은 CONFIRMED·REVIEW"""
    config = IronLawsConfig(policies=Policies(custom_spec=str(spec_file) if spec_file is not None else None), enabled_rules=[rule_id])
    report = scan(code_dir, config)
    found: dict[str, dict[int, str]] = {}
    for v in report.violations:
        if v.rule_id != rule_id:
            continue
        lines = found.setdefault(v.file_path.as_posix(), {})
        if lines.get(v.line_number) != "CONFIRMED":
            lines[v.line_number] = v.confidence.value
    return found


def _level(lines: dict[int, str], at: int | None) -> str:
    """파일(또는 지정한 줄)의 가장 강한 판정: confirmed·review·none"""
    values = [c for n, c in lines.items() if at is None or n == at]
    return "confirmed" if "CONFIRMED" in values else ("review" if values else "none")


def entry_results(kind: str, entry: SpecEntry, scan: ScanFn) -> list[tuple[str, str, bool, str]]:
    """항목 하나의 양성·음성 예제 판정. 선언한 모든 언어마다, 이 항목만 넣은 명세와 명세 없는 상태로 각각 점검해
    그 항목 때문에 판정이 바뀌었는지 본다."""
    global _VALIDATING
    _check_entry(kind, entry)
    rule_id = FAMILY_RULE[entry.family]
    _VALIDATING = True
    results = []
    try:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            code_dir = base / "code"
            code_dir.mkdir()
            spec_file = base / "spec.yml"
            spec_file.write_text(
                yaml.safe_dump(_single_entry_spec(entry, kind).model_dump(mode="json"), allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )
            names = {}
            for lang in entry.languages:
                for form in ("positive", "negative"):
                    name = f"{form}_{lang}{LANG_EXT[lang]}"
                    (code_dir / name).write_text(_examples(entry, form)[lang], encoding="utf-8")
                    names[(lang, form)] = name
            with_entry = _verdicts(scan, code_dir, rule_id, spec_file)
            without = _verdicts(scan, code_dir, rule_id, None)
    finally:
        _VALIDATING = False
    lowering = lowers(kind, entry)
    for lang in entry.languages:
        label = f"{kind}.{entry.id}" + (f"[{lang}]" if len(entry.languages) > 1 else "")
        pos_name, neg_name = names[(lang, "positive")], names[(lang, "negative")]
        pos_with = _level(with_entry.get(pos_name, {}), entry.positive_line)
        pos_without = _level(without.get(pos_name, {}), entry.positive_line)
        neg_with = _level(with_entry.get(neg_name, {}), None)
        neg_without = _level(without.get(neg_name, {}), None)
        rank = {"none": 0, "review": 1, "confirmed": 2}
        neg_within = rank[neg_with] <= rank[entry.negative_expect]
        if lowering:
            pos_ok = pos_with == entry.expect
            neg_ok = neg_within and rank[neg_without] > rank[neg_with]  # 이 항목 때문에 낮아져야 한다
        else:
            pos_ok = pos_with == entry.expect and rank[pos_without] < rank[pos_with]  # 이 항목 때문에 지적이 생겨야 한다
            neg_ok = neg_within
        where = f" {entry.positive_line}행" if entry.positive_line else ""
        results.append((label, "positive", pos_ok, f"{rule_id}{where} 판정: 항목 적용 {pos_with}, 적용 전 {pos_without} (기대 {entry.expect})"))
        results.append((label, "negative", neg_ok, f"{rule_id} 판정: 항목 적용 {neg_with}, 적용 전 {neg_without} (기대 {entry.negative_expect} 이하)"))
    return results


def load_validated(path: Path, scan: ScanFn) -> LoadedSpec:
    loaded = read_spec(path)
    cached = _CACHE.get(str(path))
    if cached is not None and cached.digest == loaded.digest:
        return cached
    failures = [r for r in example_results(path, scan) if not r[2]]
    if failures:
        detail = "; ".join(f"{name} {form}: {why}" for name, form, _ok, why in failures[:5])
        raise ConfigError(f"명세 예제가 기대와 맞지 않아 명세를 불러오지 않았습니다: {detail}")
    _CACHE[str(path)] = loaded
    return loaded


def apply_custom_spec(rules: list, location: str | None, scan: ScanFn | None = None) -> None:
    """활성 규칙과 오염 엔진에 명세를 적용한다. 명세가 없으면 이전 점검이 남긴 적용을 지운다.
    명세의 예제를 확인하려면 scan이 있어야 한다. 없으면 확인하지 않은 명세를 쓰지 않고 오류로 끝낸다."""
    from iron_laws.engine.languages import Lang
    from iron_laws.engine.taint import Ctx, set_custom_spec
    from iron_laws.rules.sinks import Sink

    global _CURRENT
    if not location:
        set_custom_spec({}, {}, "")
        _CURRENT = None
        return
    if _VALIDATING:
        loaded = read_spec(Path(location))
    elif scan is None:
        raise ConfigError("사용자 명세의 예제를 확인할 점검 함수가 없어 명세를 불러오지 않았습니다(get_active_rules에 scan을 넘기십시오)")
    else:
        loaded = load_validated(Path(location), scan)
    spec = loaded.spec
    lang_of = {"python": Lang.PYTHON, "javascript": Lang.JAVASCRIPT, "typescript": Lang.TYPESCRIPT, "java": Lang.JAVA, "csharp": Lang.CSHARP, "go": Lang.GO, "php": Lang.PHP}

    def langs_of(entry) -> frozenset:
        return frozenset(lang_of[lang] for lang in entry.languages) | (frozenset({Lang.TSX}) if "typescript" in entry.languages else frozenset())

    def merged(table: dict, key, pattern: str) -> None:
        prior = table.get(key)
        table[key] = re.compile(f"{prior.pattern}|(?:{pattern})" if prior else f"(?:{pattern})")

    by_rule = {r.rule_id: r for r in rules}
    for entry in spec.sinks:
        rule = by_rule.get(FAMILY_RULE[entry.family])
        if rule is not None:
            rule.sinks = [*rule.sinks, Sink.of(langs_of(entry), entry.callee, entry.arg)]
    sources: dict = {}
    for entry in spec.sources:
        for lang in langs_of(entry):
            merged(sources, lang, entry.pattern)
    sanitizers: dict = {}
    for entry in spec.sanitizers:
        try:
            ctx = Ctx(entry.context or "any")
        except ValueError as e:
            raise ConfigError(f"명세 sanitizers.{entry.id}: context는 {', '.join(c.value for c in Ctx)} 중 하나여야 합니다") from e
        for lang in langs_of(entry):
            merged(sanitizers, (lang, ctx), entry.name)
    validators: dict = {}
    for entry in spec.validators:
        try:
            ctx = Ctx(entry.context or "any")
        except ValueError as e:
            raise ConfigError(f"명세 validators.{entry.id}: context는 {', '.join(c.value for c in Ctx)} 중 하나여야 합니다") from e
        for lang in langs_of(entry):
            validators.setdefault(lang, []).append((re.compile(entry.name), entry.arg or 0, entry.success, ctx))
    normalizers: dict = {}
    propagators: dict = {}
    for entry in spec.summaries:
        for lang in langs_of(entry):
            if entry.summary == "normalize":
                merged(normalizers, lang, entry.name)
            else:
                propagators.setdefault(lang, []).append((re.compile(entry.name), entry.from_arg, entry.to))
    set_custom_spec(sources, sanitizers, loaded.digest[:16], validators, normalizers, propagators)
    _CURRENT = loaded
