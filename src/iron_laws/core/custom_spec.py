"""
오철칙 사용자 명세: 프로젝트 고유의 소스·싱크·정제 함수를 더한다. 사람이 검토하고 예제로 확인한 명세만 불러온다.

명세 파일(YAML):
    version: 1
    sources:     [{id, pattern(코드 정규식), family, languages, positive, negative}]
    sinks:       [{id, callee(호출 이름 정규식), family, languages, arg(0부터, null이면 모든 인자), positive, negative}]
    sanitizers:  [{id, name(호출 이름 정규식), context, family, languages, positive, negative}]

- family: command·sql·path·code 중 하나. 예제를 그 계열 규칙(IL-504·501·502·503)으로 확인한다.
- positive: 이 명세를 적용했을 때 그 규칙의 확정 지적이 나와야 하는 코드. negative: 나오지 않아야 하는 코드.
  정제 함수는 positive에 정제 없는 흐름을, negative에 정제를 거친 흐름을 둔다.
- 모든 항목의 예제가 기대대로 판정될 때만 명세를 불러온다. 하나라도 어긋나면 불러오지 않고 오류로 끝낸다(조용히 빼지 않는다).
- 예제는 항목 하나만 넣은 명세로 확인한다. 다른 항목이 이 항목의 예제에 영향을 주지 않게 하기 위해서다.
작성자: 최진호
작성일: 2026-10-12
"""

import hashlib
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError

from iron_laws.core.config import ConfigError

FAMILY_RULE = {"command": "IL-504", "sql": "IL-501", "path": "IL-502", "code": "IL-503"}
LANG_EXT = {"python": ".py", "javascript": ".js", "typescript": ".ts", "java": ".java", "csharp": ".cs", "go": ".go", "php": ".php"}
_VALIDATING = False


class SpecEntry(BaseModel):
    id: str
    family: str
    languages: list[str] = Field(default_factory=lambda: ["python"])
    positive: str
    negative: str
    pattern: str | None = None  # 소스
    callee: str | None = None  # 싱크
    arg: int | None = 0
    name: str | None = None  # 정제 함수
    context: str | None = None


class CustomSpec(BaseModel):
    version: int = 1
    sources: list[SpecEntry] = Field(default_factory=list)
    sinks: list[SpecEntry] = Field(default_factory=list)
    sanitizers: list[SpecEntry] = Field(default_factory=list)


@dataclass
class LoadedSpec:
    spec: CustomSpec
    digest: str


_CACHE: dict[str, LoadedSpec] = {}
_CURRENT: LoadedSpec | None = None


def current_spec() -> LoadedSpec | None:
    """이번 점검이 반영한 사용자 명세. 명세가 없으면 None이다."""
    return _CURRENT


def _check_entry(kind: str, entry: SpecEntry) -> None:
    if entry.family not in FAMILY_RULE:
        raise ConfigError(f"명세 {kind}.{entry.id}: family는 {', '.join(FAMILY_RULE)} 중 하나여야 합니다")
    unknown = [lang for lang in entry.languages if lang not in LANG_EXT]
    if unknown or not entry.languages:
        raise ConfigError(f"명세 {kind}.{entry.id}: 지원하지 않는 언어 {unknown}")
    field_name = {"sources": "pattern", "sinks": "callee", "sanitizers": "name"}[kind]
    value = getattr(entry, field_name)
    if not value:
        raise ConfigError(f"명세 {kind}.{entry.id}: {field_name}가 필요합니다")
    try:
        re.compile(value)
    except re.error as e:
        raise ConfigError(f"명세 {kind}.{entry.id}: 정규식 오류 {e}") from e
    if not entry.positive.strip() or not entry.negative.strip():
        raise ConfigError(f"명세 {kind}.{entry.id}: 양성·음성 예제가 모두 있어야 불러옵니다")


def read_spec(path: Path) -> LoadedSpec:
    try:
        raw = path.read_bytes()
        spec = CustomSpec(**(yaml.safe_load(raw.decode("utf-8")) or {}))
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValidationError, TypeError) as e:
        raise ConfigError(f"명세 파일을 읽을 수 없습니다: {path} ({e})") from e
    for kind in ("sources", "sinks", "sanitizers"):
        for entry in getattr(spec, kind):
            _check_entry(kind, entry)
    return LoadedSpec(spec, hashlib.sha256(raw).hexdigest())


def _single_entry_spec(entry: SpecEntry, kind: str) -> CustomSpec:
    """항목 하나만 담은 명세. 항목끼리 간섭하지 않게 예제를 확인할 때 쓴다."""
    spec = CustomSpec(version=1)
    getattr(spec, kind).append(entry)
    return spec


def example_results(path: Path) -> list[tuple[str, str, bool, str]]:
    """(항목, positive|negative, 맞았는지, 설명). 항목 하나만 명세에 넣어 예제마다 해당 계열 규칙의 확정 지적 여부를 본다.
    양성·음성 예제를 같은 폴더에 두고 한 번에 점검하되, 항목 하나가 다른 항목의 예제에 영향을 주지 않게 한다."""
    loaded = read_spec(path)
    return [result for kind in ("sources", "sinks", "sanitizers") for entry in getattr(loaded.spec, kind) for result in entry_results(kind, entry)]


def entry_results(kind: str, entry: SpecEntry) -> list[tuple[str, str, bool, str]]:
    """항목 하나의 양성·음성 예제 판정. 다른 항목 없이 이 항목만 명세에 넣고 점검한다."""
    global _VALIDATING
    from iron_laws.core.config import IronLawsConfig, Policies
    from iron_laws.core.scanner import AuditScanner

    _check_entry(kind, entry)
    rule_id = FAMILY_RULE[entry.family]
    extension = LANG_EXT[entry.languages[0]]
    _VALIDATING = True
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
            for form in ("positive", "negative"):
                (code_dir / f"{form}{extension}").write_text(getattr(entry, form), encoding="utf-8")
            config = IronLawsConfig(policies=Policies(custom_spec=str(spec_file)), enabled_rules=[rule_id])
            report = AuditScanner(code_dir, config).scan()
            flagged = {v.file_path.as_posix() for v in report.violations if v.rule_id == rule_id and v.confidence.value == "CONFIRMED"}
    finally:
        _VALIDATING = False
    results = []
    for form in ("positive", "negative"):
        hit = f"{form}{extension}" in flagged
        ok = hit if form == "positive" else not hit
        results.append((f"{kind}.{entry.id}", form, ok, f"{rule_id} 확정 지적 {'있음' if hit else '없음'}"))
    return results


def load_validated(path: Path) -> LoadedSpec:
    loaded = read_spec(path)
    cached = _CACHE.get(str(path))
    if cached is not None and cached.digest == loaded.digest:
        return cached
    failures = [r for r in example_results(path) if not r[2]]
    if failures:
        detail = "; ".join(f"{name} {form}: {why}" for name, form, _ok, why in failures[:5])
        raise ConfigError(f"명세 예제가 기대와 맞지 않아 명세를 불러오지 않았습니다: {detail}")
    _CACHE[str(path)] = loaded
    return loaded


def apply_custom_spec(rules: list, location: str | None) -> None:
    """활성 규칙과 오염 엔진에 명세를 적용한다. 명세가 없으면 이전 점검이 남긴 적용을 지운다."""
    from iron_laws.engine.languages import Lang
    from iron_laws.engine.taint import Ctx, set_custom_spec
    from iron_laws.rules.sinks import Sink

    global _CURRENT
    if not location:
        set_custom_spec({}, {}, "")
        _CURRENT = None
        return
    loaded = read_spec(Path(location)) if _VALIDATING else load_validated(Path(location))
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
    set_custom_spec(sources, sanitizers, loaded.digest[:16])
    _CURRENT = loaded
