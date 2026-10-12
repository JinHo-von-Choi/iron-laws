"""
오철칙 지원 범위 행렬: 언어·규칙별로 구현된 것과 시험으로 검증된 것을 구분해 보여 준다
'파서가 있다'와 '그 규칙이 그 언어에서 검증되었다'는 다르다. 검증 시험이 없는 칸은 미검증으로 공개한다.
작성자: 최진호
작성일: 2026-10-04
"""

import json
from dataclasses import dataclass, field
from importlib.resources import files

from iron_laws.engine.languages import Lang
from iron_laws.rules.base import BaseRule

LANG_ORDER = [Lang.PYTHON, Lang.JAVASCRIPT, Lang.TYPESCRIPT, Lang.JAVA, Lang.KOTLIN, Lang.CSHARP, Lang.GO, Lang.RUST, Lang.PHP, Lang.C, Lang.CPP]
# tsx는 typescript와 같은 규칙·시험을 쓰므로 한 칸으로 묶는다
FIXTURE_LANG_ALIASES = {"tsx": "typescript"}

_OWASP_JAVA = {"IL-501": "sqli", "IL-502": "pathtraver", "IL-504": "cmdi", "IL-505": "xss", "IL-508": "ldapi", "IL-527": "xpathi", "IL-102": "crypto·hash", "IL-104": "weakrand", "IL-526": "trustbound", "AI-115": "securecookie"}
_OWASP_PYTHON = {"IL-501": "sqli", "IL-502": "pathtraver", "IL-503": "codeinj", "IL-504": "cmdi", "IL-505": "xss", "IL-507": "redirect", "IL-508": "ldapi", "IL-509": "xxe", "IL-515": "deserialization", "IL-526": "trustbound", "IL-527": "xpathi", "IL-102": "hash", "IL-104": "weakrand", "AI-115": "securecookie"}
_CWE_BENCH_JAVA = {"IL-502": "CWE-22", "IL-504": "CWE-78", "IL-505": "CWE-79", "IL-503": "CWE-94"}


# Juliet 1.3에서 측정한 (규칙, 언어)와 CWE. benchmarks/juliet.py의 대응표 중 데이터셋에 사례가 있는 CWE만(결과: docs/benchmark_results/juliet_*.json)
_JULIET = {
    'IL-101': {'c': ('CWE-259', 'CWE-321'), 'cpp': ('CWE-259', 'CWE-321'), 'csharp': ('CWE-259', 'CWE-321')},
    'IL-102': {'c': ('CWE-327', 'CWE-328'), 'cpp': ('CWE-327', 'CWE-328'), 'csharp': ('CWE-327', 'CWE-328')},
    'IL-104': {'c': ('CWE-338',), 'cpp': ('CWE-338',), 'csharp': ('CWE-338',)},
    'IL-107': {'csharp': ('CWE-759',)},
    'IL-109': {'c': ('CWE-319',), 'cpp': ('CWE-319',), 'csharp': ('CWE-319',)},
    'IL-111': {'c': ('CWE-615',), 'cpp': ('CWE-615',), 'csharp': ('CWE-615',)},
    'IL-112': {'csharp': ('CWE-539',)},
    'IL-301': {'c': ('CWE-390',), 'cpp': ('CWE-390',), 'csharp': ('CWE-390',)},
    'IL-305': {'csharp': ('CWE-209',)},
    'IL-501': {'csharp': ('CWE-89',)},
    'IL-502': {'c': ('CWE-23', 'CWE-36'), 'cpp': ('CWE-23', 'CWE-36'), 'csharp': ('CWE-23', 'CWE-36')},
    'IL-503': {'csharp': ('CWE-94',)},
    'IL-504': {'c': ('CWE-78',), 'cpp': ('CWE-78',), 'csharp': ('CWE-78',)},
    'IL-505': {'csharp': ('CWE-80', 'CWE-81', 'CWE-83')},
    'IL-507': {'csharp': ('CWE-601',)},
    'IL-508': {'c': ('CWE-90',), 'cpp': ('CWE-90',), 'csharp': ('CWE-90',)},
    'IL-511': {'csharp': ('CWE-113',)},
    'IL-514': {'c': ('CWE-121', 'CWE-122', 'CWE-124', 'CWE-126', 'CWE-127', 'CWE-134', 'CWE-190'), 'cpp': ('CWE-121', 'CWE-122', 'CWE-124', 'CWE-126', 'CWE-127', 'CWE-134', 'CWE-190'), 'csharp': ('CWE-134', 'CWE-190')},
    'IL-516': {'c': ('CWE-367',), 'cpp': ('CWE-367',)},
    'IL-517': {'c': ('CWE-835',), 'cpp': ('CWE-835',), 'csharp': ('CWE-835',)},
    'IL-518': {'c': ('CWE-401', 'CWE-404', 'CWE-775'), 'cpp': ('CWE-401', 'CWE-404', 'CWE-775'), 'csharp': ('CWE-404', 'CWE-772', 'CWE-775')},
    'IL-519': {'c': ('CWE-476',), 'cpp': ('CWE-476',), 'csharp': ('CWE-476',)},
    'IL-523': {'c': ('CWE-247',), 'cpp': ('CWE-247',)},
    'IL-524': {'c': ('CWE-242', 'CWE-676'), 'cpp': ('CWE-242', 'CWE-676')},
    'IL-527': {'csharp': ('CWE-643',)},
    'IL-528': {'c': ('CWE-416',), 'cpp': ('CWE-416',)},
    'IL-529': {'c': ('CWE-457',), 'cpp': ('CWE-457',)},
}


def _public_benchmarks() -> dict[str, dict[str, str]]:
    """공개 벤치마크로 측정한 (규칙, 언어). 결과는 docs/benchmark_results/에 있다."""
    from collections import defaultdict

    found: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for rule, category in _OWASP_JAVA.items():
        found[rule]["java"].append(f"OWASP Benchmark v1.2 {category}")
    for rule, category in _CWE_BENCH_JAVA.items():
        found[rule]["java"].append(f"CWE-Bench-Java {category}")
    for rule, category in _OWASP_PYTHON.items():
        found[rule]["python"].append(f"OWASP Benchmark Python {category}")
    for rule, langs in _JULIET.items():
        for lang, cwes in langs.items():
            found[rule][lang] += [f"Juliet 1.3 {cwe}" for cwe in cwes]
    return {rule: {lang: ", ".join(dict.fromkeys(v)) for lang, v in langs.items()} for rule, langs in found.items()}


PUBLIC_BENCHMARKS: dict[str, dict[str, str]] = _public_benchmarks()


@dataclass
class LangCell:
    lang: str
    status: str  # 미지원 / 적용(패턴) / 적용(싱크 정의)
    positives: int = 0
    negatives: int = 0
    benchmark: str = ""

    @property
    def verified(self) -> bool:
        return self.positives > 0 and self.negatives > 0

    def label(self) -> str:
        if self.status == "미지원":
            return "-"
        tests = f"양성 {self.positives}·음성 {self.negatives}" if (self.positives or self.negatives) else "미검증"
        extra = f" · 공개 벤치마크({self.benchmark})" if self.benchmark else ""
        return f"{self.status} · {tests}{extra}"


@dataclass
class SupportRow:
    rule_id: str
    name: str
    cells: dict[str, LangCell] = field(default_factory=dict)
    kinds: dict[str, tuple[int, int]] = field(default_factory=dict)  # 설정·문서 파일 종류별 (양성, 음성) 시험 수

    def verified_languages(self) -> list[str]:
        return [lang for lang, cell in self.cells.items() if cell.verified]


def load_fixture_manifest() -> dict[str, dict[str, dict[str, int]]]:
    raw = files("iron_laws.standards").joinpath("data", "support_fixtures.json").read_text(encoding="utf-8")
    return json.loads(raw)


def build_support_matrix(rules: list[BaseRule]) -> list[SupportRow]:
    manifest = load_fixture_manifest()
    rows: list[SupportRow] = []
    for rule in sorted(rules, key=lambda r: r.rule_id):
        sinks = getattr(rule, "sinks", None) or []
        sink_langs = {lang for sink in sinks for lang in sink.langs}
        row = SupportRow(rule.rule_id, rule.name)
        fixtures = manifest.get(rule.rule_id, {})
        row.kinds = {
            key[5:]: (counts.get("positive", 0), counts.get("negative", 0))
            for key, counts in fixtures.items()
            if key.startswith("kind:")
        }
        for lang in LANG_ORDER:
            applicable = rule.languages is None or lang in rule.languages
            if not applicable:
                status = "미지원"
            elif lang in sink_langs:
                status = "적용(싱크 정의)"
            else:
                status = "적용(패턴)"
            counts = fixtures.get(lang.value, {})
            row.cells[lang.value] = LangCell(
                lang.value,
                status,
                positives=counts.get("positive", 0),
                negatives=counts.get("negative", 0),
                benchmark=PUBLIC_BENCHMARKS.get(rule.rule_id, {}).get(lang.value, ""),
            )
        rows.append(row)
    return rows


def render_support_matrix(rows: list[SupportRow], rule_id: str | None = None) -> str:
    lines: list[str] = []
    if rule_id is not None:
        row = next(r for r in rows if r.rule_id.upper() == rule_id.upper())
        lines.append(f"# {row.rule_id} {row.name}")
        lines.append("")
        lines.append("| 언어 | 구현 | 검증 |")
        lines.append("|---|---|---|")
        for lang, cell in row.cells.items():
            lines.append(f"| {lang} | {cell.status} | {cell.label() if cell.status != '미지원' else '-'} |")
        for kind, (pos, neg) in sorted(row.kinds.items()):
            lines.append(f"| (파일 종류) {kind} | 패턴 | 양성 {pos}·음성 {neg} |")
        return "\n".join(lines)

    header = ["규칙", *[lang.value for lang in LANG_ORDER], "설정·문서 파일 시험(양성/음성)"]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "|".join(["---"] * len(header)) + "|")
    symbol = {"미지원": "-", "적용(패턴)": "적용·패턴", "적용(싱크 정의)": "적용·싱크"}
    for row in rows:
        cells = []
        for lang in LANG_ORDER:
            cell = row.cells[lang.value]
            if cell.status == "미지원":
                cells.append("-")
                continue
            mark = symbol[cell.status] + ("·검증" if cell.verified else "·미검증")
            if cell.benchmark:
                mark += "·벤치"
            cells.append(mark)
        kinds = ", ".join(f"{kind} {pos}/{neg}" for kind, (pos, neg) in sorted(row.kinds.items())) or "-"
        lines.append(f"| {row.rule_id} | " + " | ".join(cells) + f" | {kinds} |")
    total_cells = sum(1 for r in rows for c in r.cells.values() if c.status != "미지원")
    verified_cells = sum(1 for r in rows for c in r.cells.values() if c.status != "미지원" and c.verified)
    lines.append("")
    lines.append(
        f"규칙이 적용되도록 선언된 (규칙, 언어) {total_cells}칸 중 양성·음성 시험이 모두 있는 칸은 {verified_cells}칸입니다. "
        "'적용'은 그 언어에 규칙이 걸린다는 선언일 뿐 그 언어에서의 분석 정확도나 탐지 보증이 아닙니다. 시험이 없는 칸은 미검증입니다."
    )
    lines.append(
        "범례: 적용·싱크=언어별 싱크 정의가 있음, 적용·패턴=정규식·구문 패턴으로 점검, 검증=양성·음성 시험이 모두 있음, "
        "벤치=공개 벤치마크 측정이 있음(OWASP Benchmark Java·Python, CWE-Bench-Java, Juliet C/C++·C#; 결과는 docs/benchmark_results). "
        "파일 간 오염 추적은 Python, JavaScript·TypeScript, Java(static·주입 필드), Go, PHP를 지원한다."
    )
    return "\n".join(lines)
