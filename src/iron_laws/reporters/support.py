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

LANG_ORDER = [Lang.PYTHON, Lang.JAVASCRIPT, Lang.TYPESCRIPT, Lang.JAVA, Lang.CSHARP, Lang.GO, Lang.RUST, Lang.PHP, Lang.C, Lang.CPP]
# tsx는 typescript와 같은 규칙·시험을 쓰므로 한 칸으로 묶는다
FIXTURE_LANG_ALIASES = {"tsx": "typescript"}

# 공개 벤치마크가 있는 (규칙, 언어). 지금은 OWASP Benchmark v1.2의 Java뿐이다.
PUBLIC_BENCHMARKS: dict[str, dict[str, str]] = {
    "IL-501": {"java": "OWASP Benchmark v1.2 sqli"},
    "IL-502": {"java": "OWASP Benchmark v1.2 pathtraver"},
    "IL-504": {"java": "OWASP Benchmark v1.2 cmdi"},
    "IL-505": {"java": "OWASP Benchmark v1.2 xss"},
    "IL-508": {"java": "OWASP Benchmark v1.2 ldapi"},
    "IL-527": {"java": "OWASP Benchmark v1.2 xpathi"},
    "IL-102": {"java": "OWASP Benchmark v1.2 crypto·hash"},
    "IL-104": {"java": "OWASP Benchmark v1.2 weakrand"},
    "IL-526": {"java": "OWASP Benchmark v1.2 trustbound"},
    "AI-115": {"java": "OWASP Benchmark v1.2 securecookie"},
}


@dataclass
class LangCell:
    lang: str
    status: str  # 미지원 / 패턴 / 싱크 모델
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
                status = "싱크 모델"
            else:
                status = "패턴"
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
    symbol = {"미지원": "-", "패턴": "패턴", "싱크 모델": "모델"}
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
        f"적용 가능한 (규칙, 언어) {total_cells}칸 중 양성·음성 시험이 모두 있는 칸은 {verified_cells}칸입니다. "
        "나머지는 미검증이며, 파서가 있다는 사실이 그 규칙의 정확도를 뜻하지 않습니다."
    )
    lines.append("범례: 모델=언어별 싱크 정의가 있음, 패턴=정규식·구문 패턴으로 점검, 벤치=공개 벤치마크 측정이 있음(Java만).")
    return "\n".join(lines)
