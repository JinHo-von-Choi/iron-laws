"""
오철칙 지원 범위 행렬 표: 계산은 core/support_matrix.py가 하고 표로 그리는 일만 한다
작성자: 최진호
작성일: 2026-10-04
"""

from iron_laws.core.support_matrix import (
    FIXTURE_LANG_ALIASES as FIXTURE_LANG_ALIASES,
)
from iron_laws.core.support_matrix import (
    LANG_ORDER as LANG_ORDER,
)
from iron_laws.core.support_matrix import (
    PUBLIC_BENCHMARKS as PUBLIC_BENCHMARKS,
)
from iron_laws.core.support_matrix import (
    LangCell as LangCell,
)
from iron_laws.core.support_matrix import (
    SupportRow as SupportRow,
)
from iron_laws.core.support_matrix import (
    build_support_matrix as build_support_matrix,
)
from iron_laws.core.support_matrix import (
    load_fixture_manifest as load_fixture_manifest,
)


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
