"""
OWASP Benchmark(Java) 정확도 측정 도구

사용법:
    git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git
    uv run python benchmarks/owasp_benchmark.py BenchmarkJava [all|confirmed]

confirmed는 외부 입력 도달이 코드에서 확인된 지적(확정)만, all은 확인 필요 지적까지 포함한다.
벤치마크 코드는 저장소에 포함하지 않는다.
작성자: 최진호
작성일: 2026-10-04
"""

import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

from iron_laws.core.scanner import AuditScanner

CATEGORY_RULES = {
    "sqli": {"IL-501"},
    "xss": {"IL-505"},
    "cmdi": {"IL-504"},
    "pathtraver": {"IL-502"},
    "crypto": {"IL-102"},
    "hash": {"IL-102"},
    "weakrand": {"IL-104"},
    "ldapi": {"IL-508"},
    "xpathi": {"IL-527"},
    "securecookie": {"AI-115"},
    "trustbound": {"IL-526"},
}


def load_expected(root: Path) -> dict[str, tuple[str, bool]]:
    expected = {}
    with open(root / "expectedresults-1.2.csv", encoding="utf-8") as handle:
        for row in csv.reader(handle):
            if row and not row[0].startswith("#"):
                expected[row[0]] = (row[1], row[2] == "true")
    return expected


def main(root: Path, mode: str) -> None:
    code = root / "src/main/java/org/owasp/benchmark/testcode"
    report = AuditScanner(code).scan()
    found: dict[str, set[str]] = defaultdict(set)
    for v in report.violations:
        if mode == "confirmed" and v.confidence.value != "CONFIRMED":
            continue
        found[Path(v.file_path).stem].add(v.rule_id)

    stats: dict[str, Counter] = defaultdict(Counter)
    for test, (category, real) in load_expected(root).items():
        rules = CATEGORY_RULES.get(category, set())
        hit = bool(found.get(test, set()) & rules)
        key = ("TP" if hit else "FN") if real else ("FP" if hit else "TN")
        stats[category][key] += 1

    print(f"파일 {report.summary.total_files_scanned}개, 모드 {mode}")
    for category, k in sorted(stats.items()):
        tp, fn, fp, tn = k["TP"], k["FN"], k["FP"], k["TN"]
        tpr = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        print(f"{category:13s} TP={tp:4d} FN={fn:4d} FP={fp:4d} TN={tn:4d} TPR={tpr:6.1%} FPR={fpr:6.1%} 점수={tpr - fpr:+7.1%}")


if __name__ == "__main__":
    main(Path(sys.argv[1]), sys.argv[2] if len(sys.argv) > 2 else "confirmed")
