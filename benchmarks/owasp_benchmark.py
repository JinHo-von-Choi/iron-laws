"""
OWASP Benchmark(Java) 정확도 측정 도구

사용법:
    git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git
    uv run python benchmarks/owasp_benchmark.py BenchmarkJava [all|confirmed] [원시결과.json]

confirmed는 외부 입력 도달이 코드에서 확인된 지적(확정)만, all은 확인 필요 지적까지 포함한다.
사례 대응과 집계는 bench_common.py를 따른다. 분석하지 못한 파일은 TN·FN이 아니라 분석 불가로 따로 센다.
벤치마크 코드는 저장소에 포함하지 않는다.
작성자: 최진호
작성일: 2026-10-04
"""

import csv
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bench_common import Case, score  # noqa: E402

from iron_laws.core.scanner import AuditScanner, tool_version  # noqa: E402

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

CATEGORY_CWE = {
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "cmdi": "CWE-78",
    "pathtraver": "CWE-22",
    "crypto": "CWE-327",
    "hash": "CWE-328",
    "weakrand": "CWE-330",
    "ldapi": "CWE-90",
    "xpathi": "CWE-643",
    "securecookie": "CWE-614",
    "trustbound": "CWE-501",
}


def load_expected(root: Path) -> dict[str, tuple[str, bool]]:
    expected = {}
    with open(root / "expectedresults-1.2.csv", encoding="utf-8") as handle:
        for row in csv.reader(handle):
            if row and not row[0].startswith("#"):
                expected[row[0]] = (row[1], row[2] == "true")
    return expected


def load_cases(root: Path) -> list[Case]:
    """벤치마크 사례 하나는 파일 하나다(BenchmarkTestNNNNN.java)."""
    return [
        Case(test, f"{test}.java", category, real, frozenset(CATEGORY_RULES.get(category, set())), CATEGORY_CWE.get(category, ""))
        for test, (category, real) in load_expected(root).items()
    ]


def dataset_commit(root: Path) -> str:
    try:
        return subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "(git 정보 없음)"


def main(root: Path, mode: str, raw_output: Path | None = None) -> None:
    code = root / "src/main/java/org/owasp/benchmark/testcode"
    report = AuditScanner(code).scan()
    scored = score(load_cases(root), report, code, confirmed_only=mode == "confirmed")

    commit = dataset_commit(root)
    print(f"도구 {tool_version()} · 벤치마크 커밋 {commit}")
    print(f"파일 {report.summary.total_files_scanned}개, 모드 {mode}")
    raw: dict = {
        "tool_version": tool_version(),
        "dataset_commit": commit,
        "mode": mode,
        "command": f"benchmarks/owasp_benchmark.py <BenchmarkJava 폴더> {mode}",
        "files": report.summary.total_files_scanned,
        "categories": scored.table(),
    }
    for category, row in raw["categories"].items():
        tpr, fpr = row["TPR"], row["FPR"]
        extra = f" 분석 불가={row['unanalyzed']}" if row.get("unanalyzed") else ""
        print(f"{category:13s} TP={row['TP']:4d} FN={row['FN']:4d} FP={row['FP']:4d} TN={row['TN']:4d} TPR={tpr:6.1%} FPR={fpr:6.1%} 점수={tpr - fpr:+7.1%}{extra}")

    if raw_output is not None:
        raw_output.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"원시 결과 저장: {raw_output}")


if __name__ == "__main__":
    main(Path(sys.argv[1]), sys.argv[2] if len(sys.argv) > 2 else "confirmed", Path(sys.argv[3]) if len(sys.argv) > 3 else None)
