"""
OWASP Benchmark for Python 정확도 측정 도구

사용법:
    git clone https://github.com/OWASP-Benchmark/BenchmarkPython.git
    uv run python benchmarks/owasp_benchmark_python.py BenchmarkPython <커밋 해시> [all|confirmed] [원시결과.json] [--testcode-only]

받은 사본의 커밋이 인자와 다르면 종료코드 2로 끝난다(측정 대상 고정).
confirmed는 외부 입력 도달이 코드에서 확인된 지적(확정)만, all은 확인 필요 지적까지 포함한다.
저장소 루트를 점검해 도우미 모듈(helpers)까지 분석하고, 채점은 testcode 아래 사례 파일만 한다.
--testcode-only는 예전 측정 방식(testcode 폴더만 점검)이다.
사례 하나는 testcode/BenchmarkTestNNNNN.py 파일 하나다. 벤치마크 코드는 저장소에 포함하지 않는다(GPL-3.0).
작성자: 최진호
작성일: 2026-10-12
"""

import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bench_common import Case, require_commit, score  # noqa: E402

from iron_laws.core.scanner import AuditScanner, tool_version  # noqa: E402

CATEGORY_RULES = {
    "sqli": {"IL-501"},
    "xss": {"IL-505"},
    "cmdi": {"IL-504"},
    "codeinj": {"IL-503"},
    "pathtraver": {"IL-502"},
    "hash": {"IL-102"},
    "weakrand": {"IL-104"},
    "ldapi": {"IL-508"},
    "xpathi": {"IL-527"},
    "xxe": {"IL-509"},
    "deserialization": {"IL-515"},
    "redirect": {"IL-507"},
    "securecookie": {"AI-115"},
    "trustbound": {"IL-526"},
}


def load_cases(root: Path, prefix: str = "testcode") -> list[Case]:
    """prefix는 점검 루트에서 사례 폴더까지의 상대 경로다"""
    folder = f"{prefix}/" if prefix else ""
    cases = []
    with open(root / "expectedresults-0.1.csv", encoding="utf-8") as handle:
        for row in csv.reader(handle):
            if not row or row[0].startswith("#"):
                continue
            test, category, real, cwe = row[0], row[1], row[2] == "true", row[3]
            cases.append(Case(test, f"{folder}{test}.py", category, real, frozenset(CATEGORY_RULES.get(category, set())), f"CWE-{cwe}"))
    return cases


def main(root: Path, commit: str, mode: str, raw_output: Path | None = None, testcode_only: bool = False) -> None:
    require_commit(root, commit)
    scan_root = root / "testcode" if testcode_only else root
    report = AuditScanner(scan_root).scan()
    scored = score(load_cases(root, "" if testcode_only else "testcode"), report, scan_root, confirmed_only=mode == "confirmed")
    raw = {
        "tool_version": tool_version(),
        "dataset": "OWASP Benchmark for Python 0.1",
        "dataset_commit": commit,
        "mode": mode,
        "command": f"benchmarks/owasp_benchmark_python.py <BenchmarkPython 폴더> {commit} {mode}" + (" --testcode-only" if testcode_only else ""),
        "scan_root": "testcode" if testcode_only else ".",
        "files": report.summary.total_files_scanned,
        "categories": scored.table(),
        "outcomes": dict(sorted(scored.outcomes.items())),
    }
    print(f"도구 {tool_version()} · 벤치마크 커밋 {commit} · 파일 {raw['files']}개 · 모드 {mode}")
    for category, row in raw["categories"].items():
        extra = f" 분석 불가={row['unanalyzed']}" if row.get("unanalyzed") else ""
        print(f"{category:16s} TP={row['TP']:4d} FN={row['FN']:4d} FP={row['FP']:4d} TN={row['TN']:4d} TPR={row['TPR']:6.1%} FPR={row['FPR']:6.1%}{extra}")
    if raw_output is not None:
        raw_output.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--testcode-only"]
    if len(args) < 2:
        print(__doc__)
        sys.exit(2)
    main(Path(args[0]), args[1], args[2] if len(args) > 2 else "confirmed", Path(args[3]) if len(args) > 3 else None, "--testcode-only" in sys.argv)
