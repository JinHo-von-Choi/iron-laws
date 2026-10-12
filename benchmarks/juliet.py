"""
NIST Juliet Test Suite 1.3(C/C++, C#) 정확도 측정 도구

사용법:
    # https://samate.nist.gov/SARD/test-suites 에서 받은 압축 파일과 푼 폴더
    uv run python benchmarks/juliet.py c  <압축.zip> <푼 폴더> [원시결과.json]
    uv run python benchmarks/juliet.py cs <압축.zip> <푼 폴더> [원시결과.json]

압축 파일의 sha256이 아래 고정값과 다르면 종료코드 2로 끝난다.
- 사례 하나는 Juliet 시험 사례 하나(분할 파일 `_51a.c`·`_51b.c`, 클래스 분할 `_81_bad.cpp`·`_81_goodG2B.cpp`를 묶은 것)다.
- 위험 쪽: 사례 파일들에서 이름에 bad가 들어간 함수(또는 `_bad` 파일) 안에 대응 규칙의 지적이 있으면 TP, 없으면 FN.
- 정상 쪽: 이름에 good이 들어간 함수(또는 `_good*` 파일) 안에 대응 규칙의 지적이 있으면 FP, 없으면 TN.
- 오철칙 규칙과 대응하는 CWE만 잰다(JULIET_CWE_RULES). 대응표는 결과 파일에도 함께 남긴다. 확정 지적만 센다.
작성자: 최진호
작성일: 2026-10-12
"""

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bench_common import entry_ranges, require_digest  # noqa: E402

from iron_laws.core.scanner import AuditScanner, tool_version  # noqa: E402

DATASETS = {
    "c": {
        "name": "Juliet Test Suite for C/C++ 1.3",
        "sha256": "ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb",
        "testcases": "C/testcases",
        "exts": (".c", ".cpp"),
    },
    "cs": {
        "name": "Juliet Test Suite for C# 1.3",
        "sha256": "2e6dbac4741fb020a0b1c2db69e98aed165987df2bd70bd51f7c8c5302c8e8f8",
        "testcases": "src/testcases",
        "exts": (".cs",),
    },
}

# Juliet CWE → 그 결함을 다루는 오철칙 규칙. 규칙의 행안부 가이드 항목 CWE와 그 하위 CWE만 넣는다.
JULIET_CWE_RULES: dict[int, set[str]] = {
    23: {"IL-502"}, 36: {"IL-502"},
    78: {"IL-504"},
    79: {"IL-505"}, 80: {"IL-505"}, 81: {"IL-505"}, 83: {"IL-505"},
    89: {"IL-501"},
    90: {"IL-508"},
    94: {"IL-503"}, 95: {"IL-503"},
    113: {"IL-511"},
    121: {"IL-514"}, 122: {"IL-514"}, 124: {"IL-514"}, 126: {"IL-514"}, 127: {"IL-514"},
    134: {"IL-514"},
    190: {"IL-514"},
    209: {"IL-305"},
    242: {"IL-524"}, 676: {"IL-524"},
    247: {"IL-523"},
    259: {"IL-101"}, 321: {"IL-101"},
    312: {"IL-109"}, 319: {"IL-109"},
    327: {"IL-102"}, 328: {"IL-102"},
    338: {"IL-104"},
    367: {"IL-516"},
    390: {"IL-301"},
    401: {"IL-518"}, 404: {"IL-518"}, 772: {"IL-518"}, 775: {"IL-518"},
    416: {"IL-528"},
    457: {"IL-529"},
    476: {"IL-519"},
    502: {"IL-515"},
    539: {"IL-112"},
    601: {"IL-507"},
    611: {"IL-509"},
    615: {"IL-111"},
    643: {"IL-527"},
    732: {"IL-114"},
    759: {"IL-107"},
    835: {"IL-517"},
}

CASE_RE = re.compile(r"^(?P<case>CWE\d+_.+?_\d+)(?:[a-e]|_bad|_good\w*)?$")


def _cwe_of(directory: str) -> int | None:
    m = re.match(r"CWE(\d+)_", directory)
    return int(m.group(1)) if m else None


def _spans(path: Path) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    stem = path.stem
    text = path.read_text(encoding="utf-8", errors="replace")
    whole = [(1, text.count("\n") + 1)]
    if re.search(r"_bad$", stem):
        return whole, []
    if re.search(r"_good\w*$", stem):
        return [], whole
    return entry_ranges(text, path.suffix, r"(?i).*bad.*"), entry_ranges(text, path.suffix, r"(?i).*good.*")


def measure_cwe(directory: Path, rules: set[str], exts: tuple[str, ...]) -> tuple[Counter, int]:
    report = AuditScanner(directory).scan()
    found: dict[str, list[int]] = defaultdict(list)
    for v in report.violations:
        if v.rule_id in rules and v.confidence.value == "CONFIRMED":
            found[v.file_path.as_posix()].append(v.line_number)
    cases: dict[str, dict[str, bool]] = defaultdict(lambda: {"bad": False, "good": False, "has_bad": False, "has_good": False})
    for path in sorted(p for p in directory.rglob("*") if p.suffix in exts):
        m = CASE_RE.match(path.stem)
        if not m:
            continue
        key = f"{path.parent.relative_to(directory).as_posix()}/{m.group('case')}"
        bad, good = _spans(path)
        lines = found.get(path.relative_to(directory).as_posix(), [])
        row = cases[key]
        row["has_bad"] |= bool(bad)
        row["has_good"] |= bool(good)
        row["bad"] |= any(a <= n <= b for n in lines for a, b in bad)
        row["good"] |= any(a <= n <= b for n in lines for a, b in good)
    counts: Counter = Counter()
    for row in cases.values():
        if row["has_bad"]:
            counts["TP" if row["bad"] else "FN"] += 1
        if row["has_good"]:
            counts["FP" if row["good"] else "TN"] += 1
    return counts, report.summary.total_files_scanned


def main(kind: str, archive: Path, root: Path, raw_output: Path | None) -> None:
    spec = DATASETS[kind]
    require_digest(archive, spec["sha256"])
    testcases = root / spec["testcases"]
    raw: dict = {
        "tool_version": tool_version(),
        "dataset": spec["name"],
        "dataset_sha256": spec["sha256"],
        "command": f"benchmarks/juliet.py {kind} <압축.zip> <푼 폴더>",
        "cwe_rule_map": {f"CWE-{c}": sorted(r) for c, r in sorted(JULIET_CWE_RULES.items())},
        "categories": {},
    }
    print(f"도구 {tool_version()} · {spec['name']}")
    for directory in sorted(p for p in testcases.iterdir() if p.is_dir()):
        cwe = _cwe_of(directory.name)
        if cwe not in JULIET_CWE_RULES:
            continue
        counts, files = measure_cwe(directory, JULIET_CWE_RULES[cwe], spec["exts"])
        tp, fn, fp, tn = counts["TP"], counts["FN"], counts["FP"], counts["TN"]
        tpr = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        raw["categories"][directory.name] = {"files": files, "TP": tp, "FN": fn, "FP": fp, "TN": tn, "TPR": round(tpr, 4), "FPR": round(fpr, 4)}
        print(f"{directory.name[:48]:48s} TP={tp:5d} FN={fn:5d} FP={fp:5d} TN={tn:5d} TPR={tpr:6.1%} FPR={fpr:6.1%}", flush=True)
    if raw_output is not None:
        raw_output.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) < 4 or sys.argv[1] not in DATASETS:
        print(__doc__)
        sys.exit(2)
    main(sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]) if len(sys.argv) > 4 else None)
