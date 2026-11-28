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
- 오철칙 규칙과 대응하는 CWE만 잰다(JULIET_CWE_RULES). 대응표는 결과 파일에도 함께 남긴다.
- TP·FN·FP·TN은 확정 지적만 센다. 확인 필요 지적까지 센 결과는 with_review에 따로 적는다.
- by_kind에는 good·bad 함수 안의 지적을 하위 판정(IL-514는 복사·서식·입력 너비·크기 계산)별로 사례 수로 적는다.
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

# IL-514 지적 문구로 하위 판정을 가른다. 다른 규칙은 규칙 ID를 하위 판정으로 쓴다
IL514_KINDS = (
    ("copy", ("버퍼 크기를 검사하지", "버퍼에 복사합니다", "버퍼 아래쪽")),
    ("format", ("포맷 문자열",)),
    ("width", ("입력 길이를 제한하지",)),
    ("alloc", ("정수 오버플로우",)),
)


def finding_kind(v) -> str:
    if v.rule_id == "IL-514":
        return next((kind for kind, markers in IL514_KINDS if any(m in v.message for m in markers)), "other")
    return v.rule_id


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


def measure_cwe(directory: Path, rules: set[str], exts: tuple[str, ...]) -> tuple[dict, int]:
    """사례별로 bad·good 함수 안의 지적을 모아 확정 기준, 확인 필요 포함 기준, 하위 판정별 사례 수를 센다"""
    report = AuditScanner(directory).scan()
    found: dict[str, list[tuple[int, bool, str]]] = defaultdict(list)
    for v in report.violations:
        if v.rule_id in rules:
            found[v.file_path.as_posix()].append((v.line_number, v.confidence.value == "CONFIRMED", finding_kind(v)))
    cases: dict[str, dict] = defaultdict(lambda: {"has_bad": False, "has_good": False, "bad": set(), "good": set()})
    for path in sorted(p for p in directory.rglob("*") if p.suffix in exts):
        m = CASE_RE.match(path.stem)
        if not m:
            continue
        key = f"{path.parent.relative_to(directory).as_posix()}/{m.group('case')}"
        bad, good = _spans(path)
        row = cases[key]
        row["has_bad"] |= bool(bad)
        row["has_good"] |= bool(good)
        for line, confirmed, kind in found.get(path.relative_to(directory).as_posix(), []):
            for side, spans in (("bad", bad), ("good", good)):
                if any(a <= line <= b for a, b in spans):  # iron-laws: ignore[PERF-102] spans는 함수 하나의 줄 범위라 한두 개다
                    row[side].add((confirmed, kind))
    counts: Counter = Counter()
    with_review: Counter = Counter()
    by_kind: dict[str, Counter] = defaultdict(Counter)
    for row in cases.values():
        for side, hit_key, miss_key in (("bad", "TP", "FN"), ("good", "FP", "TN")):
            if not row["has_" + side]:
                continue
            marks = row[side]
            counts[hit_key if any(confirmed for confirmed, _ in marks) else miss_key] += 1
            with_review[hit_key if marks else miss_key] += 1
            for kind in {k for confirmed, k in marks if confirmed}:
                by_kind[kind][side] += 1
            for kind in {k for confirmed, k in marks if not confirmed}:
                by_kind[kind][side + "_review"] += 1
    result = {"counts": counts, "with_review": with_review, "by_kind": {k: dict(sorted(v.items())) for k, v in sorted(by_kind.items())}}
    return result, report.summary.total_files_scanned


def _rates(k: Counter) -> dict:
    tp, fn, fp, tn = k["TP"], k["FN"], k["FP"], k["TN"]
    return {"TP": tp, "FN": fn, "FP": fp, "TN": tn, "TPR": round(tp / (tp + fn), 4) if tp + fn else 0.0, "FPR": round(fp / (fp + tn), 4) if fp + tn else 0.0}


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
        measured, files = measure_cwe(directory, JULIET_CWE_RULES[cwe], spec["exts"])
        row = {"files": files, **_rates(measured["counts"]), "with_review": _rates(measured["with_review"]), "by_kind": measured["by_kind"]}
        raw["categories"][directory.name] = row
        print(f"{directory.name[:48]:48s} TP={row['TP']:5d} FN={row['FN']:5d} FP={row['FP']:5d} TN={row['TN']:5d} TPR={row['TPR']:6.1%} FPR={row['FPR']:6.1%} {measured['by_kind']}", flush=True)
    if raw_output is not None:
        raw_output.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) < 4 or sys.argv[1] not in DATASETS:
        print(__doc__)
        sys.exit(2)
    main(sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]) if len(sys.argv) > 4 else None)
