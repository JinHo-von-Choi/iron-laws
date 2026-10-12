"""
CWE-Bench-Java 함수 단위 측정 도구(실제 프로젝트 120개 CVE, 경로 조작·명령 삽입·XSS·코드 삽입)

사용법:
    git clone https://github.com/iris-sast/cwe-bench-java.git
    uv run python benchmarks/cwe_bench_java.py <cwe-bench-java 폴더> <커밋 해시> <프로젝트 작업 폴더> [--fetch] [원시결과.json]

- 데이터셋 사본의 커밋이 인자와 다르면 종료코드 2로 끝난다.
- 프로젝트마다 취약 커밋과 마지막 수정 커밋을 얕게 받아(--fetch) 각각 점검한다. 이미 받은 사본은 다시 받지 않는다.
- 위험 쪽: 취약 커밋에서 수정된 메서드(fix_info.csv의 파일·메서드) 안에 CWE에 대응하는 규칙의 확정 지적이 있으면 TP, 없으면 FN.
- 정상 쪽: 수정 커밋의 같은 메서드 안에 같은 지적이 있으면 FP, 없으면 TN.
- 받지 못했거나 메서드를 찾지 못한 사례는 TN·FN이 아니라 분석 불가로 센다.
작성자: 최진호
작성일: 2026-10-12
"""

import csv
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bench_common import entry_ranges, require_commit  # noqa: E402

from iron_laws.core.scanner import AuditScanner, tool_version  # noqa: E402

CWE_RULES = {"CWE-022": {"IL-502"}, "CWE-078": {"IL-504"}, "CWE-079": {"IL-505"}, "CWE-094": {"IL-503"}}


def _git(*args: str, cwd: Path) -> bool:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True).returncode == 0


def checkout(work: Path, url: str, commit: str, fetch: bool) -> Path | None:
    target = work / commit[:12]
    if (target / ".git").is_dir():
        return target
    if not fetch:
        return None
    target.mkdir(parents=True, exist_ok=True)
    ok = _git("init", "-q", cwd=target) and _git("remote", "add", "origin", url, cwd=target)
    ok = ok and _git("fetch", "-q", "--depth", "1", "origin", commit, cwd=target) and _git("checkout", "-q", "FETCH_HEAD", cwd=target)
    return target if ok else None


def method_hit(root: Path, rules: set[str], methods: list[tuple[str, str]], report, include_review: bool = False) -> bool | None:
    """수정된 메서드 중 하나라도 안에 지적이 있으면 True. 메서드를 하나도 찾지 못하면 None.
    기본은 확정 지적만 센다. include_review면 확인 필요 지적도 센다"""
    found: dict[str, list[int]] = defaultdict(list)
    for v in report.violations:
        if v.rule_id in rules and (include_review or v.confidence.value == "CONFIRMED"):
            found[v.file_path.as_posix()].append(v.line_number)
    located = False
    for rel, method in methods:
        path = root / rel
        if not path.is_file():
            continue
        spans = entry_ranges(path.read_text(encoding="utf-8", errors="replace"), ".java", method)
        located |= bool(spans)
        if any(a <= n <= b for n in found.get(rel, []) for a, b in spans):
            return True
    return False if located else None


def main(dataset: Path, commit: str, work: Path, fetch: bool, raw_output: Path | None) -> None:
    require_commit(dataset, commit)
    projects = list(csv.DictReader(open(dataset / "data/project_info.csv", encoding="utf-8")))
    methods: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for row in csv.DictReader(open(dataset / "data/fix_info.csv", encoding="utf-8")):
        if row["method"]:
            methods[row["project_slug"]].append((row["file"], row["method"]))
    rows: dict[str, Counter] = defaultdict(Counter)
    rows_all: dict[str, Counter] = defaultdict(Counter)  # 확인 필요 지적까지 센 결과
    outcomes: dict[str, dict] = {}
    for project in projects:
        slug, cwe = project["project_slug"], project["cwe_id"]
        rules = CWE_RULES.get(cwe)
        if rules is None:
            continue
        url = project["github_url"]
        fixes = [c for c in project["fix_commit_ids"].split(";") if c]
        result = {"cwe": cwe}
        for side, sha in (("buggy", project["buggy_commit_id"]), ("fixed", fixes[-1] if fixes else "")):
            root = checkout(work / slug, url, sha, fetch) if sha else None
            if root is None:
                result[side] = "unanalyzed"
                rows[cwe]["unanalyzed_" + side] += 1
                continue
            report = AuditScanner(root).scan()
            hit = method_hit(root, rules, methods[slug], report)
            if hit is None:
                result[side] = "unanalyzed"
                rows[cwe]["unanalyzed_" + side] += 1
                continue
            key = ("TP" if hit else "FN") if side == "buggy" else ("FP" if hit else "TN")
            result[side] = key
            rows[cwe][key] += 1
            hit_all = method_hit(root, rules, methods[slug], report, include_review=True)
            key_all = ("TP" if hit_all else "FN") if side == "buggy" else ("FP" if hit_all else "TN")
            result[side + "_all"] = key_all
            rows_all[cwe][key_all] += 1
        outcomes[slug] = result
        print(slug, result, flush=True)
    raw = {
        "tool_version": tool_version(),
        "dataset": "CWE-Bench-Java",
        "dataset_commit": commit,
        "command": "benchmarks/cwe_bench_java.py <cwe-bench-java 폴더> <커밋> <작업 폴더> --fetch",
        "cwe_rule_map": {c: sorted(r) for c, r in CWE_RULES.items()},
        "categories": {},
        "outcomes": outcomes,
    }
    for cwe, k in sorted(rows.items()):
        tp, fn, fp, tn = k["TP"], k["FN"], k["FP"], k["TN"]
        raw["categories"][cwe] = {
            "TP": tp, "FN": fn, "FP": fp, "TN": tn,
            "TPR": round(tp / (tp + fn), 4) if tp + fn else 0.0,
            "FPR": round(fp / (fp + tn), 4) if fp + tn else 0.0,
            "unanalyzed": {"buggy": k["unanalyzed_buggy"], "fixed": k["unanalyzed_fixed"]},
        }
        a = rows_all[cwe]
        raw["categories"][cwe]["with_review"] = {
            "TP": a["TP"], "FN": a["FN"], "FP": a["FP"], "TN": a["TN"],
            "TPR": round(a["TP"] / (a["TP"] + a["FN"]), 4) if a["TP"] + a["FN"] else 0.0,
            "FPR": round(a["FP"] / (a["FP"] + a["TN"]), 4) if a["FP"] + a["TN"] else 0.0,
        }
        print(cwe, raw["categories"][cwe])
    if raw_output is not None:
        raw_output.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--fetch"]
    if len(args) < 3:
        print(__doc__)
        sys.exit(2)
    main(Path(args[0]), args[1], Path(args[2]), "--fetch" in sys.argv, Path(args[3]) if len(args) > 3 else None)
