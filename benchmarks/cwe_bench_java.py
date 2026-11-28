"""
CWE-Bench-Java 함수 단위 측정 도구(실제 프로젝트 120개 CVE, 경로 조작·명령 삽입·XSS·코드 삽입)

사용법:
    git clone https://github.com/iris-sast/cwe-bench-java.git
    uv run python benchmarks/cwe_bench_java.py <cwe-bench-java 폴더> <커밋 해시> <프로젝트 작업 폴더> [--fetch] [--public-api] [원시결과.json]

- 데이터셋 사본의 커밋이 인자와 다르면 종료코드 2로 끝난다.
- 프로젝트마다 취약 커밋과 마지막 수정 커밋을 얕게 받아(--fetch) 각각 점검한다. 이미 받은 사본은 다시 받지 않는다.
- 데이터셋의 해시가 40자보다 짧으면 저장소 이력을 파일 내용 없이(--filter=blob:none) 받아,
  그 문자열이 유일한 커밋 접두사인지 확인하고 전체 해시로 받는다. 작업 폴더 이름은 전체 해시의 앞 12자다.
- 위험 쪽: 취약 커밋에서 수정된 메서드(fix_info.csv의 파일·메서드) 안에 CWE에 대응하는 규칙의 확정 지적이 있으면 TP, 없으면 FN.
- 정상 쪽: 수정 커밋의 같은 메서드 안에 같은 지적이 있으면 FP, 없으면 TN.
- 사례마다 두 쪽의 판정 쌍(TP·TN, TP·FP, FN·TN, FN·FP)을 센다.
- 지적이 붙은 줄이 두 커밋 사이에 바뀌지 않았으면 unchanged로 표시한다. 그런 지적은 취약한 쪽에서는 결함을 잡은 근거가 아니고,
  고친 쪽에서는 수정을 인정하지 못한 근거가 아니다.
- 받지 못했거나(not_fetched) 메서드를 찾지 못한(method_not_found) 사례는 TN·FN이 아니라 쪽과 이유별로 분석 불가로 센다.
- --public-api는 공개 함수의 매개변수를 입력으로 보는 모드(policies.entry_points: public_api)로 잰다. 기본 설정 결과와 따로 기록한다.
- cwe_bench_java_notes.json에 적힌 사례(고친 쪽으로 지정한 커밋에 보안 수정이 없는 사례 등)는 판정 쌍 지표에서 따로 센다.
  데이터셋 값은 바꾸지 않는다.
작성자: 최진호
작성일: 2026-10-12
"""

import csv
import difflib
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bench_common import entry_ranges, require_commit  # noqa: E402

from iron_laws.core.scanner import AuditScanner, tool_version  # noqa: E402

CWE_RULES = {"CWE-022": {"IL-502"}, "CWE-078": {"IL-504"}, "CWE-079": {"IL-505"}, "CWE-094": {"IL-503"}}
NOTES = Path(__file__).with_name("cwe_bench_java_notes.json")
FULL_HASH = 40


def _git(*args: str, cwd: Path) -> bool:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True).returncode == 0


def _git_out(*args: str, cwd: Path) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    return done.stdout.strip() if done.returncode == 0 else ""


def resolve_commit(work: Path, url: str, commit: str, fetch: bool) -> str:
    """짧거나 잘린 해시를 전체 해시로 바꾼다. 유일한 접두사가 아니거나 이력을 받지 못하면 빈 문자열"""
    if len(commit) >= FULL_HASH:
        return commit
    history = work / "_history"
    if not (history / "HEAD").is_file():
        if not fetch:
            return ""
        history.parent.mkdir(parents=True, exist_ok=True)
        if not _git("clone", "-q", "--bare", "--filter=blob:none", url, str(history), cwd=history.parent):
            return ""
    return _git_out("rev-parse", "-q", "--verify", f"{commit}^{{commit}}", cwd=history)


def checkout(work: Path, url: str, commit: str, fetch: bool) -> Path | None:
    """받다 만 사본(HEAD가 없는 .git)은 받은 것으로 보지 않고 다시 받는다. 받기는 세 번까지 시도한다"""
    target = work / commit[:12]
    if (target / ".git").is_dir() and _git("rev-parse", "-q", "--verify", "HEAD", cwd=target):
        return target
    if not fetch:
        return None
    target.mkdir(parents=True, exist_ok=True)
    if not (target / ".git").is_dir() and not (_git("init", "-q", cwd=target) and _git("remote", "add", "origin", url, cwd=target)):
        return None
    for _ in range(3):
        if _git("fetch", "-q", "--depth", "1", "origin", commit, cwd=target) and _git("checkout", "-q", "FETCH_HEAD", cwd=target):
            return target
    return None


def method_hits(root: Path, rules: set[str], methods: list[tuple[str, str]], report, include_review: bool = False) -> list[tuple[str, int]] | None:
    """수정된 메서드 안에 있는 지적의 (파일, 줄) 목록. 메서드를 하나도 찾지 못하면 None.
    기본은 확정 지적만 센다. include_review면 확인 필요 지적도 센다"""
    found: dict[str, list[int]] = defaultdict(list)
    for v in report.violations:
        if v.rule_id in rules and (include_review or v.confidence.value == "CONFIRMED"):
            found[v.file_path.as_posix()].append(v.line_number)
    located = False
    hits: set[tuple[str, int]] = set()
    for rel, method in methods:
        path = root / rel
        if not path.is_file():
            continue
        spans = entry_ranges(path.read_text(encoding="utf-8", errors="replace"), ".java", method)
        located |= bool(spans)
        hits |= {(rel, n) for n in found.get(rel, []) for a, b in spans if a <= n <= b}  # iron-laws: ignore[PERF-102] spans는 메서드 하나의 줄 범위라 한두 개다
    return sorted(hits) if located else None


def method_hit(root: Path, rules: set[str], methods: list[tuple[str, str]], report, include_review: bool = False) -> bool | None:
    """수정된 메서드 중 하나라도 안에 지적이 있으면 True. 메서드를 하나도 찾지 못하면 None"""
    hits = method_hits(root, rules, methods, report, include_review)
    return None if hits is None else bool(hits)


def unchanged_lines(mine: Path, other: Path) -> set[int]:
    """mine 파일에서 other 파일과 같은 내용으로 남은 줄 번호(1부터). 파일이 한쪽에 없으면 빈 집합"""
    if not mine.is_file() or not other.is_file():
        return set()
    a = mine.read_text(encoding="utf-8", errors="replace").splitlines()
    b = other.read_text(encoding="utf-8", errors="replace").splitlines()
    same: set[int] = set()
    for block in difflib.SequenceMatcher(None, a, b, autojunk=False).get_matching_blocks():
        same.update(range(block.a + 1, block.a + block.size + 1))
    return same


def mark_unchanged(hits: list[tuple[str, int]], root: Path, other_root: Path | None) -> list[dict]:
    cache: dict[str, set[int]] = {}
    marked = []
    for rel, line in hits:
        if other_root is None:
            marked.append({"file": rel, "line": line, "unchanged": None})
            continue
        if rel not in cache:
            cache[rel] = unchanged_lines(root / rel, other_root / rel)
        marked.append({"file": rel, "line": line, "unchanged": line in cache[rel]})
    return marked


def _rates(k: Counter) -> dict:
    tp, fn, fp, tn = k["TP"], k["FN"], k["FP"], k["TN"]
    return {
        "TP": tp, "FN": fn, "FP": fp, "TN": tn,
        "TPR": round(tp / (tp + fn), 4) if tp + fn else 0.0,
        "FPR": round(fp / (fp + tn), 4) if fp + tn else 0.0,
    }


def load_notes() -> dict[str, dict]:
    if not NOTES.is_file():
        return {}
    return json.loads(NOTES.read_text(encoding="utf-8")).get("cases", {})


def evaluate(project: dict, methods: list[tuple[str, str]], work: Path, fetch: bool, entry_points: str = "web") -> dict:
    """사례 하나의 두 쪽을 점검해 판정, 판정 쌍, 지적 줄의 변경 여부를 돌려준다"""
    slug, cwe = project["project_slug"], project["cwe_id"]
    rules = CWE_RULES[cwe]
    url = project["github_url"]
    fixes = [c for c in project["fix_commit_ids"].split(";") if c]
    result: dict = {"cwe": cwe}
    roots: dict[str, Path] = {}
    hits: dict[str, list[tuple[str, int]]] = {}
    for side, sha in (("buggy", project["buggy_commit_id"]), ("fixed", fixes[-1] if fixes else "")):
        full = resolve_commit(work / slug, url, sha, fetch) if sha else ""
        if full and full != sha:
            result[side + "_commit"] = full
        root = checkout(work / slug, url, full, fetch) if full else None
        if root is None:
            result[side] = "unanalyzed"
            result[side + "_reason"] = "not_fetched"
            continue
        from iron_laws.core.config import IronLawsConfig, Policies

        report = AuditScanner(root, IronLawsConfig(policies=Policies(entry_points=entry_points))).scan()
        confirmed = method_hits(root, rules, methods, report)
        if confirmed is None:
            result[side] = "unanalyzed"
            result[side + "_reason"] = "method_not_found"
            continue
        roots[side] = root
        hits[side] = confirmed
        result[side] = ("TP" if confirmed else "FN") if side == "buggy" else ("FP" if confirmed else "TN")
        with_review = method_hits(root, rules, methods, report, include_review=True) or []
        result[side + "_all"] = ("TP" if with_review else "FN") if side == "buggy" else ("FP" if with_review else "TN")
    for side, other in (("buggy", "fixed"), ("fixed", "buggy")):
        if hits.get(side):
            result[side + "_hits"] = mark_unchanged(hits[side], roots[side], roots.get(other))
    if "buggy" in roots and "fixed" in roots:
        result["pair"] = f"{result['buggy']}/{result['fixed']}"
        marks = result.get("buggy_hits", []) + result.get("fixed_hits", [])
        if marks and all(m["unchanged"] for m in marks):
            result["hits_unchanged"] = True
    return result


def main(dataset: Path, commit: str, work: Path, fetch: bool, raw_output: Path | None, entry_points: str = "web") -> None:
    require_commit(dataset, commit)
    projects = list(csv.DictReader(open(dataset / "data/project_info.csv", encoding="utf-8")))
    methods: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for row in csv.DictReader(open(dataset / "data/fix_info.csv", encoding="utf-8")):
        if row["method"]:
            methods[row["project_slug"]].append((row["file"], row["method"]))
    notes = load_notes()
    rows: dict[str, Counter] = defaultdict(Counter)
    rows_all: dict[str, Counter] = defaultdict(Counter)  # 확인 필요 지적까지 센 결과
    pairs: dict[str, Counter] = defaultdict(Counter)
    outcomes: dict[str, dict] = {}
    for project in projects:
        slug, cwe = project["project_slug"], project["cwe_id"]
        if cwe not in CWE_RULES:
            continue
        result = evaluate(project, methods[slug], work, fetch, entry_points)
        for side in ("buggy", "fixed"):
            if result[side] == "unanalyzed":
                rows[cwe][f"unanalyzed_{side}_{result[side + '_reason']}"] += 1
            else:
                rows[cwe][result[side]] += 1
                rows_all[cwe][result[side + "_all"]] += 1
        if "pair" in result:
            bucket = "noted" if slug in notes else "pairs"
            pairs[cwe][f"{bucket}:{result['pair']}"] += 1
            if result.get("hits_unchanged"):
                pairs[cwe][f"{bucket}:{result['pair']}:hits_unchanged"] += 1
        else:
            pairs[cwe]["unpaired"] += 1
        if slug in notes:
            result["note"] = notes[slug]
        outcomes[slug] = result
        print(slug, result, flush=True)
    raw = {
        "tool_version": tool_version(),  # iron-laws: ignore[ARC-205] 보고서 JSON의 필드 이름이다
        "dataset": "CWE-Bench-Java",
        "dataset_commit": commit,
        "command": "benchmarks/cwe_bench_java.py <cwe-bench-java 폴더> <커밋> <작업 폴더> --fetch" + (" --public-api" if entry_points == "public_api" else ""),
        "entry_points": entry_points,
        "cwe_rule_map": {c: sorted(r) for c, r in CWE_RULES.items()},
        "categories": {},
        "outcomes": outcomes,
    }
    for cwe, k in sorted(rows.items()):
        unanalyzed = {
            side: {reason: k[f"unanalyzed_{side}_{reason}"] for reason in ("not_fetched", "method_not_found") if k[f"unanalyzed_{side}_{reason}"]}
            for side in ("buggy", "fixed")
        }
        raw["categories"][cwe] = {**_rates(k), "unanalyzed": unanalyzed, "with_review": _rates(rows_all[cwe]), "pairs": dict(sorted(pairs[cwe].items()))}
        print(cwe, raw["categories"][cwe])
    if raw_output is not None:
        raw_output.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a not in ("--fetch", "--public-api")]
    if len(args) < 3:
        print(__doc__)
        sys.exit(2)
    main(Path(args[0]), args[1], Path(args[2]), "--fetch" in sys.argv, Path(args[3]) if len(args) > 3 else None, "public_api" if "--public-api" in sys.argv else "web")
