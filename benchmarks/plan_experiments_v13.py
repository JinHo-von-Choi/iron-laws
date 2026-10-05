"""
오철칙 v1.3 실행계획(판정 신뢰성과 검토 비용 개선)의 실험 표본을 측정하고 원시 결과를 남긴다.

사용법:
    uv run python benchmarks/plan_experiments_v13.py [결과.json]

측정 대상(모두 구현자가 직접 만들고 분류한 표본이다. 독립 검토자의 분류가 아니며 효과 주장의 근거가 아니다):
- 실험 1 판정과 근거의 일치: 표본 보고서의 독립 검증기 통과, 손상시킨 보고서의 검출, 설명 없는 통과 수
- 실험 2 정상 코드와 위험 코드의 동시 판별: 개발용·평가용(holdout)을 따로, 원본 수와 변형 수를 나눠서
- 실험 3 회귀시험의 결함 구별력: 시험 입력 하나만 막는 수정의 수용 수(변형 입력 유무별)
- 실험 4 변경 영향과 승인 승계: 위험한 승계와 불필요한 재검토, 전체 재검토 방식과의 비교
- 실험 5 팀 도입과 검토 비용: 수행하지 않았다(파일럿 팀이 없다). 도구만 준비했다.
시험용 대역 실행기(호스트 실행)를 쓰므로 격리 실행의 성능·안전은 이 측정에 포함되지 않는다.
작성자: 최진호
작성일: 2026-10-05
"""

import copy
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from iron_laws.core.approvals import ApprovalStore, approve_record  # noqa: E402
from iron_laws.core.review_bundle import build_bundle  # noqa: E402
from iron_laws.core.scanner import AuditScanner, tool_version  # noqa: E402
from iron_laws.evidence.verifier import verify_report  # noqa: E402
from iron_laws.verify.engine import resolve_finding  # noqa: E402
from tests import test_v13_stage2_evidence as s2e  # noqa: E402
from tests import test_v13_stage3_regression_heldout as s3r  # noqa: E402
from tests.repair_cases import REPAIR_CASES  # noqa: E402
from tests.semantic_corpus import DEV_APPROVAL, DEV_OUTPUT, DEV_SCAN, OPERATORS  # noqa: E402
from tests.semantic_eval import evaluate_approvals, evaluate_output, evaluate_scan  # noqa: E402
from tests.semantic_holdout import HOLDOUT_APPROVAL, HOLDOUT_OUTPUT, HOLDOUT_SCAN  # noqa: E402
from tests.test_stage2_contract import KNOWN_GAPS, SAFE_CHANGES  # noqa: E402


def scratch() -> Path:
    return Path(tempfile.mkdtemp(prefix="iron-laws-v13-"))


class Tmp:
    def __call__(self, name: str) -> Path:
        return scratch() / name[:60]


def experiment_1() -> dict:
    corpora = [case[1] for case in KNOWN_GAPS] + [files for _name, files in SAFE_CHANGES] + [s2e.MIXED]
    reports = [s2e.report_of(scratch(), files) for files in corpora]
    for _group, _name, ext, code, _rule, _risky in REPAIR_CASES:
        reports.append(s2e.report_of(scratch(), {f"app{ext}": code}))
    inconsistent = [i for i, data in enumerate(reports) if not verify_report(data).ok]
    unexplained_pass = sum(1 for data in reports if verify_report(data).ok is False and data["summary"]["is_passed"])
    good = s2e.report_of(scratch(), s2e.MIXED)
    caught = 0
    for _name, mutate, expected in s2e.CORRUPTIONS:
        broken = copy.deepcopy(good)
        mutate(broken)
        caught += expected in {p.code for p in verify_report(broken).problems}
    return {
        "reports_checked": len(reports),
        "reports_inconsistent": len(inconsistent),
        "unexplained_pass": unexplained_pass,
        "corruptions": len(s2e.CORRUPTIONS),
        "corruptions_caught": caught,
        "distinct_problem_codes_exercised": len({c[2] for c in s2e.CORRUPTIONS}),
        "note": "검증기는 구조적 모순을 잡는다. 엔진이 일관되게 만든 의미 오류는 증명하지 않는다.",
    }


def experiment_2() -> dict:
    tmp = Tmp()
    result = {}
    for split, scan, approvals, outputs in (("dev", DEV_SCAN, DEV_APPROVAL, DEV_OUTPUT), ("holdout", HOLDOUT_SCAN, HOLDOUT_APPROVAL, HOLDOUT_OUTPUT)):
        metrics = evaluate_scan(scan, tmp)
        result[split] = {
            "scan": metrics.summary(),
            "approvals": evaluate_approvals(approvals, tmp),
            "output": evaluate_output(outputs, tmp),
            "failures": [(o.case_id, o.form, o.operator, o.verdict) for o in metrics.failures()],
        }
    result["operators"] = list(OPERATORS)
    result["base_cases"] = len(DEV_SCAN) + len(DEV_APPROVAL) + len(DEV_OUTPUT) + len(HOLDOUT_SCAN) + len(HOLDOUT_APPROVAL) + len(HOLDOUT_OUTPUT)
    result["note"] = "위험 탐지율과 정상 유지율은 합치지 않고 따로 쓴다. 평가용에서 실패해 엔진을 고친 사례는 개발용으로 옮겼다(docs/ACCURACY.md)."
    return result


def experiment_3() -> dict:
    class Factory:
        def mktemp(self, name: str) -> Path:
            return scratch() / name[:40]

    factory = Factory()
    with_variants = [s3r._evaluate(factory, case, name, strip_variants=False).result for case, name in s3r.PAIRS]
    without_variants = [s3r._evaluate(factory, case, name, strip_variants=True).result for case, name in s3r.PAIRS]
    return {
        "wrong_fixes": len(s3r.PAIRS),
        "accepted_with_variant_inputs": with_variants.count("pass"),
        "accepted_without_variant_inputs": without_variants.count("pass"),
        "note": "시험 입력 하나만 막는 수정(정확한 입력 차단·한 글자 필터)이다. 수집 0개·skip·timeout은 통과로 세지 않는다(기존 시험 항목).",
    }


def experiment_4() -> dict:
    from tests.test_v13_stage4_bundle import TOOLS, approve_all, five, tool_source

    trials = []
    wrongly_kept = unnecessary = invalidated_total = full_total = 0
    patterns = [("ls -R /", "risky"), ("find /", "risky"), ("ls", "benign")]
    import itertools

    for mask in itertools.product([0, 1], repeat=len(TOOLS)):
        if sum(mask) == 0 or sum(mask) == len(TOOLS):
            continue
        base = scratch()
        project = base / "proj"
        project.mkdir()
        store = base / "s.jsonl"
        five(project)
        approve_all(project, store)
        truth: dict[str, bool] = {}
        for name, hit in zip(TOOLS, mask, strict=True):
            prefix, kind = patterns[0] if hit else patterns[2]
            text = tool_source(name, prefix) if hit else tool_source(name) + "\n# 관련 없는 설명\n"
            (project / f"{name}.py").write_text(text)
            truth[f"{name}.py"] = bool(hit) and kind == "risky"
        scanner = AuditScanner(project, approvals=ApprovalStore(store), changed_files={f"{n}.py" for n in TOOLS}, changed_since="HEAD")
        report = scanner.scan()
        bundle = build_bundle(report, scanner.approval_rows, changed_files=scanner.changed_files, command="", approvals_path=None)
        for decision in bundle.approvals:
            path = decision.location.split(":")[0]
            invalidated = decision.decision == "invalidate"
            wrongly_kept += truth[path] and not invalidated
            unnecessary += (not truth[path]) and invalidated
            invalidated_total += invalidated
            full_total += 1
        trials.append(sum(mask))
    return {
        "scenarios": len(trials),
        "approvals_evaluated": full_total,
        "dangerous_inheritance": wrongly_kept,
        "unnecessary_re_review": unnecessary,
        "re_reviews_with_bundle": invalidated_total,
        "re_reviews_with_full_review": full_total,
        "reduction_vs_full_review": round(1 - invalidated_total / full_total, 3) if full_total else None,
        "note": "위험 승계가 0건인지가 먼저이고 절감은 그다음이다. 전체 재검토 방식은 모든 승인을 다시 보는 것이다.",
    }


def main() -> int:
    result = {
        "tool_version": tool_version(),
        "note": "구현자가 직접 만들고 분류한 표본이다. 독립 검토자의 분류가 아니며 효과 주장의 근거가 아니다. 호스트 실행 대역 실행기로 측정했다.",
        "experiment_1_evidence_consistency": experiment_1(),
        "experiment_2_discrimination": experiment_2(),
        "experiment_3_regression_discrimination": experiment_3(),
        "experiment_4_approval_inheritance": experiment_4(),
        "experiment_5_team_pilot": {"executed": False, "reason": "파일럿 팀과 검토자가 없어 수행하지 않았다. 도구(`pilot`, `--metrics`)만 준비했다."},
    }
    text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if len(sys.argv) > 1:
        Path(sys.argv[1]).write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    _ = (approve_record, resolve_finding)
    return 0


if __name__ == "__main__":
    sys.exit(main())
