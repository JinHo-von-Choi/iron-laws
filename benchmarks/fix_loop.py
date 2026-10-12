"""
AI 수정 성공률 측정: 지적 하나마다 AI가 만든 패치를 같은 정책·조건으로 검증하고 결과를 나눠 센다

사용법:
    uv run python benchmarks/fix_loop.py <사례목록.json> [원시결과.json] [--runner auto|docker|bwrap|none]

사례 목록(JSON 배열): {"id", "project"(원본 폴더), "patch"(unified diff), "finding"(지문 접두사·RULE@경로:줄),
                       "regression_spec"(선택), "test_cmd"(선택, 인자 배열)}. 상대 경로는 사례 목록 파일 기준이다.

결과 하나는 다음 중 하나다(앞의 것이 우선).
- bypass: 시험 삭제·무시 주석·정책 약화 같은 우회 변경이 있다(지적이 사라졌어도 수정으로 세지 않는다)
- tests_failed: 기존 시험이 원본에서는 통과하는데 수정본에서 실패한다
- undeterminable: 검증을 끝내지 못했다(격리 실행 불가, 패치 적용 실패 등)
- static_not_resolved: 대상 지적이 남아 있다
- behavior_not_removed: 회귀 명세의 결함 행동이 수정본에서도 재현된다
- resolved_with_new_debt: 해결했지만 수정 지점과 같은 함수에 새 부채(삼킨 예외·타입 회피 등)를 만들었다
- new_findings: 대상 지적은 사라졌지만 수정본에 HIGH 이상 지적이 새로 생겼다
- check_failed: 그 밖의 검증 항목(적용 범위·검사 범위 축소 등)이 실패했다
- resolved: 대상 지적이 사라졌고(회귀 명세가 있으면 결함 행동도 사라짐) 위 문제가 없다
정적 지적 소멸과 결함 행동 제거는 따로도 센다. 회귀 명세가 없는 사례의 결함 행동 제거는 '측정 안 함'이다.
작성자: 최진호
작성일: 2026-10-12
"""

import json
import sys
from collections import Counter
from pathlib import Path

from iron_laws.verify.engine import VerifyOptions, verify_patch
from iron_laws.verify.receipt import Receipt

OUTCOMES = ("bypass", "tests_failed", "undeterminable", "static_not_resolved", "behavior_not_removed", "resolved_with_new_debt", "new_findings", "check_failed", "resolved")


def classify(receipt: Receipt) -> dict:
    checks = {c.id: c.result for c in receipt.checks}
    static = checks.get("target_resolved")
    behavior = checks.get("regression_test", "not_measured")
    new_debt = bool((receipt.debt_delta or {}).get("fix_adjacent_new"))
    if receipt.bypass_changes:
        outcome = "bypass"
    elif checks.get("existing_tests") == "fail":
        outcome = "tests_failed"
    elif receipt.verdict.overall == "undeterminable" and static != "fail":
        outcome = "undeterminable"
    elif static != "pass":
        outcome = "static_not_resolved"
    elif behavior == "fail":
        outcome = "behavior_not_removed"
    elif new_debt:
        outcome = "resolved_with_new_debt"  # 수정 지점의 새 부채(삼킨 예외 등)는 새 지적이기도 하지만 더 구체적인 이 분류로 센다
    elif checks.get("no_new_findings") == "fail":
        outcome = "new_findings"
    elif any(result == "fail" for result in checks.values()):
        outcome = "check_failed"
    else:
        outcome = "resolved"
    return {"outcome": outcome, "static_finding_resolved": static, "defect_behavior_removed": behavior, "new_debt": new_debt, "verdict": receipt.verdict.overall}


def run(manifest: Path, runner: str = "auto") -> dict:
    base = manifest.parent
    cases = json.loads(manifest.read_text(encoding="utf-8"))
    rows = []
    for case in cases:
        spec = case.get("regression_spec")
        options = VerifyOptions(
            finding=case.get("finding"),
            test_cmd=case.get("test_cmd"),
            runner=runner,
            require_tests=bool(case.get("test_cmd")),
            regression_spec=(base / spec) if spec else None,
        )
        receipt = verify_patch(base / case["project"], base / case["patch"], options)
        rows.append({"id": case["id"], **classify(receipt), "receipt_digest": receipt.receipt_digest})
    counts = Counter(r["outcome"] for r in rows)
    measured_behavior = [r for r in rows if r["defect_behavior_removed"] != "not_measured"]
    return {
        "cases": len(rows),
        "outcomes": {k: counts.get(k, 0) for k in OUTCOMES},
        "static_resolved_rate": round(sum(1 for r in rows if r["static_finding_resolved"] == "pass") / len(rows), 4) if rows else 0.0,
        "behavior_removed_rate": round(sum(1 for r in measured_behavior if r["defect_behavior_removed"] == "pass") / len(measured_behavior), 4) if measured_behavior else None,
        "success_rate": round(counts.get("resolved", 0) / len(rows), 4) if rows else 0.0,
        "rows": rows,
    }


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--runner")]
    runner_arg = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--runner=")), "auto")
    if not args:
        print(__doc__)
        sys.exit(2)
    result = run(Path(args[0]), runner_arg)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if len(args) > 1:
        Path(args[1]).write_text(text + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "rows"}, ensure_ascii=False, indent=2))
