"""
오철칙 경쟁력 강화 계획의 실험 표본을 측정하고 원시 결과를 남긴다.

사용법:
    uv run python benchmarks/plan_experiments.py [결과.json]

측정 대상(모두 구현자가 직접 만들고 분류한 표본이다. 독립 검토자의 분류가 아니며 효과 주장의 근거가 아니다):
- 검사 공백 장부: 알려진 공백 30개가 모두 드러나는지, 안전한 변경 30개가 불필요하게 차단되는 비율
- 회귀시험: 재현 가능한 결함 30개에서 시험 후보 생성 비율, 정답 수정 수용, 잘못된 수정 수용
- 패치 검증 종합: 정확한 수정·경고를 가린 수정·기능을 훼손한 수정에서 해로운 수정 수용 건수
- 승인 추적: 안전한 변형의 불필요한 재검토 비율, 위험한 변화의 잘못된 승계 건수
시험용 대역 실행기(호스트 실행)를 쓰므로 격리 실행의 성능·안전은 이 측정에 포함되지 않는다.
작성자: 최진호
작성일: 2026-10-04
"""

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from iron_laws.core.scanner import AuditScanner, tool_version  # noqa: E402
from iron_laws.verify.engine import VerifyOptions, verify_patch  # noqa: E402
from iron_laws.verify.regression import dump_spec  # noqa: E402
from tests import test_stage2_contract as s2  # noqa: E402
from tests import test_stage4_regression as s4  # noqa: E402
from tests import test_stage5_approvals as s5  # noqa: E402
from tests.regression_corpus import SUPPORTED, bad_fixes  # noqa: E402
from tests.runner_doubles import LocalTestRunner  # noqa: E402
from tests.test_stage3_verify import make_diff  # noqa: E402


def scratch() -> Path:
    return Path(tempfile.mkdtemp(prefix="iron-laws-exp-"))


def ledger_experiment() -> dict:
    exposed = 0
    for _name, files, family, line, state in s2.KNOWN_GAPS:
        report = s2._scan(scratch(), files)
        points = [p for p in report.coverage_ledger.points if p.family == family and p.line == line]
        exposed += bool(points) and all(p.state == state for p in points)
    blocked = 0
    for _name, files in s2.SAFE_CHANGES:
        blocked += s2._scan(scratch(), files).coverage_ledger.status == "unmet"
    return {
        "known_gaps": len(s2.KNOWN_GAPS),
        "gaps_exposed": exposed,
        "safe_changes": len(s2.SAFE_CHANGES),
        "safe_changes_blocked": blocked,
        "unnecessary_block_rate": round(blocked / len(s2.SAFE_CHANGES), 3),
    }


def regression_experiment() -> dict:
    from tests.regression_corpus import CASES

    generated = 0
    for case in CASES:
        project = s4.write_project(scratch() / "proj", case.vulnerable)
        generated += s4.propose(project, case) is not None
    correct = wrong = wrong_total = 0
    for case in SUPPORTED:
        base = scratch()
        project = s4.write_project(base / "proj", case.vulnerable)
        spec = s4.propose(project, case)
        correct += s4.check(base, project, case.fix, spec).result == "pass"
        for name, code in bad_fixes(case).items():
            wrong_total += 1
            wrong += s4.check(base, project, code, spec, patch_name=f"{name}.diff").result == "pass"
    return {
        "defects": len(CASES),
        "proposals_generated": generated,
        "generation_rate": round(generated / len(CASES), 3),
        "correct_fixes": len(SUPPORTED),
        "correct_fixes_accepted": correct,
        "wrong_fixes": wrong_total,
        "wrong_fixes_accepted": wrong,
    }


def hiding_variants(case) -> dict[str, str]:
    """경고만 숨기는 수정 6종"""
    vulnerable = case.vulnerable
    return {
        "ignore-comment": "# iron-laws: ignore-file[" + case.rule + "] 내부용이라 괜찮다\n" + vulnerable,
        "nosec": vulnerable + "# nosec\n",
        "try-except-swallow": vulnerable + "\n\ndef _wrapped():\n    try:\n        pass\n    except Exception:\n        pass\n",
        "comment-only": vulnerable + "# 보안 검토 완료\n",
        "noop-refactor": vulnerable + "\n\ndef _unused():\n    return None\n",
        "reformat": vulnerable.replace("    ", "\t"),
    }


def patch_experiment() -> dict:
    """정확한 수정 30·경고만 숨기는 수정 30·기능을 훼손하는 수정 30을 종합 검증(정적+회귀시험)에 넣는다."""
    runner = LocalTestRunner()
    outcomes = {"correct": [], "hiding": [], "breaking": []}
    cases = SUPPORTED
    for index in range(30):
        case = cases[index % len(cases)]
        base = scratch()
        project = s4.write_project(base / "proj", case.vulnerable)
        spec = s4.confirmed(s4.propose(project, case))
        spec_path = base / "spec.yml"
        spec_path.write_text(dump_spec(spec))

        def run(code: str, name: str, base=base, project=project, case=case, spec_path=spec_path) -> str:
            patch = base / f"{name}.diff"
            patch.write_text(make_diff(project, {"app.py": code}))
            options = VerifyOptions(finding=f"{case.rule}@app.py", runner="none", require_tests=False, regression_spec=spec_path)
            return verify_patch(project, patch, options, runner).verdict.overall

        fix = case.fix + (f"\n# 정확한 수정 변형 {index}\n" if index >= len(cases) else "")
        outcomes["correct"].append(run(fix, f"correct{index}"))
        hide = list(hiding_variants(case).values())[index % 6]
        outcomes["hiding"].append(run(hide, f"hide{index}"))
        breaking = list(bad_fixes(case).items())
        broken = [code for name, code in breaking if name in ("block-everything", "syntax-error")][index % 2]
        outcomes["breaking"].append(run(broken, f"break{index}"))
    return {
        "correct_total": 30,
        "correct_verified": outcomes["correct"].count("verified"),
        "hiding_total": 30,
        "hiding_accepted": outcomes["hiding"].count("verified"),
        "breaking_total": 30,
        "breaking_accepted": outcomes["breaking"].count("verified"),
        "verdicts": {k: {v: vs.count(v) for v in set(vs)} for k, vs in outcomes.items()},
    }


def approvals_experiment() -> dict:
    import shutil

    rereview = 0
    for _name, change in s5.SAFE:
        base = scratch()
        project = s5.make(base / "proj")
        store = base / "s.jsonl"
        approval_id = s5.approve(project, store)
        s5.apply_variant(project, change)
        rereview += s5.status(project, store)[approval_id][0] != "valid"
    inherited = 0
    total = 0
    for _name, files, change, expected in s5.RISKY:
        if expected in ("__rule_version__", "__contract__", "__expired__", "__clone__"):
            continue
        total += 1
        base = scratch()
        project = s5.make(base / "proj", files)
        store = base / "s.jsonl"
        approval_id = s5.approve(project, store, "IL-502@app.py" if files is s5.PATHY else "IL-504@app.py")
        change = dict(change)
        delete = change.pop("__delete__", None)
        s5.apply_variant(project, change)
        if delete:
            (project / delete).unlink()
        inherited += s5.status(project, store)[approval_id][0] == "valid"
    shutil.rmtree(scratch(), ignore_errors=True)
    return {
        "safe_changes": len(s5.SAFE),
        "unnecessary_re_review": rereview,
        "unnecessary_re_review_rate": round(rereview / len(s5.SAFE), 3),
        "risky_changes_evaluated": total,
        "dangerous_inheritance": inherited,
    }


def main() -> int:
    result = {
        "tool_version": tool_version(),
        "note": "구현자가 직접 만들고 분류한 표본이다. 독립 검토자의 분류가 아니며 효과 주장의 근거가 아니다. 호스트 실행 대역 실행기로 측정했다.",
        "ledger": ledger_experiment(),
        "regression": regression_experiment(),
        "patch_verification": patch_experiment(),
        "approvals": approvals_experiment(),
    }
    text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if len(sys.argv) > 1:
        Path(sys.argv[1]).write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    _ = AuditScanner
    return 0


if __name__ == "__main__":
    sys.exit(main())
