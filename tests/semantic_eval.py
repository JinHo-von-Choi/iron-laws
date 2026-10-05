"""
오철칙 v1.3 의미 변형 평가기: 사례집(`semantic_corpus.py`, `semantic_holdout.py`)을 돌려 위험 미탐·정상 오차단·판정 변화·보류(unknown)를
원본 수와 변형 수를 나눠서 센다. 개발용과 평가용(holdout)은 같은 평가기로 따로 돌린다.
작성자: 최진호
작성일: 2026-10-05
"""

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from statistics import median

from iron_laws.core.approvals import ApprovalStore
from iron_laws.core.models import Confidence
from iron_laws.core.scanner import AuditScanner
from iron_laws.reporters.json_reporter import generate_json_report
from iron_laws.reporters.markdown import generate_markdown_report
from iron_laws.reporters.prompt import generate_fix_prompt
from iron_laws.reporters.sarif import generate_sarif_report
from tests.semantic_corpus import OPERATORS, ApprovalCase, OutputCase, ScanCase, render
from tests.test_stage5_approvals import BASE, RULE, apply_variant, approve, make

TmpFactory = Callable[[str], Path]


@dataclass
class Outcome:
    case_id: str
    form: str  # benign / risky
    operator: str  # original / 연산 이름
    verdict: str  # confirmed / review / clean
    seconds: float


@dataclass
class ScanMetrics:
    outcomes: list[Outcome] = field(default_factory=list)

    def _pick(self, form: str, original: bool | None = None) -> list[Outcome]:
        return [o for o in self.outcomes if o.form == form and (original is None or (o.operator == "original") == original)]

    def summary(self) -> dict:
        def count(form: str, original: bool, verdict: str) -> int:
            return sum(1 for o in self._pick(form, original) if o.verdict == verdict)

        base = {o.case_id: {} for o in self.outcomes}
        for o in self.outcomes:
            base[o.case_id].setdefault(o.form, {})[o.operator] = o.verdict
        flips = {"benign": 0, "risky": 0}
        for per_form in base.values():
            for form, by_op in per_form.items():
                origin = by_op.get("original")
                flips[form] += sum(1 for op, verdict in by_op.items() if op != "original" and verdict != origin)
        by_operator: dict[str, dict[str, int]] = {}
        for o in self.outcomes:
            if o.operator == "original":
                continue
            row = by_operator.setdefault(o.operator, {"variants": 0, "flips": 0})
            row["variants"] += 1
            origin = base[o.case_id][o.form]["original"]
            row["flips"] += o.verdict != origin
        seconds = [o.seconds for o in self.outcomes]
        cases = {o.case_id for o in self.outcomes}
        return {
            "base_cases": len(cases),
            "originals": {"risky": len(self._pick("risky", True)), "benign": len(self._pick("benign", True))},
            "variants": {"risky": len(self._pick("risky", False)), "benign": len(self._pick("benign", False))},
            "risk_miss": {
                "original": sum(1 for o in self._pick("risky", True) if o.verdict != "confirmed"),
                "variant": sum(1 for o in self._pick("risky", False) if o.verdict != "confirmed"),
            },
            "benign_blocked": {
                "original": count("benign", True, "confirmed"),
                "variant": count("benign", False, "confirmed"),
            },
            "unknown": {
                "risky": sum(1 for o in self._pick("risky") if o.verdict == "review"),
                "benign": sum(1 for o in self._pick("benign") if o.verdict == "review"),
            },
            "verdict_flips": flips,
            "by_operator": by_operator,
            "seconds_total": round(sum(seconds), 2),
            "seconds_median": round(median(seconds), 4) if seconds else 0.0,
        }

    def failures(self) -> list[Outcome]:
        return [o for o in self.outcomes if (o.form == "risky" and o.verdict != "confirmed") or (o.form == "benign" and o.verdict == "confirmed")]


def _verdict(root: Path, case: ScanCase, code: str) -> tuple[str, float]:
    started = time.perf_counter()
    root.mkdir(parents=True, exist_ok=True)
    (root / f"app{case.ext}").write_text(code, encoding="utf-8")
    for name, content in case.files.items():
        (root / name).write_text(content, encoding="utf-8")
    violations = [v for v in AuditScanner(root).scan().violations if v.rule_id == case.rule]
    elapsed = time.perf_counter() - started
    if any(v.confidence is Confidence.CONFIRMED for v in violations):
        return "confirmed", elapsed
    return ("review" if violations else "clean"), elapsed


def evaluate_scan(cases: list[ScanCase], tmp: TmpFactory) -> ScanMetrics:
    metrics = ScanMetrics()
    for case in cases:
        for form, code in (("benign", case.benign), ("risky", case.risky)):
            for operator in ("original", *OPERATORS):
                text = render(code, case.ext, None if operator == "original" else operator)
                verdict, seconds = _verdict(tmp(f"{case.id}_{form}_{operator}"), case, text)
                metrics.outcomes.append(Outcome(case.id, form, operator, verdict, seconds))
    return metrics


# ---------------------------------------------------------------------------
# 승인
# ---------------------------------------------------------------------------


def evaluate_approvals(cases: list[ApprovalCase], tmp: TmpFactory) -> dict:
    results = {"cases": len(cases), "unnecessary_re_review": 0, "dangerous_inheritance": 0, "details": []}
    for case in cases:
        for form, change in (("benign", case.benign_change), ("risky", case.risky_change)):
            base = tmp(f"{case.id}_{form}")
            project = make(base / "proj", case.base if case.base is not None else BASE)
            store = base / "s.jsonl"
            days = case.benign_expires if form == "benign" else case.risky_expires
            expires = date.today() + timedelta(days=days) if days is not None else None
            approval_id = approve(project, store, case.finding or RULE, expires=expires)
            apply_variant(project, change)
            scanner = AuditScanner(project, approvals=ApprovalStore(store))
            report = scanner.scan()
            row = next(r for r in scanner.approval_rows if r.approval.id == approval_id)
            if form == "benign" and row.status != "valid":
                results["unnecessary_re_review"] += 1
                results["details"].append((case.id, form, row.status, row.reasons[:2]))
            if form == "risky":
                if case.risky_expect == "clone_not_approved":
                    inherited = any(v.approval_status == "approved" and v.file_path.as_posix() != "app.py" for v in report.violations)
                else:
                    inherited = row.status == "valid"
                if inherited:
                    results["dangerous_inheritance"] += 1
                    results["details"].append((case.id, form, row.status, row.reasons[:2]))
    return results


# ---------------------------------------------------------------------------
# 출력과 억제
# ---------------------------------------------------------------------------


def _all_outputs(report) -> str:
    return "\n".join(
        [
            generate_json_report(report),
            generate_sarif_report(report, AuditScanner(Path('.')).rules),
            generate_markdown_report(report),
            generate_fix_prompt(report, 0),
        ]
    )


def evaluate_output(cases: list[OutputCase], tmp: TmpFactory) -> dict:
    results = {"cases": len(cases), "mishandled": 0, "details": []}
    for case in cases:
        for form, spec in (("benign", case.benign), ("risky", case.risky)):
            root = tmp(f"{case.id}_{form}")
            root.mkdir(parents=True, exist_ok=True)
            (root / spec["file"]).write_text(spec["text"], encoding="utf-8")
            report = AuditScanner(root).scan()
            if case.kind == "suppression":
                present = any(v.rule_id == spec["rule"] for v in report.violations)
                # 전제 확인: 억제 지시문이 없으면 이 규칙의 지적이 실제로 나오는 입력이어야 한다(탐지가 안 되는 입력으로 억제를 시험하지 않는다)
                control = tmp(f"{case.id}_{form}_control")
                control.mkdir(parents=True, exist_ok=True)
                (control / spec["file"]).write_text(re.sub(r"iron-laws:\s*ignore(-file)?", "iron-laws: noop", spec["text"]), encoding="utf-8")
                detectable = any(v.rule_id == spec["rule"] for v in AuditScanner(control).scan().violations)
                ok = detectable and ((not present) if spec["suppressed"] else present)
            else:
                blob = _all_outputs(report)
                ok = not any(s in blob or s[:12] in blob or s[-12:] in blob for s in spec["secrets"])
            if not ok:
                results["mishandled"] += 1
                results["details"].append((case.id, form))
    return results
