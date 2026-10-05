"""
오철칙 수정 부채 표시: 원본과 후보를 같은 정책으로 점검한 두 보고서를 비교해, 수정이 해결한 지적과 새로 만든 지적을
AI 코드의 다섯 습관(하드코딩·구조 붕괴·삼킨 예외·중복 헬퍼·타입 회피)별로 해결·유지·신규·이동으로 나눠 보여 준다.
- 표시만 한다. 판정(통과·실패)에 연결하지 않으며, 탑재된 규칙 범위 안의 변화일 뿐 코드 품질의 보증이 아니다.
- 지적의 짝짓기는 (규칙, 함수, 정규화한 코드 모양)이 같은 것끼리 한다. 같은 경로면 유지, 다른 경로이고 양쪽에 하나뿐이면 이동,
  짝이 여럿이라 하나로 정할 수 없는 것은 판정 불가로 따로 센다(추정으로 이어 붙이지 않는다).
- 수정 지점과 같은 함수 안에서 새로 생긴 습관 지적은 따로 적는다. 경고를 없애는 대신 가리는 수정의 전형이기 때문이다.
작성자: 최진호
작성일: 2026-10-05
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from iron_laws.core.models import AuditReport, Violation

MAPPING_VERSION = "debt-map/1"

HABIT_OF_RULE: dict[str, str] = {
    "AI-101": "hardcoding",
    "AI-102": "hardcoding",
    "IL-101": "hardcoding",
    "ARC-205": "hardcoding",
    "ARC-201": "structure",
    "ARC-202": "structure",
    "ARC-203": "structure",
    "ARC-207": "structure",
    "IL-301": "swallowed_exception",
    "IL-304": "swallowed_exception",
    "AI-120": "swallowed_exception",
    "ARC-204": "duplicate_helper",
    "TYP-301": "typing",
    "TYP-302": "typing",
    "TYP-303": "typing",
    "TYP-304": "typing",
    "TYP-305": "typing",
}
HABITS = ("hardcoding", "structure", "swallowed_exception", "duplicate_helper", "typing")
LIMITS = (
    "다섯 습관에 대응하는 규칙의 지적만 비교한다(대응표 debt-map/1). 대응하지 않는 규칙의 변화는 이 표에 없다.",
    "중복 헬퍼 규칙(ARC-204)에는 토큰·줄 수 임계가 있어 임계 미만의 짧은 함수 복제는 탐지하지 않는다.",
    "짝짓기는 규칙·함수·코드 모양이 같은 지적끼리만 한다. 코드 모양이 바뀐 지적은 해결과 신규로 나뉠 수 있다.",
    "표시는 판정이 아니다. 신규 부채가 없다는 것이 수정의 안전성이나 품질을 뜻하지 않는다.",
)


@dataclass
class _Side:
    violation: Violation
    matched: bool = False


@dataclass
class DebtDelta:
    habits: dict[str, dict[str, int]] = field(default_factory=lambda: {h: {"resolved": 0, "maintained": 0, "new": 0, "moved": 0, "undetermined": 0} for h in HABITS})
    fix_adjacent_new: list[dict[str, Any]] = field(default_factory=list)
    details: dict[str, list[dict[str, Any]]] = field(default_factory=lambda: {"resolved": [], "new": [], "moved": [], "undetermined": []})

    def to_dict(self) -> dict[str, Any]:
        totals = {k: sum(h[k] for h in self.habits.values()) for k in ("resolved", "maintained", "new", "moved", "undetermined")}
        return {
            "mapping_version": MAPPING_VERSION,
            "habits": self.habits,
            "totals": totals,
            "fix_adjacent_new": self.fix_adjacent_new,
            "details": self.details,
            "limits": list(LIMITS),
        }


def _loose(v: Violation) -> tuple[str, str, str]:
    return (v.rule_id, v.scope_name, v.shape)


def _row(v: Violation) -> dict[str, Any]:
    return {"rule": v.rule_id, "path": v.file_path.as_posix(), "line": v.line_number, "scope": v.scope_name, "finding_id": v.finding_id}


def compare(original: AuditReport, candidate: AuditReport) -> DebtDelta:
    """원본·후보 보고서의 습관 지적을 짝지어 네 칸으로 센다."""
    delta = DebtDelta()
    candidate_paths = {f.path for f in candidate.coverage_ledger.files} if candidate.coverage_ledger is not None else set()
    before: dict[tuple[str, str, str], list[_Side]] = defaultdict(list)
    after: dict[tuple[str, str, str], list[_Side]] = defaultdict(list)
    for report, bucket in ((original, before), (candidate, after)):
        for v in report.violations:
            if v.rule_id in HABIT_OF_RULE:
                bucket[_loose(v)].append(_Side(v))
    for key in set(before) | set(after):
        olds, news = before.get(key, []), after.get(key, [])
        # 1) 같은 경로에서 같은 모양: 유지(지문이 같은 것부터, 다음으로 경로가 같은 것)
        for old in olds:
            for new in news:
                if not new.matched and not old.matched and old.violation.file_path == new.violation.file_path:
                    old.matched = new.matched = True
                    delta.habits[HABIT_OF_RULE[key[0]]]["maintained"] += 1
                    break
        rest_old = [o for o in olds if not o.matched]
        rest_new = [n for n in news if not n.matched]
        # 2) 경로가 달라진 나머지: 양쪽에 하나뿐이면 이동, 여럿이면 하나로 정할 수 없어 판정 불가
        habit = HABIT_OF_RULE[key[0]]
        if rest_old and rest_new:
            if len(rest_old) == 1 and len(rest_new) == 1 and rest_old[0].violation.file_path.as_posix() in candidate_paths:
                continue  # 원래 파일이 후보에도 있다. 옮긴 것이 아니라 한쪽이 해결되고 다른 쪽에 새로 생겼거나 복제된 것이다
            if len(rest_old) == 1 and len(rest_new) == 1:
                rest_old[0].matched = rest_new[0].matched = True
                delta.habits[habit]["moved"] += 1
                delta.details["moved"].append({**_row(rest_new[0].violation), "from": rest_old[0].violation.file_path.as_posix()})
            else:
                for side in rest_old + rest_new:
                    side.matched = True
                delta.habits[habit]["undetermined"] += len(rest_old) + len(rest_new)
                delta.details["undetermined"].extend(_row(s.violation) for s in rest_old + rest_new)
            continue
    resolved_rows: list[tuple[str, str]] = []
    for key, sides in before.items():
        for side in sides:
            if not side.matched:
                delta.habits[HABIT_OF_RULE[key[0]]]["resolved"] += 1
                delta.details["resolved"].append(_row(side.violation))
                resolved_rows.append((side.violation.file_path.as_posix(), side.violation.scope_name))
    # 수정 지점: 원본에 있던 어떤 규칙의 지적이 후보에서 사라진 함수(습관에 속하지 않는 규칙의 지적도 포함한다)
    fix_points = set(resolved_rows)
    candidate_keys = {(v.rule_id, v.file_path.as_posix(), v.scope_name, v.shape) for v in candidate.violations}
    for v in original.violations:
        if v.rule_id not in HABIT_OF_RULE and (v.rule_id, v.file_path.as_posix(), v.scope_name, v.shape) not in candidate_keys:
            fix_points.add((v.file_path.as_posix(), v.scope_name))
    for key, sides in after.items():
        for side in sides:
            if side.matched:
                continue
            habit = HABIT_OF_RULE[key[0]]
            delta.habits[habit]["new"] += 1
            row = _row(side.violation)
            delta.details["new"].append(row)
            location = (side.violation.file_path.as_posix(), side.violation.scope_name)
            if side.violation.scope_name and location in fix_points:
                delta.fix_adjacent_new.append({**row, "habit": habit})
    for bucket in (delta.details["resolved"], delta.details["new"], delta.details["moved"], delta.details["undetermined"], delta.fix_adjacent_new):
        bucket.sort(key=lambda r: (r["path"], r["line"], r["rule"]))
    return delta
