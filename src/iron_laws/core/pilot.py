"""
오철칙 파일럿 준비: 새 검토 묶음이 검토 시간을 줄이는지, 위험한 승인을 늘리지 않는지를 팀 단위로 측정하기 위한 로컬 기록 도구
- 같은 PR을 두 조건에 노출하지 않는다. 조건(기존 방식 baseline / 검토 묶음 bundle)은 팀·난도층별 크기 2 블록으로 순서를 무작위 교차 배정한다.
- 기록은 로컬 JSONL이며 식별자(팀·PR 이름표)와 분 단위 수치만 담는다. 코드·개인정보·원문은 수집하지 않는다. 참여자가 동의한 집계만 공유한다.
- 이 모듈은 측정 도구이지 성과가 아니다. 요약의 기준값(설치 30분, 총 능동시간 중앙값 20% 감소, 75백분위 악화 없음, 확인된 오승인 증가 없음)은 제안 목표이며
  표본이 부족하면 판정하지 않고 '표본 부족'으로 둔다. 작은 표본의 오류 0건은 일반 오류율 0을 뜻하지 않는다.
작성자: 최진호
작성일: 2026-10-05
"""

import json
import random
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from typing import Any

from iron_laws.core.config import ConfigError

PILOT_FILE = ".iron-laws-pilot.jsonl"
ARMS = ("baseline", "bundle")
TARGETS = {"setup_minutes": 30, "median_reduction": 0.20}
RISK_KINDS = ("misaccept", "dangerous_inheritance", "legitimate_exception")
BLOCKING_RISKS = ("misaccept", "dangerous_inheritance")
RISK_STATUS = ("confirmed", "investigating")
SAMPLE = {"teams_min": 3, "teams_max": 5, "per_team_min": 20, "total_min": 60, "total_max": 100}


@dataclass
class PilotStore:
    path: Path

    def records(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        rows = []
        for number, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ConfigError(f"파일럿 기록 {number}번째 줄을 읽을 수 없습니다: {e}") from e
        return rows

    def append(self, record: dict[str, Any]) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    def records_rewrite_last(self, record: dict[str, Any]) -> None:
        """방금 덧붙인 마지막 줄에 필드를 더해 다시 쓴다(기록을 지우지 않고 마지막 줄만 같은 사건의 완결본으로 바꾼다)."""
        lines = self.path.read_text(encoding="utf-8").splitlines()
        lines[-1] = json.dumps(record, ensure_ascii=False, sort_keys=True)
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def assignment_of(self, pr: str) -> dict[str, Any] | None:
        return next((r for r in self.records() if r["kind"] == "assign" and r["pr"] == pr), None)


def assign(store: PilotStore, team: str, pr: str, stratum: str, seed: int, reviewer: str = "") -> dict[str, Any]:
    """PR 하나를 한 번만 조건에 배정한다. 같은 (팀, 난도층) 안에서 두 PR마다 한 번씩 baseline·bundle이 나오고 그 순서만 무작위다."""
    if store.assignment_of(pr) is not None:
        raise ConfigError(f"이미 배정된 PR입니다(같은 PR을 두 조건에 노출하지 않습니다): {pr}")
    previous = [r for r in store.records() if r["kind"] == "assign" and r["team"] == team and r["stratum"] == stratum]
    block_index, offset = divmod(len(previous), 2)
    order = list(ARMS)
    random.Random(f"{seed}|{team}|{stratum}|{block_index}").shuffle(order)
    record = {"kind": "assign", "team": team, "pr": pr, "stratum": stratum, "arm": order[offset], "block": block_index, "reviewer": reviewer, "seed": seed}
    store.append(record)
    return record


def record_review(store: PilotStore, pr: str, minutes: float, setup_minutes: float = 0.0, overhead_minutes: float = 0.0, outcome: str = "", risk_accepted: bool = False) -> dict[str, Any]:
    assignment = store.assignment_of(pr)
    if assignment is None:
        raise ConfigError(f"배정되지 않은 PR입니다. 먼저 `pilot assign`으로 조건을 배정하십시오: {pr}")
    if any(r["kind"] == "review" and r["pr"] == pr for r in store.records()):
        raise ConfigError(f"이미 검토 결과가 기록된 PR입니다: {pr}")
    if minutes < 0 or setup_minutes < 0 or overhead_minutes < 0:
        raise ConfigError("시간은 0 이상이어야 합니다")
    record = {"kind": "review", "pr": pr, "team": assignment["team"], "arm": assignment["arm"], "stratum": assignment["stratum"], "minutes": minutes, "setup_minutes": setup_minutes, "overhead_minutes": overhead_minutes, "outcome": outcome, "risk_accepted": risk_accepted}
    store.append(record)
    return record


def flag_risk(store: PilotStore, pr: str, kind: str, note: str = "", status: str = "confirmed") -> dict[str, Any]:
    """위험 사건 기록. misaccept·dangerous_inheritance는 확인된 오승인이고, legitimate_exception은 정당한 예외 승인이라 오승인으로 세지 않는다.
    status가 investigating이면 조사 중인 사건이라 성과 판정에 넣지 않고 별도 상태로 남긴다."""
    if kind not in RISK_KINDS:
        raise ConfigError(f"kind는 {', '.join(RISK_KINDS)} 중 하나여야 합니다")
    if status not in RISK_STATUS:
        raise ConfigError(f"status는 {', '.join(RISK_STATUS)} 중 하나여야 합니다")
    assignment = store.assignment_of(pr)
    record = {"kind": "risk", "pr": pr, "risk": kind, "status": status, "note": note[:200], "arm": assignment["arm"] if assignment else "", "team": assignment["team"] if assignment else ""}
    store.append(record)
    return record


def close_risk(store: PilotStore, pr: str, kind: str, confirmed: bool, note: str = "") -> dict[str, Any]:
    """조사 중이던 사건을 확인(오승인 확정) 또는 기각(정당한 예외로 분류)한다. 기록은 지우지 않고 새 기록으로 덧붙인다."""
    records = [r for r in store.records() if r["kind"] == "risk" and r["pr"] == pr]
    opened = sum(1 for r in records if r["risk"] == kind and r.get("status") == "investigating")
    closed = sum(1 for r in records if r.get("closes") == kind)
    if opened <= closed:
        raise ConfigError(f"조사 중인 사건이 없습니다: {pr} ({kind})")
    resolved_kind = kind if confirmed else "legitimate_exception"
    record = flag_risk(store, pr, resolved_kind, note or ("조사 종료: 확인" if confirmed else "조사 종료: 정당한 예외"), "confirmed")
    record["closes"] = kind
    store.records_rewrite_last(record)
    return record


def record_dropout(store: PilotStore, team: str, reason: str) -> dict[str, Any]:
    record = {"kind": "dropout", "team": team, "reason": reason[:200]}
    store.append(record)
    return record


def _p75(values: list[float]) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = 0.75 * (len(ordered) - 1)
    low = int(index)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (index - low)


def _stats(values: list[float]) -> dict[str, Any]:
    return {"n": len(values), "median": round(median(values), 2) if values else None, "p75": round(_p75(values), 2) if values else None, "mean": round(sum(values) / len(values), 2) if values else None}


def _risk_view(rows: list[dict[str, Any]], reviews: list[dict[str, Any]]) -> dict[str, Any]:
    """위험 flag와 검토 기록을 한 집계에 넣는다. 확인된 오승인 / 조사 중 / 정당한 예외를 구분하고, PR당 한 번만 센다."""
    risks = [r for r in rows if r["kind"] == "risk"]
    closes: dict[tuple[str, str], int] = {}
    for r in risks:
        if r.get("closes"):
            closes[(r["pr"], r["closes"])] = closes.get((r["pr"], r["closes"]), 0) + 1
    opened: dict[tuple[str, str], int] = {}
    confirmed: dict[str, set[str]] = {arm: set() for arm in ARMS}
    investigating: dict[str, set[str]] = {arm: set() for arm in ARMS}
    exceptions: dict[str, set[str]] = {arm: set() for arm in ARMS}
    for r in risks:
        arm = r.get("arm") or ""
        if arm not in ARMS:
            continue
        status = r.get("status", "confirmed")
        if r["risk"] == "legitimate_exception":
            exceptions[arm].add(r["pr"])
        elif status == "investigating":
            key = (r["pr"], r["risk"])
            opened[key] = opened.get(key, 0) + 1
            if opened[key] > closes.get(key, 0):
                investigating[arm].add(r["pr"])
        elif r["risk"] in BLOCKING_RISKS:
            confirmed[arm].add(r["pr"])
    for r in reviews:  # 검토 기록의 결과 메모도 같은 집계에 넣는다
        if r.get("outcome") in BLOCKING_RISKS and r["arm"] in ARMS:
            confirmed[r["arm"]].add(r["pr"])
    return {"confirmed": confirmed, "investigating": investigating, "exceptions": exceptions}


def _rate(count: int, total: int) -> dict[str, Any]:
    return {"count": count, "of": total, "rate": round(count / total, 4) if total else None}


def summarize(store: PilotStore) -> dict[str, Any]:
    rows = store.records()
    assigns = [r for r in rows if r["kind"] == "assign"]
    reviews = [r for r in rows if r["kind"] == "review"]
    dropouts = [r for r in rows if r["kind"] == "dropout"]
    teams = sorted({r["team"] for r in assigns})
    risk_view = _risk_view(rows, reviews)
    bundle_reviews_by_team: dict[str, int] = {}
    for r in reviews:
        if r["arm"] == "bundle":
            bundle_reviews_by_team[r["team"]] = bundle_reviews_by_team.get(r["team"], 0) + 1
    setup_by_team: dict[str, float] = {}
    for r in reviews:
        if r["arm"] == "bundle":  # 설치·설정 시간은 도구를 쓰는 조건의 비용이다
            setup_by_team[r["team"]] = setup_by_team.get(r["team"], 0.0) + r["setup_minutes"]

    def total_with_setup(r: dict[str, Any]) -> float:
        extra = setup_by_team.get(r["team"], 0.0) / bundle_reviews_by_team[r["team"]] if r["arm"] == "bundle" and bundle_reviews_by_team.get(r["team"]) else 0.0
        return r["minutes"] + r["overhead_minutes"] + extra  # 설치·설정 시간을 그 팀의 bundle 검토 건수로 나눠 상각한 값

    arms: dict[str, Any] = {}
    for arm in ARMS:
        mine = [r for r in reviews if r["arm"] == arm]
        arms[arm] = {
            "review_minutes": _stats([r["minutes"] for r in mine]),  # 보조 지표(순수 검토 시간)
            "total_minutes": _stats([r["minutes"] + r["overhead_minutes"] for r in mine]),  # 주 지표(선별·예외·유지보수 시간을 포함한 총 능동 시간)
            "total_minutes_with_amortized_setup": _stats([total_with_setup(r) for r in mine]),  # 설치 상각 포함(보고용)
            "risk_accepted": sum(1 for r in mine if r["risk_accepted"]),
            "risk_accepted_rate": _rate(sum(1 for r in mine if r["risk_accepted"]), len(mine)),
            "confirmed_misaccepts": _rate(len(risk_view["confirmed"][arm]), len(mine)),
            "legitimate_exceptions": len(risk_view["exceptions"][arm]),
            "investigating": len(risk_view["investigating"][arm]),
            "flagged_risks": len(risk_view["confirmed"][arm]),
        }
    per_team = {t: {"assigned": sum(1 for r in assigns if r["team"] == t), "reviewed": sum(1 for r in reviews if r["team"] == t), "dropouts": sum(1 for r in dropouts if r["team"] == t)} for t in teams}
    setup = list(setup_by_team.values())  # 팀별 설치 시간의 합. 기록을 나눠 적어도 합쳐서 본다
    reasons: list[str] = []
    if not (SAMPLE["teams_min"] <= len(teams) <= SAMPLE["teams_max"]):
        reasons.append(f"팀 수 {len(teams)}(목표 {SAMPLE['teams_min']}~{SAMPLE['teams_max']})")
    short = [t for t, v in per_team.items() if v["reviewed"] < SAMPLE["per_team_min"]]
    if short or not teams:
        reasons.append(f"팀별 검토 {SAMPLE['per_team_min']}건 미만: {', '.join(short) or '기록 없음'}")
    if not (SAMPLE["total_min"] <= len(reviews) <= SAMPLE["total_max"]):
        reasons.append(f"전체 검토 {len(reviews)}건(목표 {SAMPLE['total_min']}~{SAMPLE['total_max']})")
    if any(len([r for r in reviews if r["arm"] == a]) == 0 for a in ARMS):
        reasons.append("한 조건의 검토 기록이 없다")
    sufficient = not reasons
    base, bundle = arms["baseline"]["total_minutes"], arms["bundle"]["total_minutes"]
    comparison: dict[str, Any] = {"basis": "total_minutes", "median_reduction": None, "p75_change": None, "review_only": {"median_reduction": None, "p75_change": None}}
    if base["n"] and bundle["n"] and base["median"]:
        comparison["median_reduction"] = round(1 - bundle["median"] / base["median"], 3)
        comparison["p75_change"] = round(bundle["p75"] - base["p75"], 2)
    rbase, rbundle = arms["baseline"]["review_minutes"], arms["bundle"]["review_minutes"]
    if rbase["n"] and rbundle["n"] and rbase["median"]:
        comparison["review_only"] = {"median_reduction": round(1 - rbundle["median"] / rbase["median"], 3), "p75_change": round(rbundle["p75"] - rbase["p75"], 2)}
    base_rate, bundle_rate = arms["baseline"]["risk_accepted_rate"]["rate"], arms["bundle"]["risk_accepted_rate"]["rate"]
    checks = {
        "setup_within_30_minutes": (max(setup) <= TARGETS["setup_minutes"]) if setup else None,
        "median_reduction_at_least_20_percent": (comparison["median_reduction"] >= TARGETS["median_reduction"]) if comparison["median_reduction"] is not None else None,
        "p75_not_worse": (comparison["p75_change"] <= 0) if comparison["p75_change"] is not None else None,
        "no_risk_increase": arms["bundle"]["flagged_risks"] == 0 and (bundle_rate is None or base_rate is None or bundle_rate <= base_rate),
    }
    pending = sum(len(v) for v in risk_view["investigating"].values())
    if risk_view["confirmed"]["bundle"]:
        automation = "manual_review_only"
    elif risk_view["investigating"]["bundle"]:
        automation = "pending_investigation"
    else:
        automation = "allowed"
    if pending:
        verdict = "investigation_pending"  # 조사가 끝나기 전에는 성과에 포함하지 않는다
    elif not sufficient:
        verdict = "insufficient_sample"
    elif all(v for v in checks.values() if v is not None) and all(v is not None for v in checks.values()):
        verdict = "targets_met"
    else:
        verdict = "targets_not_met"
    return {
        "teams": per_team,
        "arms": arms,
        "comparison": comparison,
        "checks": checks,
        "sample": {"sufficient": sufficient, "reasons": reasons, "reviews": len(reviews), "targets": SAMPLE},
        "dropouts": len(dropouts),
        "automation": automation,
        "investigating": pending,
        "verdict": verdict,
        "notes": [
            "기준값은 제안 목표이며 달성한 결과가 아닙니다. 표본이 부족하면 판정하지 않습니다.",
            "확인된 오승인이나 위험한 승인 승계가 한 건이라도 기록되면 관련 자동 경로를 수동 검토로 돌립니다(automation). 조사 중인 사건은 별도 상태이며 조사가 끝나기 전에는 성과에 포함하지 않습니다.",
            "주 지표는 총 능동 시간(검토+추가 시간)이다. 순수 검토 시간은 보조 지표이고, 설치 시간의 상각값은 보고만 한다.",
            "작은 표본의 오류 0건은 일반 오류율 0을 뜻하지 않습니다.",
        ],
    }
