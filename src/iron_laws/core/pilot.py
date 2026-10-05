"""
오철칙 파일럿 준비: 새 검토 묶음이 검토 시간을 줄이는지, 위험한 승인을 늘리지 않는지를 팀 단위로 측정하기 위한 로컬 기록 도구
- 같은 PR을 두 조건에 노출하지 않는다. 조건(기존 방식 baseline / 검토 묶음 bundle)은 팀·난도층별 크기 2 블록으로 순서를 무작위 교차 배정한다.
- 기록은 로컬 JSONL이며 식별자(팀·PR 이름표)와 분 단위 수치만 담는다. 코드·개인정보·원문은 수집하지 않는다. 참여자가 동의한 집계만 공유한다.
- 이 모듈은 측정 도구이지 성과가 아니다. 요약의 기준값(설치 30분, 중앙값 30% 감소, 75백분위 악화 없음, 위험 수용 증가 없음)은 제안 목표이며
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
TARGETS = {"setup_minutes": 30, "median_reduction": 0.30}
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


def flag_risk(store: PilotStore, pr: str, kind: str, note: str = "") -> dict[str, Any]:
    if kind not in ("misaccept", "dangerous_inheritance"):
        raise ConfigError("kind는 misaccept 또는 dangerous_inheritance여야 합니다")
    assignment = store.assignment_of(pr)
    record = {"kind": "risk", "pr": pr, "risk": kind, "note": note[:200], "arm": assignment["arm"] if assignment else "", "team": assignment["team"] if assignment else ""}
    store.append(record)
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


def summarize(store: PilotStore) -> dict[str, Any]:
    rows = store.records()
    assigns = [r for r in rows if r["kind"] == "assign"]
    reviews = [r for r in rows if r["kind"] == "review"]
    risks = [r for r in rows if r["kind"] == "risk"]
    dropouts = [r for r in rows if r["kind"] == "dropout"]
    teams = sorted({r["team"] for r in assigns})
    arms: dict[str, Any] = {}
    for arm in ARMS:
        mine = [r for r in reviews if r["arm"] == arm]
        arms[arm] = {
            "review_minutes": _stats([r["minutes"] for r in mine]),
            "total_minutes": _stats([r["minutes"] + r["overhead_minutes"] for r in mine]),  # 선별·예외·유지보수 시간을 포함한 총 시간
            "risk_accepted": sum(1 for r in mine if r["risk_accepted"]),
            "flagged_risks": sum(1 for r in risks if r["arm"] == arm),
        }
    per_team = {t: {"assigned": sum(1 for r in assigns if r["team"] == t), "reviewed": sum(1 for r in reviews if r["team"] == t), "dropouts": sum(1 for r in dropouts if r["team"] == t)} for t in teams}
    setup = [r["setup_minutes"] for r in reviews if r["setup_minutes"]]
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
    base, bundle = arms["baseline"]["review_minutes"], arms["bundle"]["review_minutes"]
    comparison: dict[str, Any] = {"median_reduction": None, "p75_change": None}
    if base["n"] and bundle["n"] and base["median"]:
        comparison["median_reduction"] = round(1 - bundle["median"] / base["median"], 3)
        comparison["p75_change"] = round(bundle["p75"] - base["p75"], 2)
    checks = {
        "setup_within_30_minutes": (max(setup) <= TARGETS["setup_minutes"]) if setup else None,
        "median_reduction_at_least_30_percent": (comparison["median_reduction"] >= TARGETS["median_reduction"]) if comparison["median_reduction"] is not None else None,
        "p75_not_worse": (comparison["p75_change"] <= 0) if comparison["p75_change"] is not None else None,
        "no_risk_increase": arms["bundle"]["risk_accepted"] <= arms["baseline"]["risk_accepted"] and arms["bundle"]["flagged_risks"] == 0,
    }
    automation = "manual_review_only" if any(r["risk"] in ("misaccept", "dangerous_inheritance") for r in risks if r["arm"] == "bundle") else "allowed"
    if not sufficient:
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
        "verdict": verdict,
        "notes": [
            "기준값은 제안 목표이며 달성한 결과가 아닙니다. 표본이 부족하면 판정하지 않습니다.",
            "위험 수용이나 위험한 승인 승계가 한 건이라도 기록되면 관련 자동 경로를 수동 검토로 돌립니다(automation).",
            "작은 표본의 오류 0건은 일반 오류율 0을 뜻하지 않습니다.",
        ],
    }
