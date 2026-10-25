"""
오철칙 AI 습관 시계열: 점검마다 다섯 습관(하드코딩·구조 붕괴·삼킨 예외·중복 헬퍼·타입 회피)의 지적 수를 기록하고 추이를 보여 준다

- 기록 한 줄: 시각, 코드 지문, 점검 파일 수, 습관별 지적 수, 1천 줄당 지적 수. 코드·경로·메시지는 담지 않는다.
- 습관 대응은 수정 부채 표시와 같은 대응표(debt-map/1)를 쓴다. 표시는 판정이 아니다.
작성자: 최진호
작성일: 2026-10-12
"""

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from iron_laws.core.models import AuditReport
from iron_laws.verify.debt_delta import HABIT_OF_RULE, HABITS, MAPPING_VERSION


def snapshot(report: AuditReport, code_lines: int, timestamp: str | None = None) -> dict:
    counts = Counter(HABIT_OF_RULE[v.rule_id] for v in report.violations if v.rule_id in HABIT_OF_RULE)
    per_kloc = {h: round(counts.get(h, 0) * 1000 / code_lines, 3) if code_lines else 0.0 for h in HABITS}
    return {
        "timestamp": timestamp or datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "mapping": MAPPING_VERSION,
        "code_digest": report.execution.code_digest if report.execution else "",
        "files": report.summary.total_files_scanned,
        "code_lines": code_lines,
        "counts": {h: counts.get(h, 0) for h in HABITS},
        "per_kloc": per_kloc,
    }


def append(history: Path, record: dict) -> list[dict]:
    rows = load(history)
    if rows and rows[-1].get("code_digest") == record["code_digest"] and record["code_digest"]:
        rows[-1] = record  # 같은 코드를 다시 점검하면 마지막 기록을 바꾼다(같은 점을 두 번 찍지 않는다)
    else:
        rows.append(record)
    history.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    return rows


def load(history: Path) -> list[dict]:
    if not history.is_file():
        return []
    rows = []
    for line in history.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except ValueError:  # iron-laws: ignore[IL-301] 손상된 습관 기록 줄은 건너뛰고 나머지 줄로 집계한다
            continue
        if isinstance(row, dict) and isinstance(row.get("counts"), dict):
            rows.append(row)
    return rows


def trend(rows: list[dict]) -> dict[str, dict]:
    """습관별 처음·직전·최근 값과 직전 대비 변화(1천 줄당)"""
    if not rows:
        return {}
    first, last = rows[0], rows[-1]
    prev = rows[-2] if len(rows) > 1 else rows[-1]
    return {
        h: {
            "first": first["per_kloc"].get(h, 0.0), "previous": prev["per_kloc"].get(h, 0.0), "latest": last["per_kloc"].get(h, 0.0),
            "change": round(last["per_kloc"].get(h, 0.0) - prev["per_kloc"].get(h, 0.0), 3),
        }
        for h in HABITS
    }
