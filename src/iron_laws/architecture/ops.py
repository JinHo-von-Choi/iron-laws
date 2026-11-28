"""
오철칙 운영 준비도: 웹 서비스를 계속 돌리는 데 필요한 기본 장치를 규칙 결과로 모아 한 표로 보여 준다.
구조 진단(architecture)의 선택 필드 ops_readiness로 나가며, 고정 지표와 compare()에는 들어가지 않는다.
작성자: 최진호
작성일: 2026-11-28
"""

from pathlib import Path

from iron_laws.core.config import IronLawsConfig

ITEMS = (
    ("OPS-101", "CI가 시험을 돌린다"),
    ("OPS-102", "DB 구조 변경을 마이그레이션으로 기록한다"),
    ("OPS-103", "컨테이너 배포에 상태 확인이 있다"),
    ("AI-111", "의존성 버전을 고정한다"),
    ("AI-104", "비밀 파일(.env, 개인키)을 저장소에 올리지 않는다"),
    ("ARC-206", "시험이 있다"),
)
SERVICE_ONLY = frozenset({"OPS-101", "OPS-102", "OPS-103"})


def readiness(path: Path, config: IronLawsConfig | None = None) -> list[dict]:
    """항목마다 상태(지적 있음·점검함·해당 없음)와 지적 위치. 운영 규칙은 웹 라우트가 있을 때만 적용하므로 라우트가 없으면 해당 없음이다"""
    from iron_laws.core.scanner import AuditScanner

    base = (config or IronLawsConfig()).model_copy(deep=True)
    base.enabled_rules = [rule_id for rule_id, _ in ITEMS]
    base.disabled_rules = [r for r in base.disabled_rules if r not in base.enabled_rules]
    report = AuditScanner(path, config=base).scan()
    service = bool((report.metadata.get("routes") or {}).get("total"))
    rows = []
    for rule_id, label in ITEMS:
        hits = [v for v in report.violations if v.rule_id == rule_id]
        if hits:
            state = "지적 있음"
        elif rule_id in SERVICE_ONLY and not service:
            state = "해당 없음(웹 라우트 없음)"
        else:
            state = "점검함·지적 없음"
        rows.append({"rule_id": rule_id, "item": label, "state": state, "where": [f"{v.file_path.as_posix()}:{v.line_number}" for v in hits[:3]]})
    return rows


def markdown_section(rows: list[dict]) -> str:
    lines = ["## 운영 준비도", "", "| 항목 | 규칙 | 상태 | 위치 |", "|---|---|---|---|"]
    lines.extend(f"| {r['item']} | {r['rule_id']} | {r['state']} | {', '.join(r['where']) or '-'} |" for r in rows)
    lines.append("")
    lines.append("파일과 설정만 보고 판정합니다. CI가 최근에 성공했는지, 상태 확인 주소가 실제로 응답하는지는 확인하지 않습니다.")
    return "\n".join(lines)
