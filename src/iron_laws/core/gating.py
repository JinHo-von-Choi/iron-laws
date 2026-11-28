"""
오철칙 통과 판정의 단계별 차단 정책: 설정의 stage(prototype·launch·production)에 따라 어떤 지적이 통과를 막는지 정한다.

- stage가 없으면 지금처럼 fail_on 이상 심각도의 지적이 막는다.
- prototype: 비밀값 노출 규칙과 확정 CRITICAL 지적만 막는다.
- launch: 위에 더해 인증 없는 관리 기능(IL-525), CI 시험(OPS-101), DB 마이그레이션(OPS-102), 보안 계열 규칙의 확정 지적 가운데 fail_on 이상 심각도를 막는다.
- production: 위에 더해 모든 규칙의 fail_on 이상 지적, 중복 함수(ARC-204), 구조 계약 위반(ARC-207), 컨테이너 상태 확인(OPS-103)을 막는다.
  기준선을 쓰면 기준선에 없던 지적만 센다(이미 있던 중복은 막지 않는다).
정책은 보고서 metadata.stage_policy에 그대로 적어, 독립 검증기가 엔진 코드 없이 같은 판정을 다시 계산할 수 있게 한다.
작성자: 최진호
작성일: 2026-11-28
"""

STAGES = ("prototype", "launch", "production")
SECRET_RULES = ("AI-102", "AI-103", "AI-104", "IL-101")
LAUNCH_RULES = ("IL-525", "OPS-101", "OPS-102")
PRODUCTION_RULES = ("ARC-204", "ARC-207", "OPS-103")
SECURITY_LAYERS = ("AI_ATTACK", "AI_CODE", "STANDARD")
SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
STAGE_QUESTIONS = {
    "prototype": "내 PC에서만 돌려 본다",
    "launch": "링크를 공유하거나 시험 배포한다",
    "production": "실제 사용자·결제가 있다",
}


def stage_policy(stage: str | None, fail_on: str) -> dict | None:
    """보고서에 적을 차단 정책. stage가 없으면 None이며 fail_on만으로 판정한다."""
    if stage is None:
        return None
    if stage not in STAGES:
        raise ValueError(f"알 수 없는 단계입니다: {stage} (prototype, launch, production 가운데 하나)")
    always = list(SECRET_RULES)
    if stage in ("launch", "production"):
        always += LAUNCH_RULES
    if stage == "production":
        always += PRODUCTION_RULES
    return {
        "stage": stage,
        "always_block_rules": sorted(always),
        "block_confirmed_critical": True,
        "threshold": fail_on,
        "threshold_layers": "all" if stage == "production" else list(SECURITY_LAYERS) if stage == "launch" else [],
        "threshold_confirmed_only": stage == "launch",
    }


def blocks(rule_id: str, severity: str, confidence: str, layer: str, policy: dict | None, fail_on: str) -> bool:
    """이 지적이 통과를 막는가. 값은 보고서 JSON과 같은 문자열(심각도 CRITICAL, 확정 여부 CONFIRMED 등)로 받는다."""
    rank = SEVERITY_RANK.get(severity, 0)
    if policy is None:
        return rank >= SEVERITY_RANK.get(fail_on, 2)
    if rule_id in policy["always_block_rules"]:
        return True
    if policy["block_confirmed_critical"] and confidence == "CONFIRMED" and severity == "CRITICAL":
        return True
    layers = policy["threshold_layers"]
    if layers != "all" and layer not in layers:
        return False
    if policy["threshold_confirmed_only"] and confidence != "CONFIRMED":
        return False
    return rank >= SEVERITY_RANK.get(policy["threshold"], 2)
