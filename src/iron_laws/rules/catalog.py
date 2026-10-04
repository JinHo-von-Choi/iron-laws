"""
오철칙 Rule Registry & Catalog
작성자: 최진호
작성일: 2026-10-04
"""

from iron_laws.core.config import ConfigError, IronLawsConfig
from iron_laws.rules.ai_code import AI_RULES
from iron_laws.rules.architecture import ARCH_RULES
from iron_laws.rules.base import BaseRule
from iron_laws.rules.code_quality import CODE_QUALITY_RULES
from iron_laws.rules.errors import ERROR_RULES
from iron_laws.rules.injection import INJECTION_RULES
from iron_laws.rules.review_rules import REVIEW_RULES
from iron_laws.rules.secrets_crypto import SECRETS_CRYPTO_RULES
from iron_laws.rules.typing_rules import TYPING_RULES

ALL_RULES: list[type[BaseRule]] = [
    *SECRETS_CRYPTO_RULES,
    *ERROR_RULES,
    *INJECTION_RULES,
    *CODE_QUALITY_RULES,
    *AI_RULES,
    *ARCH_RULES,
    *TYPING_RULES,
    *REVIEW_RULES,
]


def get_active_rules(
    enabled: list[str] | None = None,
    disabled: list[str] | None = None,
    config: IronLawsConfig | None = None,
) -> list[BaseRule]:
    """설정에 따라 활성화된 규칙 인스턴스 리스트 생성"""
    instances = [cls() for cls in ALL_RULES]
    if config is not None:
        for rule in instances:
            rule.configure(config)

    known = {r.rule_id for r in instances} | {r.name for r in instances}
    unknown = sorted({*(enabled or []), *(disabled or [])} - known)
    if unknown:
        raise ConfigError(
            f"등록되지 않은 규칙입니다: {', '.join(unknown)} (규칙 목록은 `iron-laws rules`로 확인하세요)"
        )
    if enabled is not None and not enabled:
        raise ConfigError("enabled_rules가 비어 있습니다. 모든 규칙을 쓰려면 항목 자체를 지우세요")

    if enabled:
        instances = [r for r in instances if r.rule_id in enabled or r.name in enabled]

    if disabled:
        instances = [r for r in instances if r.rule_id not in disabled and r.name not in disabled]

    if not instances:
        raise ConfigError("활성화된 규칙이 없습니다. enabled_rules와 disabled_rules를 확인하세요")
    return instances
