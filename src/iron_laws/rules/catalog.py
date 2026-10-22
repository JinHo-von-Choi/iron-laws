"""
오철칙 Rule Registry & Catalog
작성자: 최진호
작성일: 2026-10-04
"""

import importlib
import pkgutil

from iron_laws.core.config import ConfigError, IronLawsConfig
from iron_laws.rules.base import BaseRule

# 규칙이 속한 계열의 순서. 계열 안의 순서는 분류와 무관하지만, `iron-laws rules` 목록이 계열별로 모여 보이도록 잡는다.
FAMILY_ORDER: tuple[str, ...] = (
    "secrets_crypto",
    "errors",
    "injection",
    "code_quality",
    "ai_code",
    "ai_attack",
    "ai_agent_surface",
    "architecture",
    "performance",
    "typing_rules",
    "review_rules",
)


def _family_of(module_name: str) -> str:
    """규칙이 정의된 모듈 이름에서 계열 이름을 찾는다."""
    best = ""
    for family in FAMILY_ORDER:
        if module_name.startswith(family) and len(family) > len(best):
            best = family
    return best or module_name


def _discover_rule_classes() -> list[type[BaseRule]]:
    """rules 패키지의 모든 규칙 클래스를 찾는다. 등록 목록을 따로 쓰지 않으므로 빠뜨릴 수 없다."""
    package = importlib.import_module("iron_laws.rules")
    found: dict[str, type[BaseRule]] = {}
    ordered: list[tuple[tuple[int, str, str], type[BaseRule]]] = []
    for info in pkgutil.walk_packages(package.__path__, prefix="iron_laws.rules."):
        try:
            module = importlib.import_module(info.name)
        except ImportError:  # pragma: no cover - 선택 의존성이 모듈을 못 읽는 경우
            continue
        short = info.name.rsplit(".", 1)[-1]
        for obj in vars(module).values():
            if not isinstance(obj, type) or not issubclass(obj, BaseRule):
                continue
            if "rule_id" not in obj.__dict__:
                continue  # 중간 기반 클래스는 등록 대상이 아니다
            if obj.__module__ != info.name:
                continue  # 다른 모듈에서 가져온 클래스는 정의된 곳에서 한 번만 센다
            if obj.rule_id in found:
                continue
            found[obj.rule_id] = obj
            family = _family_of(short)
            rank = FAMILY_ORDER.index(family) if family in FAMILY_ORDER else len(FAMILY_ORDER)
            ordered.append(((rank, family, short), obj))
    ordered.sort(key=lambda item: item[0])
    return [obj for _key, obj in ordered]


ALL_RULES: list[type[BaseRule]] = _discover_rule_classes()


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
    from iron_laws.core.custom_spec import apply_custom_spec

    apply_custom_spec(instances, config.policies.custom_spec if config is not None else None)
    return instances
