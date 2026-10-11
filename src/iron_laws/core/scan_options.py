"""점검 호출의 옵션 묶음. 기존 AuditScanner 생성자의 키워드와 호환한다."""

from collections.abc import Callable
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from iron_laws.core.approvals import ApprovalStore
from iron_laws.core.baseline import Baseline
from iron_laws.core.config import IronLawsConfig
from iron_laws.core.contract import Contract
from iron_laws.core.suppress import Directive


@dataclass
class ScanOptions:
    root_path: Path
    config: IronLawsConfig | None = None
    config_path: Path | None = None
    search_parents: bool = False
    baseline: Baseline | None = None
    changed_files: set[str] | None = None
    changed_since: str | None = None
    renames: list[tuple[str, str]] | None = None
    gates: dict[str, float] | None = None
    respect_gitignore: bool = False
    contract: Contract | None = None
    contract_source: str = '기본값'
    contract_path: Path | None = None
    directive_filter: Callable[[str, Directive], bool] | None = None
    approvals: ApprovalStore | None = None
    collect_dependencies: bool = False

    def kwargs(self) -> dict[str, Any]:
        # asdict는 정책 모델까지 복제·변환하므로 신뢰된 모델 객체를 그대로 전달한다.
        return {field.name: getattr(self, field.name) for field in fields(self)}
