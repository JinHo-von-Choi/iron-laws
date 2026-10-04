"""
오철칙 근거 계약(Contract): 팀이 선언하는 '이 변경을 승인하려면 무엇을 확인해야 하는가'
검사가 끝났다는 것(scan_status)과 요구한 근거가 충족됐다는 것(contract_status)은 별개다.
계약은 사용자가 지정한 신뢰 정책 파일에서 읽는다. 점검 대상(후보 변경)이 이 파일을 바꾸면 정책 변경 검토로 보낸다.
작성자: 최진호
작성일: 2026-10-04
"""

import hashlib
from enum import StrEnum
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from iron_laws.core.config import ConfigError

CONTRACT_SCHEMA_VERSION = 1
FAMILIES = ("command", "path", "sql")  # 첫 범위: Python 명령 실행·경로 접근·SQL 조립
SUPPORTED_LANGUAGES = ("python",)


class PointState(StrEnum):
    EVIDENCE_MET = "evidence_met"  # 요구한 분석 근거를 확보했다 (전체 프로그램이 안전하다는 뜻이 아니다)
    UNSUPPORTED = "unsupported"  # 언어·API·구문에 필요한 모델이 없다
    UNRESOLVED = "unresolved"  # 호출·전파·상태를 확정하지 못했다. 깨끗함으로 바꾸지 않는다
    BUDGET_EXCEEDED = "budget_exceeded"  # 시간·깊이·횟수 상한에 도달했다
    POLICY_EXCLUDED = "policy_excluded"  # 신뢰된 정책이 명시적으로 제외했다


GAP_STATES = (PointState.UNSUPPORTED, PointState.UNRESOLVED, PointState.BUDGET_EXCEEDED)
DEFAULT_BLOCK_ON = [PointState.UNSUPPORTED, PointState.UNRESOLVED, PointState.BUDGET_EXCEEDED]


class FamilyRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    required: bool = True
    block_on: list[PointState] = Field(default_factory=lambda: list(DEFAULT_BLOCK_ON))


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = CONTRACT_SCHEMA_VERSION
    mode: Literal["report", "block"] = "report"  # report: 근거 공백을 모으기만 한다 / block: 필수 범위의 미충족이면 실패
    scope: Literal["changed", "all"] = "all"  # changed: --changed-since로 바뀐 파일의 관심 지점만 판정한다
    languages: list[str] = Field(default_factory=lambda: list(SUPPORTED_LANGUAGES))
    families: dict[str, FamilyRequirement] = Field(default_factory=lambda: {f: FamilyRequirement() for f in FAMILIES})
    include_tests: bool = False
    trusted_sources: list[str] = Field(default_factory=lambda: ["env"], description="값을 배포자가 정한다고 믿는 출처 (env)")
    exclude_paths: list[str] = Field(default_factory=list, description="정책으로 제외하는 경로 패턴")
    exclusion_reason: str = Field(default="", description="exclude_paths를 둔 사유와 승인 전제")

    def validate_semantics(self) -> None:
        unknown = sorted(set(self.families) - set(FAMILIES))
        if unknown:
            raise ConfigError(f"계약의 알 수 없는 검사 계열: {', '.join(unknown)} (지원: {', '.join(FAMILIES)})")
        bad_languages = sorted(set(self.languages) - set(SUPPORTED_LANGUAGES))
        if bad_languages:
            raise ConfigError(f"계약이 아직 지원하지 않는 언어: {', '.join(bad_languages)} (지원: {', '.join(SUPPORTED_LANGUAGES)})")
        if self.exclude_paths and len(self.exclusion_reason.strip()) < 3:
            raise ConfigError("exclude_paths를 두려면 exclusion_reason에 사유와 승인 전제를 적어야 합니다")
        if self.version != CONTRACT_SCHEMA_VERSION:
            raise ConfigError(f"지원하지 않는 계약 버전입니다: {self.version}")


def default_contract() -> Contract:
    return Contract()


def load_contract(path: Path) -> tuple[Contract, str]:
    """(계약, 파일 내용 해시)를 돌려준다. 해시는 보고서에 남겨 '어떤 계약으로 판정했는가'를 고정한다."""
    if not path.is_file():
        raise ConfigError(f"계약 파일이 없습니다: {path}")
    try:
        raw = path.read_bytes()
        data = yaml.safe_load(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        raise ConfigError(f"계약 파일을 읽을 수 없습니다: {path} ({e})") from e
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(f"계약 파일의 최상위 구조는 매핑이어야 합니다: {path}")
    try:
        contract = Contract(**data)
    except ValidationError as e:
        raise ConfigError(f"계약 파일 검증 실패: {path}\n{e}") from e
    contract.validate_semantics()
    return contract, hashlib.sha256(raw).hexdigest()[:16]


def contract_digest(contract: Contract) -> str:
    return hashlib.sha256(contract.model_dump_json().encode()).hexdigest()[:16]
