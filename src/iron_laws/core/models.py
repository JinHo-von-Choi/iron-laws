"""
오철칙 (Iron Laws) Core Domain Models
작성자: 최진호
작성일: 2026-10-04
"""

from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "CRITICAL"  # 납품/배포 즉시 차단 (부적합)
    HIGH = "HIGH"  # 중대 보안 결함 (부적합)
    MEDIUM = "MEDIUM"  # 아키텍처/품질 결함 (개선권고)
    LOW = "LOW"  # 스타일 및 권장사항 (참고)


class IronLaw(IntEnum):
    LAW_1 = 1  # 제1철칙: 타협과 묵인은 없다 (No Compromise)
    LAW_2 = 2  # 제2철칙: 근거 없는 지적은 잡담이다 (Evidence-Backed)
    LAW_3 = 3  # 제3철칙: 병신같이 덮지 않는다 (Anti-Coverup)
    LAW_4 = 4  # 제4철칙: 대안 없는 비판은 직무유기다 (Actionable Alternatives)
    LAW_5 = 5  # 제5철칙: 전수 검증의 원칙 (Exhaustive Verification)


class RuleLayer(StrEnum):
    STANDARD = "STANDARD"  # 행안부 개발보안 가이드 등 외부 기준에 근거한 규칙
    AI_CODE = "AI_CODE"  # AI 생성 코드의 전형적 결함을 겨냥한 오철칙 자체 규칙
    ARCHITECTURE = "ARCHITECTURE"  # 구조 건전성 점검 오철칙 자체 규칙


class Confidence(StrEnum):
    CONFIRMED = "CONFIRMED"  # 외부 입력 도달 등 근거가 코드에서 확인됨
    REVIEW = "REVIEW"  # 패턴은 확실하나 실제 악용 여부는 사람이 확인해야 함


class GovStandard(BaseModel):
    """참고한 공개 가이드의 항목 매핑 정보"""

    standard_name: str = Field(..., description="표준 명칭 (예: 행정안전부 SW 개발보안 가이드)")
    clause_id: str = Field(
        ..., description="조항 번호 (예: 행안부 1-1, KISA 암호규격, 국정원 11조)"
    )
    description: str = Field(..., description="표준 요약 설명")


class CodeFix(BaseModel):
    """BEFORE -> AFTER 교정 안내"""

    before_snippet: str = Field(..., description="취약/결함 코드 예시")
    after_snippet: str = Field(..., description="완벽 교정 코드 예시")
    rationale: str = Field(..., description="수정 근거 및 이유")


class Violation(BaseModel):
    """감리 및 린트 지적 사항"""

    rule_id: str
    rule_name: str
    iron_law: IronLaw
    severity: Severity
    file_path: Path
    line_number: int
    column: int = 1
    snippet: str
    message: str
    gov_standard: GovStandard | None = None
    fix: CodeFix | None = None
    layer: RuleLayer = RuleLayer.STANDARD
    confidence: Confidence = Confidence.CONFIRMED
    plain: str = ""
    how_to_fix: str = ""


class AuditSummary(BaseModel):
    """감리 총괄 통계"""

    total_files_scanned: int = 0
    total_violations: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    suppressed_count: int = 0
    is_passed: bool = True
    grade: str = "A"  # A, B, C, D, F


class AuditReport(BaseModel):
    """점검 보고서 데이터 모델"""

    document_id: str
    title: str = "SW 개발보안 점검 보고서"
    auditor: str = "오철칙 자동 점검"
    audit_date: str
    target_path: str
    summary: AuditSummary
    violations: list[Violation] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
