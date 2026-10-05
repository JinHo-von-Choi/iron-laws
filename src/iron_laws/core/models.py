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


class EvidenceStep(BaseModel):
    """판단 근거의 한 단계. 입력 유입 → 전파 → 싱크 순서로 위치와 변수 이름만 담는다 (코드 원문과 비밀값은 담지 않는다)"""

    role: str = Field(..., description="source(입력 유입) / propagation(전파) / sink(위험 지점)")
    file_path: str
    line: int
    note: str = ""


class BaselineStatus(StrEnum):
    NEW = "new"  # 기준선에 없던 지적
    EXISTING = "existing"  # 기준선에 있던 지적 (승인된 부채)
    REVIEW = "review"  # 규칙 의미가 바뀌어 다시 검토해야 하는 지적


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
    rule_version: int = 1
    fingerprint: str = ""
    finding_id: str = ""  # 이 점검 실행의 지적 식별자(규칙·경로·위치·지문). 장부·승인·검증기가 같은 지적을 참조하는 키
    scope_name: str = ""  # 지적이 속한 함수 이름 (구문 분석 언어에서만)
    snippet_full: str = Field(default="", exclude=True)  # 길이를 제한하기 전의 코드 줄(토큰 형식만 가린 상태). 같은 줄의 비밀을 알게 된 뒤 다시 가려 제한한다
    shape: str = Field(default="", exclude=True)  # 주석을 뺀 정규화한 코드 줄(지문 계산용, 비밀은 가린 상태)
    evidence: list[EvidenceStep] = Field(default_factory=list)
    baseline_status: BaselineStatus | None = None
    approval_status: str | None = None  # 사람의 검토 승인 대비 상태: approved / needs_review / expired / revoked / none
    approval_id: str | None = None
    approval_reasons: list[str] = Field(default_factory=list)  # 승인을 유지할 수 없는 이유(바뀐 전제)
    dependencies: dict | None = Field(default=None, exclude=True)  # 승인 유효성 판단에 쓰는 의존성 지문. 보고서에는 싣지 않는다


class Diagnostic(BaseModel):
    """점검 과정에서 생긴 문제. 오류가 하나라도 있으면 점검이 끝까지 되지 않은 것이다."""

    kind: str = Field(..., description="read / encoding / parse / rule_error / worker / analysis_limit / suppression / baseline / config")
    severity: str = Field(..., description="info / warning / error")
    message: str
    file_path: str = ""
    line: int = 0


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
    scan_status: str = "complete"  # complete / incomplete / empty
    new_count: int | None = None  # 기준선과 비교했을 때의 신규·재검토 건수
    existing_count: int | None = None
    resolved_count: int | None = None
    unobserved_count: int | None = None  # 기준선의 지적 중 파일이 없거나 점검하지 못해 알 수 없는 것
    approvals_valid: int | None = None  # 승인 기록을 쓸 때: 유효한 승인으로 받아들인 지적 수
    approvals_review: int | None = None  # 전제가 바뀌었거나 만료·철회되어 다시 검토해야 하는 지적 수
    approvals_unobserved: int | None = None  # 승인 대상 파일이 없거나 읽지 못해 알 수 없는 승인 수
    contract_status: str | None = None  # 근거 계약 충족 여부: met / unmet / policy_change_review / not_applicable. scan_status와 별개
    contract_mode: str | None = None


class InterestPoint(BaseModel):
    """보안 관심 지점(명령 실행·경로 접근·SQL 조립 호출)과 그 지점에서 확보한 분석 근거의 상태"""

    id: str
    family: str = Field(..., description="command / path / sql")
    path: str
    line: int
    column: int = 1
    callee: str
    state: str = Field(..., description="evidence_met / unsupported / unresolved / budget_exceeded / policy_excluded")
    reason: str = ""
    in_scope: bool = True  # 계약 범위(전체 또는 변경 파일) 안에 있는가
    finding: bool = False  # 같은 지점에서 지적이 나왔는가
    finding_ids: list[str] = Field(default_factory=list, description="이 지점·계열의 규칙이 실제로 낸 확정 지적의 finding_id")
    evidence_kind: str = Field(default="none", description="finding / closed_value / guard / none — 충족 근거의 종류")
    suppressed_rules: list[str] = Field(default_factory=list, description="이 지점에서 억제된 규칙 ID(정확한 억제 범위)")


class LedgerFile(BaseModel):
    path: str
    classification: str = Field(
        ..., description="analyzed / unsupported_language / out_of_scope / policy_excluded / unclassified"
    )
    reason: str = ""
    changed: bool = False
    interest_points: int = 0


class FamilyTally(BaseModel):
    family: str
    required: bool
    total: int = 0
    in_scope: int = 0
    by_state: dict[str, int] = Field(default_factory=dict)  # 계약 범위 안 지점의 상태별 수


class ExecutionRecord(BaseModel):
    """이 보고서를 만든 점검 실행의 식별자와 범위. 지적·장부·승인이 같은 실행의 근거인지 확인하는 기준이다."""

    run_id: str
    tool_version: str
    ruleset_hash: str
    config_hash: str
    contract_digest: str
    code_digest: str
    scan_status: str
    files_scanned: int
    files_skipped: int
    error_diagnostics: int
    cross_file_limit_hits: int = 0


class ApprovalCheck(BaseModel):
    """승인 기록 하나의 현재 판정. `valid`는 같은 코드 모양의 지적(finding_id)에 대한 유효한 승인이라는 뜻이다."""

    approval_id: str
    status: str = Field(..., description="valid / needs_review / invalid / revoked / resolved / unobserved")
    reasons: list[str] = Field(default_factory=list)
    rule_id: str = ""
    path: str = ""
    approved_fingerprint: str = ""
    finding_id: str | None = None
    expires: str | None = None
    policy: dict[str, str] = Field(default_factory=dict)


class CoverageLedger(BaseModel):
    """파일과 보안 관심 지점별 분석 근거 기록. 단일 '안전 점수'를 만들지 않고, 분모(발견한 지점·분류하지 못한 파일)를 함께 공개한다."""

    contract_version: int
    contract_mode: str
    contract_scope: str
    contract_digest: str
    contract_source: str = "기본값"
    languages: list[str] = Field(default_factory=list)
    digests: dict[str, str] = Field(default_factory=dict)
    families: list[FamilyTally] = Field(default_factory=list)
    points: list[InterestPoint] = Field(default_factory=list)
    files: list[LedgerFile] = Field(default_factory=list)
    unclassified_changed_files: list[str] = Field(default_factory=list)
    status: str = Field(..., description="met / unmet / policy_change_review / not_applicable")
    run_id: str = Field(default="", description="코드·도구·설정·계약 지문에서 만든 분석 실행 식별자")
    requirements: dict[str, dict[str, Any]] = Field(default_factory=dict, description="검사 계열별 요구(필수 여부, 차단 상태). 독립 검증기가 차단 사유를 다시 계산하는 입력")
    blockers: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


REPORT_SCHEMA_VERSION = "1.3"


class AuditReport(BaseModel):
    """점검 보고서 데이터 모델"""

    schema_version: str = REPORT_SCHEMA_VERSION
    document_id: str
    title: str = "SW 개발보안 점검 보고서"
    auditor: str = "오철칙 자동 점검"
    audit_date: str
    target_path: str
    summary: AuditSummary
    violations: list[Violation] = Field(default_factory=list)
    diagnostics: list[Diagnostic] = Field(default_factory=list)
    coverage_ledger: CoverageLedger | None = None
    execution: ExecutionRecord | None = None
    approval_checks: list[ApprovalCheck] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
