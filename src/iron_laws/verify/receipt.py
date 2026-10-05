"""
오철칙 검증 기록(Receipt): 원본·후보의 해시, 검사 환경, 항목별 실행 여부와 결과, 우회 변경을 한 기록으로 묶는다
- 항목 결과는 pass(검증 항목 통과) / fail(검증 실패) / not_run(미실행) / unknown(판정 불가)로 구분하며 실패와 미실행을 같은 값으로 합치지 않는다.
- 기록의 해시는 무결성 근거일 뿐이며 코드의 안전성, 승인자 진위, 기록 위변조 불가를 증명하지 않는다.
- 모델의 자기평가는 입력으로 받지 않는다. 결과는 도구가 직접 실행·측정한 것만 담는다.
작성자: 최진호
작성일: 2026-10-04
"""

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, Field

RECEIPT_SCHEMA_VERSION = "1"

CheckState = Literal["pass", "fail", "not_run", "unknown"]
STATE_LABEL = {"pass": "검증 항목 통과", "fail": "검증 실패", "not_run": "미실행", "unknown": "판정 불가"}
VERDICT_LABEL = {"verified": "검증 항목 통과", "failed": "검증 실패", "undeterminable": "판정 불가"}


class CheckResult(BaseModel):
    id: str
    title: str
    result: CheckState
    required: bool = True
    executed: bool = True
    reason: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    duration_s: float | None = None
    limit_reached: bool = False


class Verdict(BaseModel):
    overall: Literal["verified", "failed", "undeterminable"]
    label: str
    counts: dict[str, int] = Field(default_factory=dict)
    reasons: list[str] = Field(default_factory=list)
    caveat: str = "통과는 지정된 검사 계약을 충족했다는 뜻입니다. 안전성, 취약점 부재, 완전한 기능 동등성을 증명하지 않습니다."


class Receipt(BaseModel):
    schema_version: str = RECEIPT_SCHEMA_VERSION
    created: str
    options: dict[str, Any] = Field(default_factory=dict)  # 같은 조건으로 다시 실행하려고 남기는 입력(명령·상한·정책 경로)
    inputs: dict[str, Any] = Field(default_factory=dict)
    digests: dict[str, str] = Field(default_factory=dict)
    environment: dict[str, Any] = Field(default_factory=dict)
    target: dict[str, Any] | None = None
    checks: list[CheckResult] = Field(default_factory=list)
    findings: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)  # 원본·후보 점검의 실행 식별자와 지적 참조. 독립 검증기가 대조한다
    coverage: dict[str, Any] = Field(default_factory=dict)
    bypass_changes: list[dict[str, str]] = Field(default_factory=list)
    verdict: Verdict
    receipt_digest: str = ""

    def seal(self) -> "Receipt":
        """내용 해시를 채운다. 해시 필드를 뺀 정렬된 JSON을 대상으로 한다."""
        body = self.model_dump(mode="json", exclude={"receipt_digest"})
        self.receipt_digest = hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:24]
        return self

    def verify_seal(self) -> bool:
        body = self.model_dump(mode="json", exclude={"receipt_digest"})
        return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:24] == self.receipt_digest


def decide(checks: list[CheckResult]) -> Verdict:
    """필수 항목이 하나라도 실패하면 실패, 실패는 없지만 필수 항목이 미실행·판정 불가면 판정 불가, 모두 통과해야 통과"""
    required = [c for c in checks if c.required]
    failed = [c for c in required if c.result == "fail"]
    open_items = [c for c in required if c.result in ("not_run", "unknown")]
    counts: dict[str, int] = {}
    for c in checks:
        counts[c.result] = counts.get(c.result, 0) + 1
    if failed:
        return Verdict(overall="failed", label=VERDICT_LABEL["failed"], counts=counts, reasons=[f"{c.title}: {c.reason}" for c in failed])
    if open_items:
        return Verdict(
            overall="undeterminable",
            label=VERDICT_LABEL["undeterminable"],
            counts=counts,
            reasons=[f"{c.title}: {STATE_LABEL[c.result]} — {c.reason}" for c in open_items],
        )
    return Verdict(overall="verified", label=VERDICT_LABEL["verified"], counts=counts)
