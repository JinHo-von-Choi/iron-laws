"""
오철칙 승인 기록(ApprovalRecord)과 변경 유효성 추적
- 승인은 baseline(기존 지적 관리 데이터)과 별개다. baseline의 지적은 사람의 승인으로 자동 승격되지 않는다.
- 승인에는 사유, 대상, 유효기간, 정책 버전, 검토한 흐름의 의존성 지문, 검증 기록(Receipt) 해시를 남긴다.
- 이후 코드가 승인 전제를 바꾸면(호출자·source·sink·정제 함수·접근 범위·규칙 의미·정책) 관련 승인만 다시 검토 대상이 된다.
- 기록은 추가 전용 JSONL이며 각 줄이 앞 줄의 해시를 이어받는다. 이 해시는 변조 탐지용 무결성 근거일 뿐, 승인자의 진위나
  기록 파일을 바꿀 수 있는 공격자에 대한 방어가 아니다.
- 승인 기록에 OpenSSH 서명을 붙일 수 있다(이름공간 iron-laws-approval). 서명 대상은 순번·앞 기록 해시를 뺀 승인 내용이라
  보존기간 정리로 사슬을 다시 이어도 서명이 유지된다. 허용 서명자 목록을 주면 서명이 틀린 승인은, 서명 필수로 두면 서명 없는 승인도
  쓰지 않는다(invalid). 기록 삭제·되돌리기는 저장소 밖에 둔 서명된 체크포인트(기록 수·마지막 해시)와 대조해 알아챈다.
- 기록에는 식별자(규칙·경로·함수 이름·해시)와 사유만 담고 코드 원문·비밀값은 담지 않는다. 보존기간과 삭제 경로를 제공한다.
작성자: 최진호
작성일: 2026-10-04
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

from iron_laws.core.baseline import Baseline, BaselineEntry, apply_baseline, loose_key, shape_of
from iron_laws.core.config import ConfigError
from iron_laws.core.dependencies import Premise, explain_dependencies
from iron_laws.core.models import BaselineStatus, Violation

APPROVALS_SCHEMA = 1
SIGNED_PAYLOAD_PREFIX = b"iron-laws-approval/1 "
CHECKPOINT_KIND = "iron-laws-approvals-checkpoint"
DEFAULT_APPROVALS_FILE = ".iron-laws-approvals.jsonl"
GENESIS = "0" * 24


class ApprovedFinding(BaseModel):
    rule_id: str
    rule_version: int
    path: str
    scope_name: str = ""
    fingerprint: str
    loose: str
    severity: str
    line: int = 0


class ApprovalPolicy(BaseModel):
    """승인 당시의 정책·도구 조건. 바뀌면 승인 전제를 다시 확인해야 한다."""

    contract_digest: str = ""
    config_hash: str = ""
    ruleset_hash: str = ""
    tool_version: str = ""


class Record(BaseModel):
    """추가 전용 기록 한 줄"""

    schema_version: int = APPROVALS_SCHEMA
    seq: int
    kind: Literal["approve", "revoke", "forget"]
    id: str
    created: str
    prev: str = GENESIS
    hash: str = ""
    # approve
    finding: ApprovedFinding | None = None
    reason: str = ""
    reviewer: str = ""  # 인증되지 않은 표기. 누가 승인했는지 증명하지 않는다
    expires: str | None = None
    policy: ApprovalPolicy | None = None
    flow: list[dict[str, Any]] = Field(default_factory=list)  # 검토한 흐름(역할·위치·변수 이름만)
    dependencies: dict[str, Any] | None = None
    receipt_digest: str | None = None
    minutes: int = 0  # 검토에 든 시간(분). 계측용
    # revoke / forget
    target: str | None = None
    signature: str = ""  # OpenSSH 서명(선택). 해시 계산에서 빠지고 content_digest를 서명한다

    def body(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"hash", "signature"})

    def content_digest(self) -> str:
        """순번·앞 기록 해시를 뺀 기록 내용의 해시. 서명 대상이다."""
        content = self.model_dump(mode="json", exclude={"hash", "signature", "seq", "prev"})
        return hashlib.sha256(json.dumps(content, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

    def signed_payload(self) -> bytes:
        return SIGNED_PAYLOAD_PREFIX + self.content_digest().encode()

    def line(self) -> str:
        exclude = set() if self.signature else {"signature"}
        return json.dumps(self.model_dump(mode="json", exclude=exclude), ensure_ascii=False, sort_keys=True) + "\n"

    def compute_hash(self) -> str:
        return hashlib.sha256(json.dumps(self.body(), sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:24]


@dataclass
class Approval:
    """기록을 접어서 본 현재 승인 하나"""

    record: Record
    revoked: bool = False
    forgotten: bool = False

    @property
    def id(self) -> str:
        return self.record.id


CREATED_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def parse_expiry(value: str | None) -> tuple[date | None, str | None]:
    """유효기간 값을 날짜로 읽는다. (날짜, 오류). 값이 없으면 기한 없음, 형식이 틀리면 오류를 돌려준다."""
    if value is None or value == "":
        return None, None
    try:
        return date.fromisoformat(value), None
    except (ValueError, TypeError):  # iron-laws: ignore[IL-301] 날짜가 아니면 오류 문구를 함께 돌려주고 호출부가 승인을 invalid로 처리한다
        return None, f"유효기간 값이 날짜가 아니다({value!r})"


def validate_record(record: "Record") -> list[str]:
    """기록 한 줄의 형식·필수 필드 검증. check·status·verify·prune이 같은 규칙을 쓴다."""
    problems: list[str] = []
    try:
        datetime.strptime(record.created, CREATED_FORMAT)
    except (ValueError, TypeError):
        problems.append(f"생성 시각 형식이 맞지 않는다({record.created!r})")
    if record.kind == "approve":
        if not record.id.startswith("AP-"):
            problems.append(f"승인 ID 형식이 맞지 않는다({record.id!r})")
        if record.finding is None or not record.finding.fingerprint or not record.finding.rule_id or not record.finding.path:
            problems.append("승인 대상(규칙·경로·지문)이 비어 있다")
        if record.policy is None:
            problems.append("승인 당시의 정책 정보가 없다")
        if len(record.reason.strip()) < 3:
            problems.append("승인 사유가 3자 미만이다")
        if record.expires is not None:
            _expiry, error = parse_expiry(record.expires)
            if error:
                problems.append(error)
    elif not record.target:
        problems.append(f"{record.kind} 기록에 대상 승인 ID가 없다")
    return problems


@dataclass
class Integrity:
    """승인 기록 파일의 검증 결과. 해시 연결 문제는 파일 전체의 신뢰를, 기록별 문제는 그 승인만 영향을 준다."""

    chain: list[str] = field(default_factory=list)
    records: dict[str, list[str]] = field(default_factory=dict)  # 승인 ID → 문제

    @property
    def ok(self) -> bool:
        return not self.chain and not self.records

    def lines(self) -> list[str]:
        out = list(self.chain)
        for approval_id, problems in sorted(self.records.items()):
            out.extend(f"{approval_id}: {problem}" for problem in problems)
        return out


class ApprovalStore:
    def __init__(self, path: Path, allowed_signers: Path | None = None, require_signed: bool = False):
        if require_signed and allowed_signers is None:
            raise ConfigError("서명 필수로 확인하려면 허용 서명자 목록(--allowed-signers)이 필요합니다")
        if allowed_signers is not None and not allowed_signers.is_file():
            raise ConfigError(f"허용 서명자 목록 파일이 없습니다: {allowed_signers}")
        self.path = path
        self.allowed_signers = allowed_signers
        self.require_signed = require_signed
        self.signers: dict[str, str] = {}  # 승인 ID → 서명을 확인한 서명자
        self._signature_checked: dict[tuple[str, str], list[str]] = {}
        self.records: list[Record] = []
        if path.is_file():
            self._load()

    def _load(self) -> None:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as e:
            raise ConfigError(f"승인 기록을 읽을 수 없습니다: {self.path} ({e})") from e
        for number, raw in enumerate(lines, start=1):
            if not raw.strip():
                continue
            try:
                self.records.append(Record(**json.loads(raw)))
            except (json.JSONDecodeError, ValidationError, TypeError) as e:
                raise ConfigError(f"승인 기록 {number}번째 줄을 읽을 수 없습니다: {e}") from e

    def verify_chain(self) -> list[str]:
        """각 줄의 해시와 앞 줄 연결을 확인한다. 문제가 있으면 사유 목록을 돌려준다."""
        problems: list[str] = []
        previous = GENESIS
        for index, record in enumerate(self.records):
            if record.seq != index + 1:
                problems.append(f"{index + 1}번째 기록의 순번이 맞지 않는다(seq={record.seq})")
            if record.prev != previous:
                problems.append(f"{index + 1}번째 기록이 앞 기록과 이어지지 않는다(삭제·재배열 의심)")
            if record.compute_hash() != record.hash:
                problems.append(f"{index + 1}번째 기록의 내용 해시가 맞지 않는다(내용 변경 의심)")
            previous = record.hash
        return problems

    def signature_problems(self, record: Record) -> list[str]:
        """승인 기록의 서명 문제. 허용 서명자 목록이 없으면 확인하지 않는다."""
        from iron_laws.evidence.signing import APPROVAL_NAMESPACE, SigningError, verify_bytes

        if self.allowed_signers is None or record.kind != "approve":
            return []
        if not record.signature:
            return ["승인 기록에 서명이 없다(서명 필수)"] if self.require_signed else []
        key = (record.id, record.content_digest())
        if key not in self._signature_checked:
            try:
                self.signers[record.id] = verify_bytes(record.signed_payload(), record.signature, self.allowed_signers, APPROVAL_NAMESPACE)
                self._signature_checked[key] = []
            except SigningError as e:
                self._signature_checked[key] = [f"승인 서명을 확인하지 못했다: {e}"]
        return self._signature_checked[key]

    def integrity(self) -> Integrity:
        """해시 연결과 기록별 형식·서명을 함께 확인한다."""
        result = Integrity(chain=self.verify_chain())
        for record in self.records:
            problems = validate_record(record) + self.signature_problems(record)
            if problems:
                key = record.id if record.kind == "approve" else (record.target or record.id)
                result.records.setdefault(key, []).extend(problems)
        return result

    def append(self, record: Record, sign_key: Path | None = None) -> Record:
        problems = self.verify_chain()
        if problems:
            raise ConfigError("승인 기록의 무결성이 깨져 있어 기록을 추가하지 않습니다: " + "; ".join(problems[:2]))
        record.seq = len(self.records) + 1
        if record.kind == "approve" and record.finding is not None and any(r.id == record.id for r in self.records):
            # 같은 지적을 같은 초에 다시 승인하면 ID가 겹친다. 겹치면 철회·삭제 기록이 두 승인을 함께 가리키므로 순번을 섞어 새로 만든다
            record.id = new_record_id(record.finding.fingerprint, record.created, str(record.seq))
        record.prev = self.records[-1].hash if self.records else GENESIS
        record.hash = record.compute_hash()
        if sign_key is not None:
            from iron_laws.evidence.signing import APPROVAL_NAMESPACE, SigningError, sign_bytes

            try:
                record.signature = sign_bytes(record.signed_payload(), sign_key, APPROVAL_NAMESPACE)
            except SigningError as e:
                raise ConfigError(f"승인 기록에 서명하지 못해 기록하지 않습니다: {e}") from e
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(record.line())
        self.records.append(record)
        return record

    def write_checkpoint(self, output: Path, sign_key: Path) -> Path:
        """지금까지의 기록 수와 마지막 해시를 서명해 남긴다. 저장소 밖(후보 변경과 기록 작성자가 바꿀 수 없는 곳)에 두어야 의미가 있다."""
        from iron_laws.evidence.signing import APPROVAL_NAMESPACE, SigningError, sign_file

        problems = self.verify_chain()
        if problems:
            raise ConfigError("승인 기록의 무결성이 깨져 있어 체크포인트를 남기지 않습니다: " + "; ".join(problems[:2]))
        payload = {"kind": CHECKPOINT_KIND, "count": len(self.records), "head": self.records[-1].hash if self.records else GENESIS,
                   "created": datetime.now(UTC).strftime(CREATED_FORMAT)}
        output.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        try:
            return sign_file(output, sign_key, APPROVAL_NAMESPACE)
        except SigningError as e:
            raise ConfigError(f"체크포인트에 서명하지 못했습니다: {e}") from e

    def checkpoint_problems(self, checkpoint: Path, allowed_signers: Path) -> list[str]:
        """서명된 체크포인트와 지금 기록을 대조한다. 체크포인트 이후의 추가는 정상이고, 그 이전 기록이 줄거나 바뀌면 문제다."""
        from iron_laws.evidence.signing import APPROVAL_NAMESPACE, SigningError, verify_file

        try:
            verify_file(checkpoint, allowed_signers, APPROVAL_NAMESPACE)
            data = json.loads(checkpoint.read_text(encoding="utf-8"))
        except (SigningError, OSError, json.JSONDecodeError) as e:
            return [f"체크포인트를 확인하지 못했다: {e}"]
        if not isinstance(data, dict) or data.get("kind") != CHECKPOINT_KIND or type(data.get("count")) is not int or not isinstance(data.get("head"), str):
            return ["체크포인트 형식이 맞지 않는다"]
        count, head = data["count"], data["head"]
        if len(self.records) < count:
            return [f"체크포인트 시점({count}건)보다 기록이 적다(끝부분 삭제·이전 파일로 되돌리기 의심)"]
        current = self.records[count - 1].hash if count else GENESIS
        if current != head:
            return [f"체크포인트 시점의 {count}번째 기록 해시가 다르다(기록 재작성·되돌리기 의심, 보존기간 정리 뒤라면 체크포인트를 새로 만드십시오)"]
        return []

    def approvals(self) -> list[Approval]:
        """철회·삭제를 반영한 현재 승인 목록"""
        by_id: dict[str, Approval] = {}
        for record in self.records:
            if record.kind == "approve":
                by_id[record.id] = Approval(record)
            elif record.kind in ("revoke", "forget") and record.target in by_id:
                if record.kind == "revoke":
                    by_id[record.target].revoked = True
                else:
                    by_id[record.target].forgotten = True
        return [a for a in by_id.values() if not a.forgotten]

    def prune(self, before: date, today: date | None = None) -> int:
        """보존기간이 지난 기록을 지운다. 지우는 조건은 하나다: 승인이 만료·철회·삭제 표시된 상태이고 만들어진 날이 before 이전.
        조건에 맞지 않는 승인과 그 철회·삭제 기록은 그대로 두고, 남은 기록은 해시 연결을 새로 만든다.
        추가 전용 이력을 깨는 되돌릴 수 없는 작업이므로 호출부가 명시적 확인을 받아야 한다."""
        today = today or date.today()
        problems = self.verify_chain()
        if problems:
            raise ConfigError("승인 기록의 무결성이 깨져 있어 정리하지 않습니다: " + "; ".join(problems[:2]))
        revoked: set[str] = set()
        forgotten: set[str] = set()
        for record in self.records:
            if record.kind == "revoke" and record.target:
                revoked.add(record.target)
            elif record.kind == "forget" and record.target:
                forgotten.add(record.target)
        drop_ids: set[str] = set()
        for record in self.records:
            if record.kind != "approve":
                continue
            expires, error = parse_expiry(record.expires)
            created_text = record.created[:10]
            try:
                created = date.fromisoformat(created_text)
            except ValueError:  # iron-laws: ignore[IL-301] 생성일을 읽을 수 없는 기록은 시점 조건을 확인할 수 없으므로 지우지 않고 남긴다(검증기가 invalid로 드러낸다)
                continue
            ended = record.id in revoked or record.id in forgotten or (error is None and expires is not None and expires < today)
            if ended and created < before:
                drop_ids.add(record.id)
        kept = [r for r in self.records if r.id not in drop_ids and r.target not in drop_ids]
        if len(kept) == len(self.records):
            return 0
        rebuilt: list[Record] = []
        previous = GENESIS
        for index, record in enumerate(kept, start=1):
            record.seq, record.prev = index, previous
            record.hash = record.compute_hash()
            previous = record.hash
            rebuilt.append(record)
        self.path.write_text("".join(r.line() for r in rebuilt), encoding="utf-8")
        removed = len(self.records) - len(rebuilt)
        self.records = rebuilt
        return removed


def new_record_id(fingerprint: str, created: str, salt: str = "") -> str:
    return "AP-" + hashlib.sha256(f"{fingerprint}|{created}{'|' + salt if salt else ''}".encode()).hexdigest()[:10]


def approve_record(violation: Violation, reason: str, reviewer: str, policy: ApprovalPolicy, expires: date | None, receipt_digest: str | None, minutes: int) -> Record:
    reason = reason.strip()
    if len(reason) < 3:
        raise ConfigError("승인 사유는 3자 이상 적어야 합니다")
    if violation.dependencies is None:
        raise ConfigError("이 지적은 함수 구조를 확인할 수 없어(설정·문서 파일 등) 승인 기록의 전제를 남길 수 없습니다")
    created = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return Record(
        seq=0,
        kind="approve",
        id=new_record_id(violation.fingerprint, created),
        created=created,
        finding=ApprovedFinding(
            rule_id=violation.rule_id,
            rule_version=violation.rule_version,
            path=violation.file_path.as_posix(),
            scope_name=violation.scope_name,
            fingerprint=violation.fingerprint,
            loose=loose_key(violation.rule_id, violation.scope_name, shape_of(violation)),
            severity=violation.severity.value,
            line=violation.line_number,
        ),
        reason=reason,
        reviewer=reviewer.strip(),
        expires=expires.isoformat() if expires else None,
        policy=policy,
        flow=[{"role": e.role, "path": e.file_path, "line": e.line, "note": e.note} for e in violation.evidence],
        dependencies=violation.dependencies,
        receipt_digest=receipt_digest,
        minutes=minutes,
    )


# ---------------------------------------------------------------------------
# 평가: 승인 → 현재 지적 일대일 대응과 전제 비교
# ---------------------------------------------------------------------------


@dataclass
class ApprovalStatusRow:
    approval: Approval
    status: str  # valid / needs_review / invalid / revoked / resolved / unobserved
    reasons: list[str] = field(default_factory=list)
    violation: Violation | None = None
    premises: list[Premise] = field(default_factory=list)  # 승인 전제별 비교 결과(유지된 항목 포함). 검토 묶음이 쓴다
    keep_reasons: list[str] = field(default_factory=list)  # 승인을 유지하는 근거(바뀌지 않은 전제)


def _footprint(recorded: dict | None, current: dict | None) -> set[str]:
    """승인 전제에 걸린 파일들(흐름의 함수·호출 함수의 경로)"""
    files: set[str] = set()
    for deps in (recorded, current):
        if not deps:
            continue
        files |= {c["path"] for c in deps.get("chain", [])}
        files |= {c.get("path", "") for c in deps.get("callees", [])}
    return files


def _premise_reasons(approval: "Approval", violation: Violation, changed_files: set[str] | None) -> tuple[list[str], list[Premise]]:
    recorded = approval.record.dependencies
    if recorded is None:
        return [], []
    premises = explain_dependencies(recorded, violation.dependencies)
    reasons = [r for p in premises if p.state == "changed" or (p.state == "unknown" and p.key == "structure") for r in p.reasons]
    boundary = next((p for p in premises if p.key == "boundaries" and p.state == "unknown"), None)
    if boundary is not None and changed_files:
        footprint = _footprint(recorded, violation.dependencies)
        outside = sorted(f for f in changed_files if f.endswith(".py") and f not in footprint)
        if outside:
            # 호출 대상을 알 수 없는 호출 경계에서는 변경이 영향을 주는지 판단할 수 없으므로 재검토 범위를 넓힌다. 영향 없음으로 처리하지 않는다
            note = f"호출 대상을 정적으로 알 수 없는 호출이 있고 이번 변경에 영향 여부를 확인할 수 없는 파일이 있다: {', '.join(outside[:3])}"
            reasons.append(note)
            boundary.state = "changed"
            boundary.reasons = [note]
    return reasons, premises


def evaluate_approvals(
    store: ApprovalStore,
    violations: list[Violation],
    policy: ApprovalPolicy,
    current_versions: dict[str, int],
    scanned_paths: set[str],
    existing_paths: set[str],
    today: date | None = None,
    changed_files: set[str] | None = None,
) -> list[ApprovalStatusRow]:
    """전체 지적 집합에서 승인과 지적을 일대일로 맺고(복제본은 새 검토 대상), 맺어진 승인의 전제가 유지되는지 본다.
    기록 파일의 무결성이 깨졌거나 승인 기록의 형식이 틀리면 그 승인은 유효한 승인으로 쓰지 않는다(`invalid`)."""
    today = today or date.today()
    integrity = store.integrity()
    approvals = store.approvals()
    entries = [
        BaselineEntry(
            fingerprint=a.record.finding.fingerprint,
            loose=a.record.finding.loose,
            rule_id=a.record.finding.rule_id,
            rule_version=a.record.finding.rule_version,
            path=a.record.finding.path,
            line=a.record.finding.line,
            severity=a.record.finding.severity,
        )
        for a in approvals
        if a.record.finding is not None
    ]
    scratch = [v.model_copy() for v in violations]
    baseline = Baseline(tool_version=policy.tool_version, entries=entries)
    outcome = apply_baseline(scratch, baseline, current_versions, scanned_paths, existing_paths)
    unobserved_fp = {e.fingerprint for e in outcome.unobserved}
    mapping = {fp: (v, status is BaselineStatus.REVIEW) for fp, (v, status) in outcome.matched.items()}
    claimed = {v.fingerprint for v, _review in mapping.values()}
    free = [v for v in scratch if v.fingerprint not in claimed]
    rows: list[ApprovalStatusRow] = []
    unmatched_rows: list[tuple[Approval, ApprovedFinding]] = []
    for approval in approvals:
        finding = approval.record.finding
        if finding is None:
            continue
        if approval.revoked:
            rows.append(ApprovalStatusRow(approval, "revoked", ["승인이 철회되었다"]))
            continue
        invalid = list(integrity.records.get(approval.id, []))
        if integrity.chain:
            invalid.insert(0, "승인 기록 파일의 무결성 확인에 실패했다: " + integrity.chain[0])
        if invalid:
            matched_row = mapping.get(finding.fingerprint)
            rows.append(ApprovalStatusRow(approval, "invalid", invalid, matched_row[0] if matched_row else None))
            continue
        expires, _error = parse_expiry(approval.record.expires)
        matched = mapping.get(finding.fingerprint)
        if matched is None:
            if finding.fingerprint in unobserved_fp:
                rows.append(ApprovalStatusRow(approval, "unobserved", ["대상 파일이 없거나 점검하지 못해 알 수 없다(해소로 보지 않는다)"]))
            else:
                unmatched_rows.append((approval, finding))
            continue
        violation, was_review = matched
        reasons: list[str] = []
        if expires is not None and expires < today:
            reasons.append(f"승인 유효기간이 지났다({expires})")
        if was_review:
            reasons.append("규칙의 판정 의미(version)가 바뀌었다")
        old_policy = approval.record.policy or ApprovalPolicy()
        if old_policy.contract_digest and old_policy.contract_digest != policy.contract_digest:
            reasons.append("근거 계약이 바뀌었다")
        if old_policy.config_hash and old_policy.config_hash != policy.config_hash:
            reasons.append("점검 설정이 바뀌었다")
        premise_reasons, premises = _premise_reasons(approval, violation, changed_files)
        reasons.extend(premise_reasons)
        keep = [f"{p.label}: {p.detail}" for p in premises if p.state == "unchanged" and p.detail]
        if not reasons:
            keep.insert(0, "승인한 지적과 같은 지문의 지적이다")
        rows.append(ApprovalStatusRow(approval, "needs_review" if reasons else "valid", reasons, violation, premises, keep))

    # 지적의 코드 모양이 바뀌어 지문이 달라졌지만 같은 규칙·같은 파일·같은 함수에 지적이 하나만 남은 경우는 '해소'가 아니라
    # '승인한 코드가 바뀐 것'이다. 일대일일 때만 맺고, 모호하면 승계하지 않는다.
    for approval, finding in unmatched_rows:
        pool = [v for v in free if v.rule_id == finding.rule_id and v.file_path.as_posix() == finding.path and v.scope_name == finding.scope_name and finding.scope_name]
        competing = [a for a, f in unmatched_rows if f.rule_id == finding.rule_id and f.path == finding.path and f.scope_name == finding.scope_name]
        if len(pool) == 1 and len(competing) == 1:
            violation = pool[0]
            free.remove(violation)
            reasons = ["승인한 지적의 코드가 바뀌었다(같은 함수의 같은 규칙 지적)"]
            premise_reasons, premises = _premise_reasons(approval, violation, changed_files)
            reasons.extend(premise_reasons)
            rows.append(ApprovalStatusRow(approval, "needs_review", reasons, violation, premises))
        else:
            nearby = [v for v in free if v.rule_id == finding.rule_id and v.file_path.as_posix() == finding.path]
            if nearby:
                # 같은 파일에 같은 규칙의 지적이 남아 있다. 함수 이름이나 구조가 바뀌어 같은 지적인지 확인할 수 없으므로 해소로 보지 않는다
                rows.append(ApprovalStatusRow(approval, "needs_review", ["같은 파일에 같은 규칙의 지적이 남아 있으나 함수 이름·구조가 달라 같은 지적인지 확인할 수 없다(승계하지 않는다)"]))
            else:
                rows.append(ApprovalStatusRow(approval, "resolved", ["지적이 더 이상 나타나지 않는다(고쳐졌거나 모양이 바뀌었다)"]))
    return rows
