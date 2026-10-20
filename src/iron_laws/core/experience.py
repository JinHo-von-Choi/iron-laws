"""
사용자 명세와 검토에서 얻은 교훈을 모은 저장소.

명세가 채택되었을 때 무엇을 왜 넣었는지, 어떤 조건에서 무엇이 나왔는지 남긴다.
소스 코드는 저장하지 않는다. 판단의 근거가 되는 이름·조건·이유만 남긴다.
기록은 추가 전용으로 해시로 이어 붙인다. 지워지지 않은 만큼 무엇이 언제 왜 들어왔는지 남는다.
"""
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from iron_laws.core.config import ConfigError

EXPERIENCE_SCHEMA = 1
GENESIS = "0" * 24
CREATED_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_EXPERIENCE_FILE = ".iron-laws-experience.jsonl"

STATE_ACTIVE = "active"
STATE_STALE = "stale"
STATE_INVALID = "invalid"
STATE_SUPERSEDED = "superseded"


class ExperienceEntry(BaseModel):
    """따뜻한 교훈 한 조각. 판단의 근거가 되는 이름과 조건만 담는다."""

    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["spec_fragment", "note"]
    lesson: str
    rule_id: str = ""
    family: str = ""
    languages: list[str] = Field(default_factory=list)
    spec_kind: str = ""
    spec_entry: dict[str, Any] | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    basis: dict[str, Any] = Field(default_factory=dict)


class ExperienceRecord(BaseModel):
    """추가 전용 기록 한 줄"""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = EXPERIENCE_SCHEMA
    seq: int
    kind: Literal["add", "supersede", "invalidate"]
    id: str
    created: str
    prev: str = GENESIS
    hash: str = ""
    entry: ExperienceEntry | None = None
    target: str | None = None
    reason: str = ""

    def body(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"hash"})

    def compute_hash(self) -> str:
        return hashlib.sha256(json.dumps(self.body(), sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:24]


@dataclass
class Experience:
    """기록을 접어 본 현재 교훈 하나"""

    entry: ExperienceEntry
    state: str = STATE_ACTIVE
    reason: str = ""


def new_id() -> str:
    return "E-" + hashlib.sha256(str(datetime.now(UTC).timestamp()).encode()).hexdigest()[:12]


def now_stamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).strftime(CREATED_FORMAT)


def validate_record(record: ExperienceRecord) -> list[str]:
    """기록 한 줄의 형식 검증."""
    problems: list[str] = []
    if record.kind == "add":
        if not record.id.startswith("E-"):
            problems.append(f"교훈 ID 형식이 맞지 않다({record.id!r})")
        if record.entry is None or not record.entry.lesson.strip():
            problems.append("교훈 내용이 비어 있다")
    else:
        if not record.target:
            problems.append("대상 교훈 ID가 없다")
        if not record.reason.strip():
            problems.append("사유가 없다")
    return problems


class ExperienceStore:
    """추가 전용 교훈 기록. 해시로 이어 붙여 무엇이 언제 왜 들어왔는지 남는다."""

    def __init__(self, path: Path):
        self.path = path
        self.records: list[ExperienceRecord] = []
        if path.is_file():
            self._load()

    def _load(self) -> None:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as e:
            raise ConfigError(f"교훈 기록을 읽을 수 없습니다: {self.path} ({e})") from e
        for number, raw in enumerate(lines, start=1):
            if not raw.strip():
                continue
            try:
                self.records.append(ExperienceRecord(**json.loads(raw)))
            except (json.JSONDecodeError, ValidationError, TypeError) as e:
                raise ConfigError(f"교훈 기록 {number}번째 줄을 읽을 수 없습니다: {e}") from e

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

    def append(self, record: ExperienceRecord) -> ExperienceRecord:
        problems = self.verify_chain()
        if problems:
            raise ConfigError("교훈 기록의 무결성이 깨져 있어 기록을 추가하지 않습니다: " + "; ".join(problems[:2]))
        record.seq = len(self.records) + 1
        record.prev = self.records[-1].hash if self.records else GENESIS
        record.hash = record.compute_hash()
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record.model_dump(mode="json"), ensure_ascii=False, sort_keys=True) + "\n")
        self.records.append(record)
        return record

    def add(self, entry: ExperienceEntry) -> ExperienceRecord:
        record = ExperienceRecord(
            seq=0,
            kind="add",
            id=entry.id,
            created=now_stamp(),
            entry=entry,
            reason=entry.lesson,
        )
        return self.append(record)

    def invalidate(self, target: str, reason: str) -> ExperienceRecord:
        record = ExperienceRecord(
            seq=0,
            kind="invalidate",
            id=new_id(),
            created=now_stamp(),
            target=target,
            reason=reason,
        )
        return self.append(record)

    def entries(
        self,
        rule_versions: dict[str, int] | None = None,
        spec_digest: str | None = None,
    ) -> list[Experience]:
        """기록을 접어 현재 교훈을 돌려준다. 규칙 버전이나 명세 지문이 바뀌면 '다시 볼 것'으로 표시한다."""
        by_id: dict[str, Experience] = {}
        for record in self.records:
            if record.kind == "add" and record.entry is not None:
                by_id[record.id] = Experience(entry=record.entry)
            elif record.kind == "supersede" and record.target in by_id and record.entry is not None:
                previous = by_id[record.target]
                previous.state = STATE_SUPERSEDED
                previous.reason = "더 새 교훈으로 대체됨"
                by_id[record.id] = Experience(entry=record.entry)
            elif record.kind == "invalidate" and record.target in by_id:
                by_id[record.target].state = STATE_INVALID
                by_id[record.target].reason = record.reason
        for item in by_id.values():
            if item.state != STATE_ACTIVE:
                continue
            version = item.entry.basis.get("rule_version")
            current = (rule_versions or {}).get(item.entry.rule_id)
            if version is not None and current is not None and version != current:
                item.state = STATE_STALE
                item.reason = f"규칙 버전이 {version}에서 {current}으로 바뀌었다"
                continue
            digest = item.entry.evidence.get("spec_digest")
            if digest and spec_digest and digest != spec_digest:
                item.state = STATE_STALE
                item.reason = "명세 내용이 바뀌었다"
        return list(by_id.values())


def spec_fragment_entries(
    spec_path: Path,
    lesson: str,
    rule_versions: dict[str, int] | None = None,
    spec_digest: str | None = None,
) -> list[ExperienceEntry]:
    """명세의 각 항목을 교훈 조각으로 바꾼다. 항목마다 판단의 근거가 된 이름을 함께 남긴다."""
    from iron_laws.core.custom_spec import FAMILY_RULE, read_spec

    loaded = read_spec(spec_path)
    entries: list[ExperienceEntry] = []
    for kind in ("sources", "sinks", "sanitizers"):
        for item in getattr(loaded.spec, kind):
            rule_id = FAMILY_RULE.get(item.family, "")
            entries.append(
                ExperienceEntry(
                    id=new_id(),
                    kind="spec_fragment",
                    lesson=lesson,
                    rule_id=rule_id,
                    family=item.family,
                    languages=list(item.languages),
                    spec_kind=kind,
                    spec_entry=item.model_dump(mode="json"),
                    evidence={
                        "spec_path": str(spec_path),
                        "spec_digest": loaded.digest[:16] if spec_digest is None else spec_digest,
                        "spec_item": item.id,
                    },
                    basis={
                        "rule_id": rule_id,
                        "rule_version": (rule_versions or {}).get(rule_id),
                    },
                )
            )
    return entries


def rule_note(rule_id: str, lesson: str, rule_versions: dict[str, int] | None = None) -> ExperienceEntry:
    """규칙 하나에 붙인 교훈."""
    return ExperienceEntry(
        id=new_id(),
        kind="note",
        lesson=lesson,
        rule_id=rule_id,
        evidence={},
        basis={"rule_id": rule_id, "rule_version": (rule_versions or {}).get(rule_id)},
    )


def relevant(experiences: list[Experience], rule_id: str = "", family: str = "") -> list[Experience]:
    """규칙·계열에 맞는 활성 교훈만 고른다."""
    picked = [e for e in experiences if e.state == STATE_ACTIVE]
    if rule_id:
        picked = [e for e in picked if e.entry.rule_id == rule_id]
    if family:
        picked = [e for e in picked if e.entry.family == family]
    return picked
