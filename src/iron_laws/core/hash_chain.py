"""
해시로 이어 붙인 추가 전용 기록 파일(JSONL): 승인 기록(approvals.py)과 교훈 기록(experience.py)이 함께 쓴다.
각 줄은 순번(seq), 앞 줄의 해시(prev), 자기 내용의 해시(hash)를 가진다. 줄을 지우거나 순서를 바꾸거나 내용을 고치면 연결이 끊긴다.
작성자: 최진호
작성일: 2026-11-12
"""

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ValidationError

from iron_laws.core.config import ConfigError

GENESIS = "0" * 24


class ChainedRecord(Protocol):
    seq: int
    prev: str
    hash: str

    def compute_hash(self) -> str: ...


def load_records[RecordT: BaseModel](path: Path, model: type[RecordT], label: str) -> list[RecordT]:
    """기록 파일을 줄마다 model로 읽는다. 읽을 수 없는 파일이나 줄이 있으면 ConfigError로 끝낸다(건너뛰지 않는다)."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as e:
        raise ConfigError(f"{label}을 읽을 수 없습니다: {path} ({e})") from e
    records: list[RecordT] = []
    for number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            records.append(model(**json.loads(raw)))
        except (json.JSONDecodeError, ValidationError, TypeError) as e:
            raise ConfigError(f"{label} {number}번째 줄을 읽을 수 없습니다: {e}") from e
    return records


def chain_problems(records: Sequence[ChainedRecord]) -> list[str]:
    """각 줄의 해시와 앞 줄 연결을 확인한다. 문제가 있으면 사유 목록을 돌려준다."""
    problems: list[str] = []
    previous = GENESIS
    for index, record in enumerate(records):
        if record.seq != index + 1:
            problems.append(f"{index + 1}번째 기록의 순번이 맞지 않는다(seq={record.seq})")
        if record.prev != previous:
            problems.append(f"{index + 1}번째 기록이 앞 기록과 이어지지 않는다(삭제·재배열 의심)")
        if record.compute_hash() != record.hash:
            problems.append(f"{index + 1}번째 기록의 내용 해시가 맞지 않는다(내용 변경 의심)")
        previous = record.hash
    return problems
