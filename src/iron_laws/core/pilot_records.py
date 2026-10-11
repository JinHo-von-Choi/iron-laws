"""파일럿 JSONL 레코드의 형식과 수치 경계."""

import math

from iron_laws.core.config import ConfigError

FIELDS = {
    "assign": {"pr": str, "team": str, "stratum": str, "arm": str, "block": int, "seed": int},
    "review": {"pr": str, "team": str, "arm": str, "minutes": float, "risk_accepted": bool},
    "risk": {"pr": str, "risk": str, "arm": str, "team": str},
    "dropout": {"team": str, "reason": str},
}
OPTIONAL = {"reviewer": str, "note": str, "status": str, "closes": str, "stratum": str,
            "setup_minutes": float, "overhead_minutes": float, "outcome": str}
RISK_KINDS = ("misaccept", "dangerous_inheritance", "legitimate_exception")


def validate_record(record: object, number: int) -> dict:
    def invalid(field: str) -> None:
        raise ConfigError(f"파일럿 기록 {number}번째 줄의 {field} 필드가 올바르지 않습니다")

    if not isinstance(record, dict) or not isinstance(record.get("kind"), str):
        invalid("kind")
    kind = record["kind"]
    if kind not in FIELDS:
        invalid("kind")
    fields = {**OPTIONAL, **FIELDS[kind]}
    for field, expected in fields.items():
        if field not in record:
            if field in FIELDS[kind]:
                invalid(field)
            continue
        value = record[field]
        if expected is float:
            if type(value) not in (int, float) or value < 0:
                invalid(field)
            try:
                finite = math.isfinite(value)
            except OverflowError:
                finite = False
            if not finite:
                invalid(field)
        elif type(value) is not expected:
            invalid(field)
    if kind in ("assign", "review") and record["arm"] not in ("baseline", "bundle"):
        invalid("arm")
    if kind == "risk":
        if record["risk"] not in RISK_KINDS or record["arm"] not in ("", "baseline", "bundle"):
            invalid("risk/arm")
        if record.get("status", "confirmed") not in ("confirmed", "investigating"):
            invalid("status")
        if "closes" in record and record["closes"] not in RISK_KINDS:
            invalid("closes")
    return record
