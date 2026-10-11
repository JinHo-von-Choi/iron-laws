"""점검 결과의 공통 등급·버전 값."""
from importlib.metadata import PackageNotFoundError, version

from iron_laws.core.models import Severity

SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}

NOT_SCANNED_GRADE = "점검 없음"
INCOMPLETE_GRADE = "불완전"
def tool_version() -> str:
    try:
        return version("iron-laws")
    except PackageNotFoundError:  # iron-laws: ignore[IL-301] 설치 메타데이터가 없는 소스 실행에서는 버전을 알 수 없다고 표기한다
        return "0.0.0"
