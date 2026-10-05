"""
의존성 버전 비교: PyPI는 PEP 440(packaging), npm은 semver 2.0.0(선행 릴리스 규칙 포함)
해석할 수 없는 버전은 None으로 돌려주고 호출하는 쪽이 `판정 불가`로 다룬다(추정하지 않는다).
작성자: 최진호
작성일: 2026-10-05
"""

import re
from dataclasses import dataclass
from functools import total_ordering

from packaging.version import InvalidVersion, Version

SEMVER_RE = re.compile(r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


@total_ordering
@dataclass(frozen=True)
class SemVer:
    major: int
    minor: int
    patch: int
    pre: tuple[str, ...] = ()

    def _key(self) -> tuple:
        return (self.major, self.minor, self.patch)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SemVer) and self._key() == other._key() and self.pre == other.pre

    def __lt__(self, other: "SemVer") -> bool:
        if self._key() != other._key():
            return self._key() < other._key()
        if self.pre == other.pre:
            return False
        if not self.pre:
            return False  # 선행 릴리스가 없는 쪽이 더 높다
        if not other.pre:
            return True
        for a, b in zip(self.pre, other.pre, strict=False):
            if a == b:
                continue
            a_num, b_num = a.isdigit(), b.isdigit()
            if a_num and b_num:
                return int(a) < int(b)
            if a_num != b_num:
                return a_num  # 숫자 식별자가 문자 식별자보다 낮다
            return a < b
        return len(self.pre) < len(other.pre)


def parse_semver(text: str) -> SemVer | None:
    m = SEMVER_RE.match(text.strip())
    if m is None:
        return None
    return SemVer(int(m.group(1)), int(m.group(2)), int(m.group(3)), tuple(m.group(4).split(".")) if m.group(4) else ())


def parse_version(ecosystem: str, text: str):
    """에코시스템에 맞는 비교 가능한 버전 객체, 해석할 수 없으면 None"""
    text = str(text).strip()
    if ecosystem == "PyPI":
        try:
            return Version(text)
        except InvalidVersion:  # iron-laws: ignore[IL-301] 비교할 수 없는 버전은 None으로 돌려 호출한 쪽이 판정 불가로 처리한다
            return None
    if ecosystem == "npm":
        return parse_semver(text)
    return None


def normalize_name(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name
