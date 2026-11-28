"""
의존성 버전 비교: PyPI는 PEP 440(packaging), npm은 semver 2.0.0(선행 릴리스 규칙 포함), Maven은 ComparableVersion 순서
(숫자는 수로, 한정자는 alpha < beta < milestone < rc < snapshot < 정식 < sp 순으로 비교)
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


MAVEN_QUALIFIERS = {"alpha": 1, "a": 1, "beta": 2, "b": 2, "milestone": 3, "m": 3, "rc": 4, "cr": 4, "snapshot": 5, "": 6, "ga": 6, "final": 6, "release": 6, "sp": 7}


@total_ordering
@dataclass(frozen=True)
class MavenVersion:
    items: tuple[tuple[int, int, str], ...]

    def __lt__(self, other: "MavenVersion") -> bool:
        pad = (0, MAVEN_QUALIFIERS[""], "")
        size = max(len(self.items), len(other.items))
        left = self.items + (pad,) * (size - len(self.items))
        right = other.items + (pad,) * (size - len(other.items))
        return left < right


def parse_maven(text: str) -> MavenVersion | None:
    tokens = re.findall(r"\d+|[A-Za-z]+", text.lower())
    if not tokens or not tokens[0].isdigit():  # iron-laws: ignore[IL-307] 숫자로 시작하지 않는 버전은 비교할 수 없어 None으로 돌려 호출한 쪽이 판정 불가로 처리한다
        return None
    items: list[tuple[int, int, str]] = []
    for token in tokens:
        if token.isdigit():
            items.append((1, int(token), ""))
        else:
            while items and items[-1] == (1, 0, ""):
                items.pop()  # 1.0-rc1은 1-rc-1과 같다: 한정자 앞의 0은 지운다
            rank = MAVEN_QUALIFIERS.get(token)
            items.append((0, rank, "") if rank is not None else (0, 8, token))
    while items and items[-1] in ((1, 0, ""), (0, MAVEN_QUALIFIERS[""], "")):
        items.pop()
    return MavenVersion(tuple(items))


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
    if ecosystem == "Maven":
        return parse_maven(text)
    return None


def normalize_name(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name
