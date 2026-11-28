"""
매니페스트 읽기: pyproject.toml의 직접 의존 이름과 requirements 파일의 `==` 고정 줄 형식,
Maven pom.xml·Gradle(build.gradle, libs.versions.toml)의 직접 의존성(잠금 파일이 없어 전이 의존성은 알 수 없다).
락 파일 해석(lockfiles.py), 버전 단위 그래프(graph.py), 지원 종료 판정(AI-121)이 함께 쓴다.
작성자: 최진호
작성일: 2026-11-12
"""

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from iron_laws.deps.versions import normalize_name

REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.!+_-]+)")


def pyproject_direct(path: Path) -> set[str]:
    """pyproject.toml의 [project].dependencies와 Poetry 의존 표에 적힌 직접 의존 이름. 파일이 없으면 빈 집합"""
    names: set[str] = set()
    if not path.is_file():
        return names
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    for req in (data.get("project") or {}).get("dependencies") or []:
        m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", str(req))
        if m:
            names.add(normalize_name("PyPI", m.group(1)))
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    for section in ("dependencies", "dev-dependencies"):
        for name in (poetry.get(section) or {}):
            if name.lower() != "python":
                names.add(normalize_name("PyPI", name))
    for group in (poetry.get("group") or {}).values():
        for name in (group.get("dependencies") or {}):
            names.add(normalize_name("PyPI", name))
    return names


@dataclass(frozen=True)
class MavenDependency:
    coordinate: str  # groupId:artifactId
    version: str | None  # 속성을 풀어도 정하지 못하면 None
    line: int
    scope: str = ""


POM_PROPERTY = re.compile(r"\$\{([^}]+)\}")


def _tag(block: str, name: str) -> str | None:
    m = re.search(rf"<{name}>\s*([^<]*?)\s*</{name}>", block)
    return m.group(1) if m else None


def parse_pom(text: str) -> tuple[MavenDependency | None, list[MavenDependency]]:
    """pom.xml의 (parent, 직접 의존성 목록). ${속성}은 <properties>와 project.version·project.parent.version으로 푼다.
    버전이 없는 의존성은 Spring Boot parent가 관리하는 org.springframework.boot 묶음이면 parent 버전을 쓴다."""
    body = re.sub(r"<!--.*?-->", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.DOTALL)
    props: dict[str, str] = {}
    prop_block = re.search(r"<properties>(.*?)</properties>", body, re.DOTALL)
    if prop_block:
        props.update({k: v.strip() for k, v in re.findall(r"<([\w.\-]+)>\s*([^<]*?)\s*</\1>", prop_block.group(1))})
    parent = None
    pm = re.search(r"<parent>(.*?)</parent>", body, re.DOTALL)
    if pm:
        group, artifact, version = _tag(pm.group(1), "groupId"), _tag(pm.group(1), "artifactId"), _tag(pm.group(1), "version")
        if group and artifact:
            parent = MavenDependency(f"{group}:{artifact}", version, body.count("\n", 0, pm.start()) + 1, "parent")
            if version:
                props.setdefault("project.parent.version", version)
    head = re.sub(r"<parent>.*?</parent>|<dependencies>.*|<dependencyManagement>.*|<build>.*|<profiles>.*", "", body, flags=re.DOTALL)
    own = _tag(head, "version")
    if own:
        props.setdefault("project.version", own)

    def resolve(value: str | None) -> str | None:
        if value is None:
            return None
        for _ in range(5):
            if "${" not in value:
                return value
            value = POM_PROPERTY.sub(lambda m: props.get(m.group(1), m.group(0)), value)
        return None if "${" in value else value

    deps: list[MavenDependency] = []
    managed = re.search(r"<dependencyManagement>.*?</dependencyManagement>", body, re.DOTALL)
    for m in re.finditer(r"<dependency>(.*?)</dependency>", body, re.DOTALL):
        if managed and managed.start() <= m.start() < managed.end():
            continue
        block = m.group(1)
        group, artifact = _tag(block, "groupId"), _tag(block, "artifactId")
        if not group or not artifact:
            continue
        version = resolve(_tag(block, "version"))
        if version is None and parent is not None and parent.coordinate.startswith("org.springframework.boot:") and group.startswith("org.springframework.boot"):
            version = parent.version
        deps.append(MavenDependency(f"{group}:{artifact}", version, body.count("\n", 0, m.start()) + 1, _tag(block, "scope") or ""))
    if parent is not None:
        parent = MavenDependency(parent.coordinate, resolve(parent.version), parent.line, "parent")
    return parent, deps


GRADLE_DEP = re.compile(r"""(?m)^\s*(?:implementation|api|compile|runtimeOnly|compileOnly|testImplementation|annotationProcessor)\s*\(?\s*["']([\w.\-]+):([\w.\-]+)(?::([\w.\-+]+))?["']""")


def parse_gradle(text: str) -> list[MavenDependency]:
    """build.gradle(.kts)의 `그룹:이름[:버전]` 문자열 의존성. 버전이 없으면(BOM·플랫폼이 관리) version이 None이다"""
    return [MavenDependency(f"{m.group(1)}:{m.group(2)}", m.group(3), text.count("\n", 0, m.start()) + 1) for m in GRADLE_DEP.finditer(text)]


def parse_version_catalog(text: str) -> list[MavenDependency]:
    """gradle/libs.versions.toml의 [libraries]. version.ref는 [versions]로 푼다"""
    data = tomllib.loads(text)
    versions = {k: str(v) for k, v in (data.get("versions") or {}).items() if isinstance(v, str | int | float)}
    out: list[MavenDependency] = []
    lines = text.splitlines()
    for alias, spec in (data.get("libraries") or {}).items():
        line = next((i for i, row in enumerate(lines, start=1) if re.match(rf"\s*{re.escape(alias)}\s*=", row)), 1)
        if isinstance(spec, str):
            parts = spec.split(":")
            if len(parts) >= 2:
                out.append(MavenDependency(f"{parts[0]}:{parts[1]}", parts[2] if len(parts) > 2 else None, line))
            continue
        if not isinstance(spec, dict):
            continue
        module = spec.get("module") or (f"{spec.get('group')}:{spec.get('name')}" if spec.get("group") else None)
        version = spec.get("version")
        if isinstance(version, dict):
            version = versions.get(str(version.get("ref"))) if version.get("ref") else version.get("strictly") or version.get("require")
        if module:
            out.append(MavenDependency(str(module), str(version) if version else None, line))
    return out
