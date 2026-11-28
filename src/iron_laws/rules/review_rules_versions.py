"""
검토자가 자주 지적하는 버전 항목: 런타임·프레임워크 버전 표기 불일치와 정책 위반, 지원 종료(AI-121).
지원 종료 자료(policies.eol_db)로 Dockerfile·Compose 이미지, Maven·Gradle 직접 의존성, Python·Node 런타임 표기를 판정한 결과(eol_report)는
AI-121과 보고서(metadata.eol)가 함께 쓴다.
작성자: 최진호
작성일: 2026-11-23
"""

import re
from dataclasses import dataclass

from iron_laws.core.models import Confidence, IronLaw, Severity, Violation
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.source import SourceFile
from iron_laws.rules.ai_code_common import AiRule
from iron_laws.rules.review_rules import _line_of


@dataclass
class RuntimeUse:
    version: tuple[int, ...]
    src: SourceFile
    line: int
    label: str
    role: str = "fixed"


CHANGELOG_DOC_RE = re.compile(r"(?i)(change|release|history|news|migration|upgrade|todo|roadmap)")


def _vt(value: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", value)[:3])


def _java_major(raw: str) -> int:
    raw = raw.strip()
    if raw.startswith("1."):
        return int(raw.split(".")[1])
    match = re.match(r"\d+", raw)
    if match is None:
        raise ValueError("숫자로 시작하지 않는 Java 버전")
    return int(match.group(0))


class VersionRule(AiRule):
    version = 3
    rule_id = "AI-121"
    name = "런타임·프레임워크 버전 표기 불일치와 정책 위반"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    plain = "문서에는 Java 17, 빌드 파일에는 21처럼 버전이 서로 다르면 어느 쪽이 실제 운영 환경인지 알 수 없고, 보안 패치가 적용된 버전인지도 확인할 수 없습니다."
    how_to_fix = "실제로 쓰는 런타임·프레임워크 버전을 하나로 정하고 빌드 파일, Dockerfile, CI, 문서의 표기를 같은 값으로 맞추세요. 기관이 정한 최소 버전은 .iron-laws.yml의 policies.min_versions에 적어 두면 자동으로 점검합니다."

    java_patterns = {
        "pom": re.compile(r"<(?:java\.version|maven\.compiler\.(?:source|target|release)|release)>\s*(\d+(?:\.\d+)?)\s*<"),
        "gradle": re.compile(r"sourceCompatibility\s*=?\s*['\"]?(?:JavaVersion\.VERSION_)?(\d+(?:[._]\d+)?)|JavaLanguageVersion\.of\(\s*(\d+)|jvmTarget\s*=\s*['\"](\d+)"),
        "docker": re.compile(r"(?i)^\s*FROM\s+[^\n]*?(?:temurin|openjdk|corretto|zulu|jdk|jre|java)[:\-]?(\d{1,2})\b"),
        "actions": re.compile(r"java-version\s*:\s*['\"]?(\d{1,2})\b"),
        "doc": re.compile(r"(?i)\b(?:Java|JDK|자바)\s*(\d{1,2})(?:\s*[/,]\s*(\d{1,2}))?"),
    }
    python_patterns = {
        "version": re.compile(r"^\s*(?:python\s+)?(3\.\d+)"),
        "docker": re.compile(r"(?i)^\s*FROM\s+(?:[\w./-]*/)?python:(3\.\d+)"),
        "actions": re.compile(r"python-version\s*:\s*['\"]?(3\.\d+)['\"]?\s*$"),
        "doc": re.compile(r"(?i)\bPython\s*(3\.\d+)"),
    }
    node_patterns = {
        "version": re.compile(r"^\s*v?(\d{1,2})(?:\.\d+)*\s*$"),
        "docker": re.compile(r"(?i)^\s*FROM\s+(?:[\w./-]*/)?node:(\d{1,2})"),
        "actions": re.compile(r"node-version\s*:\s*['\"]?(\d{1,2})\b"),
        "doc": re.compile(r"(?i)\bNode(?:\.js)?\s*v?(\d{1,2})\b"),
    }

    def check_project(self, project: ProjectContext) -> list[Violation]:
        policies = project.config.policies.min_versions
        found: list[Violation] = []
        for runtime, patterns, key in (("Java", self.java_patterns, "java"), ("Python", self.python_patterns, "python"), ("Node.js", self.node_patterns, "node")):
            uses = self._collect(project, patterns, runtime)
            found.extend(self._mismatch(runtime, uses))
            found.extend(self._policy(runtime, key, uses, policies))
            if not project.config.policies.eol_db:
                found.extend(self._eol(runtime, uses))
        found.extend(self._spring_boot(project, policies))
        found.extend(self._dependencies(project, policies))
        found.extend(self._eol_data(project))
        return found

    def _eol_data(self, project: ProjectContext) -> list[Violation]:
        """지원 종료 자료로 판정한 제품. 자료를 지정하지 않으면 내장 목록(_eol, Spring Boot 주 버전)만 쓴다."""
        report = eol_report(project)
        by_path = {f.path.as_posix(): f for f in project.files}
        found = []
        for row in report.rows:
            src = by_path.get(row.file)
            if src is None or report.data is None:
                continue
            found.append(
                self.at_line(
                    src,
                    row.line,
                    f"{row.source}: {row.product} {row.cycle}은(는) {row.eol}에 지원이 끝났습니다(지원 종료 자료 수집일 {report.data['fetched_at']}, 근거 {row.url}).",
                    severity=Severity.MEDIUM,
                    how_to_fix="지원이 계속되는 주기로 올리세요. 바로 올릴 수 없으면 대체 통제(접근 제한, 감시)와 교체 일정을 기록해 두세요.",
                )
            )
        return found

    @staticmethod
    def _kind_of(src: SourceFile) -> str | None:
        name = src.path.name
        if name == "pom.xml":
            return "pom"
        if src.kind == "gradle":
            return "gradle"
        if src.kind == "docker":
            return "docker"
        if src.kind == "actions":
            return "actions"
        if src.kind == "version":
            return "version"
        if src.kind == "doc":
            return "doc"
        return None

    def _collect(self, project: ProjectContext, patterns: dict[str, re.Pattern[str]], runtime: str) -> list[RuntimeUse]:
        uses: list[RuntimeUse] = []
        for src in project.files:
            kind = self._kind_of(src)
            pattern = patterns.get(kind) if kind else None
            if pattern is None:
                continue
            if kind == "version" and not self._version_file_matches(src, runtime):
                continue
            if kind == "doc" and CHANGELOG_DOC_RE.search(src.path.name):
                continue
            for idx, line in enumerate(src.lines, start=1):
                m = pattern.search(line)
                matrix = kind == "actions" and re.search(r"(?:python-version|java-version|node-version)\s*:\s*\[", line)
                if (not m and not matrix) or "$" in line:
                    continue
                if matrix:
                    key = {"Python": "python-version", "Java": "java-version", "Node.js": "node-version"}[runtime]
                    if key not in line:
                        continue
                    groups = re.findall(r"3\.\d+" if runtime == "Python" else r"\b\d{1,2}\b", line)
                    role = "supported"
                else:
                    groups = [g for g in m.groups() if g]
                    role = "fixed"
                    if kind == "doc":
                        tail = line[m.end():]
                        if re.match(r"\s*(?:\+|이상|or later|and above|or newer)", tail, re.I) or re.search(r"(?:>=|최소|minimum|at least)\s*(?:Python|Java|JDK|Node(?:\.js)?)?\s*$", line[:m.start()], re.I):
                            role = "minimum"
                        elif re.match(r"\s*(?:/|,)\s*\d", tail):
                            role = "supported"
                            groups = re.findall(r"3\.\d+" if runtime == "Python" else r"\b\d{1,2}\b", line[m.start():])
                for raw in groups:
                    try:
                        value = (_java_major(raw.replace("_", ".")),) if runtime == "Java" else _vt(raw)
                    except (ValueError, AttributeError):  # iron-laws: ignore[IL-301] 숫자가 아닌 표기는 버전으로 보지 않는다
                        continue
                    if value and not (runtime == "Java" and value[0] < 6):
                        uses.append(RuntimeUse(value, src, idx, f"{src.path.as_posix()}:{idx}", role))
        return uses

    @staticmethod
    def _version_file_matches(src: SourceFile, runtime: str) -> bool:
        name = src.path.name
        if runtime == "Python":
            return name == ".python-version"
        if runtime == "Node.js":
            return name in (".nvmrc", ".node-version")
        return name == ".java-version"

    def _mismatch(self, runtime: str, uses: list[RuntimeUse]) -> list[Violation]:
        if not uses:
            return []
        fixed = [u for u in uses if u.role == "fixed"]
        selected = [u for u in fixed if self._kind_of(u.src) != "doc"]
        minimum = [u for u in uses if u.role == "minimum"]
        support_groups: dict[str, set[tuple[int, ...]]] = {}
        for u in uses:
            if u.role == "supported":
                support_groups.setdefault(u.label, set()).add(u.version)
        mismatch = len({u.version for u in fixed}) > 1
        mismatch |= any(u.version < lower.version for u in selected for lower in minimum)
        mismatch |= any(u.version not in allowed for u in selected for allowed in support_groups.values())
        if not mismatch:
            return []
        non_doc = [u for u in uses if self._kind_of(u.src) != "doc"]
        docs = [u for u in uses if self._kind_of(u.src) == "doc"]
        shown = ", ".join(f"{'.'.join(map(str, u.version))}({u.label})" for u in sorted(uses, key=lambda x: x.label)[:6])
        anchor = sorted(non_doc or docs, key=lambda x: x.label)[0]
        return [
            self.at_line(
                anchor.src,
                anchor.line,
                f"{runtime} 버전 표기가 서로 다릅니다: {shown}. 실제 적용 버전을 하나로 확정하고 빌드 파일·Dockerfile·CI·문서를 맞추십시오.",
            )
        ]

    def _policy(self, runtime: str, key: str, uses: list[RuntimeUse], policies: dict[str, str]) -> list[Violation]:
        minimum = policies.get(key)
        if not minimum or not uses:
            return []
        floor = _vt(minimum)
        found = []
        for u in uses:
            if self._kind_of(u.src) == "doc":
                continue
            if u.version < floor[: len(u.version)] or (len(u.version) >= len(floor) and u.version < floor):
                found.append(
                    self.at_line(
                        u.src,
                        u.line,
                        f"{runtime} {'.'.join(map(str, u.version))}은(는) 정책 최소 버전 {minimum}보다 낮습니다.",
                        severity=Severity.HIGH,
                    )
                )
        return found

    EOL_BELOW = {"Node.js": (21,), "Python": (3, 10)}

    def _eol(self, runtime: str, uses: list[RuntimeUse]) -> list[Violation]:
        limit = self.EOL_BELOW.get(runtime)
        if limit is None:
            return []
        found = []
        seen: set[tuple[str, int]] = set()
        for u in uses:
            if self._kind_of(u.src) == "doc" or u.version >= limit:
                continue
            key = (u.src.path.as_posix(), u.line)
            if key in seen:
                continue
            seen.add(key)
            found.append(
                self.at_line(
                    u.src,
                    u.line,
                    f"{runtime} {'.'.join(map(str, u.version))}은(는) 공식 지원이 종료된 것으로 알려진 버전입니다. 보안 패치 제공 여부를 확인하고 지원되는 버전으로 올리십시오.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.REVIEW,
                )
            )
        return found

    def _spring_boot(self, project: ProjectContext, policies: dict[str, str]) -> list[Violation]:
        found = []
        for src in project.files:
            if src.is_test:
                continue
            text = src.text
            version = None
            if src.path.name == "pom.xml":
                m = re.search(r"<parent>.*?spring-boot-starter-parent.*?<version>\s*([\d.]+)", text, re.DOTALL)
                version = m.group(1) if m else None
            elif src.kind == "gradle":
                m = re.search(r"org\.springframework\.boot['\"]\)?\s*version\s*['\"]([\d.]+)|springBootVersion\s*=\s*['\"]([\d.]+)", text)
                version = (m.group(1) or m.group(2)) if m else None
            if not version:
                continue
            idx = text.find(version)
            line = _line_of(text, idx)
            minimum = policies.get("spring-boot")
            if minimum and _vt(version) < _vt(minimum):
                found.append(
                    self.at_line(src, line, f"Spring Boot {version}은(는) 정책 최소 버전 {minimum}보다 낮습니다.", severity=Severity.HIGH)
                )
            elif _vt(version)[:1] and _vt(version)[0] <= 2 and not project.config.policies.eol_db:
                found.append(
                    self.at_line(
                        src,
                        line,
                        f"Spring Boot {version}은(는) 오래된 주 버전입니다. 지원 종료 여부와 보안 패치 적용 가능성을 확인하십시오.",
                        severity=Severity.LOW,
                        confidence=Confidence.REVIEW,
                    )
                )
        return found

    def _dependencies(self, project: ProjectContext, policies: dict[str, str]) -> list[Violation]:
        named = {k: v for k, v in policies.items() if k not in ("java", "python", "node", "spring-boot")}
        if not named:
            return []
        found = []
        for src in project.files:
            for name, minimum in named.items():  # iron-laws: ignore[PERF-102] named는 정책에 적은 최소 버전 표라 몇 개다
                pattern = None
                if src.path.name == "package.json":
                    pattern = re.compile(rf'"{re.escape(name)}"\s*:\s*"[\^~>=\s]*([\d.]+)')
                elif re.match(r"requirements.*\.txt$", src.path.name):
                    pattern = re.compile(rf"(?im)^{re.escape(name)}\s*(?:==|>=|~=)\s*([\d.]+)")
                if pattern is None:
                    continue
                m = pattern.search(src.text)
                if m and _vt(m.group(1)) < _vt(minimum):
                    found.append(
                        self.at_line(
                            src,
                            _line_of(src.text, m.start()),
                            f"{name} {m.group(1)}은(는) 정책 최소 버전 {minimum}보다 낮습니다.",
                            severity=Severity.HIGH,
                        )
                    )
        return found


@dataclass(frozen=True)
class EolRow:
    product: str
    version: str
    cycle: str
    eol: str
    url: str
    file: str
    line: int
    source: str  # 판정한 표기(Dockerfile FROM, pom 의존성 등)

    def as_row(self) -> dict:
        return dict(self.__dict__)


@dataclass(frozen=True)
class EolReport:
    data: dict | None  # 자료 설명(source, fetched_at, sha256, products). 자료를 쓰지 않으면 None
    rows: tuple[EolRow, ...]
    error: str | None  # 지정한 자료를 읽지 못한 이유


def _eol_targets(project: ProjectContext):
    """(제품, 버전, 파일, 줄, 표기) 후보: Dockerfile FROM, Compose image, pom·Gradle 직접 의존성, Python·Node 런타임 표기"""
    from iron_laws.deps.eol import docker_product, maven_product
    from iron_laws.deps.manifests import parse_gradle, parse_pom, parse_version_catalog

    for src in project.files:
        if src.is_test:
            continue
        if src.kind in ("docker", "compose"):
            pattern = r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)" if src.kind == "docker" else r"(?im)^\s*image\s*:\s*['\"]?([^\s'\"]+)"
            for m in re.finditer(pattern, src.text):
                hit = docker_product(m.group(1))
                if hit:
                    yield hit[0], hit[1], src, _line_of(src.text, m.start()), f"이미지 {m.group(1)}"
        deps = []
        if src.path.name == "pom.xml":
            parent, deps = parse_pom(src.text)
            deps = ([parent] if parent else []) + deps
        elif src.path.name in ("build.gradle", "build.gradle.kts"):
            deps = parse_gradle(src.text)
        elif src.path.name == "libs.versions.toml":
            try:
                deps = parse_version_catalog(src.text)
            except ValueError:  # iron-laws: ignore[IL-301] TOML 문법 오류인 카탈로그는 판정 대상에서 뺀다
                deps = []
        for d in deps:
            product = maven_product(d.coordinate)
            if product and d.version:
                yield product, d.version, src, d.line, f"의존성 {d.coordinate}"
    rule = VersionRule()
    for runtime, patterns, product in (("Python", VersionRule.python_patterns, "python"), ("Node.js", VersionRule.node_patterns, "nodejs")):
        for u in rule._collect(project, patterns, runtime):
            if VersionRule._kind_of(u.src) not in ("doc", "docker"):
                yield product, ".".join(map(str, u.version)), u.src, u.line, u.label or runtime


def eol_report(project: ProjectContext) -> EolReport:
    """지원 종료 자료(policies.eol_db)로 판정한 결과. 프로젝트마다 한 번만 계산해 AI-121과 보고서가 함께 쓴다."""
    cached = project.cache.get("eol_report")
    if cached is not None:
        return cached
    from pathlib import Path

    from iron_laws.deps.eol import EolDataError, judge, load_eol_data

    location = project.config.policies.eol_db
    if not location:
        report = EolReport(None, (), None)
    else:
        folder = Path(location)
        if not folder.is_absolute():
            folder = project.root / folder
        try:
            data = load_eol_data(folder)
        except EolDataError as e:
            report = EolReport(None, (), str(e))
        else:
            rows: dict[tuple[str, int, str], EolRow] = {}
            for product, version, src, line, label in _eol_targets(project):
                verdict = judge(data, product, version)
                if verdict is not None:
                    rows.setdefault((src.path.as_posix(), line, product), EolRow(product, version, verdict.cycle, verdict.eol, verdict.url, src.path.as_posix(), line, label))
            report = EolReport({**data.describe(), "source": location}, tuple(rows[k] for k in sorted(rows)), None)
    project.cache["eol_report"] = report
    return report
