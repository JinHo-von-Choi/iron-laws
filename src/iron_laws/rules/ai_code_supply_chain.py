"""
오철칙 공급망 규칙(AI-111): 매니페스트에 없거나 존재하지 않는 패키지를 import하는 코드
작성자: 최진호
작성일: 2026-11-12
"""

import fnmatch
import re
import sys
import tomllib
from pathlib import Path, PurePosixPath

from iron_laws.core.models import Confidence, IronLaw, Severity, Violation
from iron_laws.deps.lockfiles import PARSERS as LOCK_PARSERS
from iron_laws.deps.lockfiles import parse_lock
from iron_laws.deps.package_index import PackageIndexError, load_index, normalize
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.source import SourceFile
from iron_laws.rules.ai_code_common import (
    POPULAR_NPM,
    POPULAR_PY,
    AiRule,
    _levenshtein,
    _load_json_object,
)

EXCLUDED_SPEC = re.compile(r"^(workspace:|file:|link:|portal:|patch:|git\+|git:|github:|gitlab:|bitbucket:|https?:|\.{0,2}/|~/)")


def _npm_alias_target(spec: str) -> str | None:
    """`npm:실제이름@버전` 별칭이면 실제 이름"""
    if not spec.startswith("npm:"):
        return None
    body = spec[4:]
    head, at, _version = body.rpartition("@")
    return (head if at and head else body) or None


def _pyproject_names(data: dict) -> list[str]:
    """pyproject.toml의 직접 의존 이름(PEP 621·735, Poetry). 경로·Git·URL 의존은 뺀다"""
    names: list[str] = []
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    requirements = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        requirements += list(group or [])
    for group in (data.get("dependency-groups") or {}).values():
        requirements += [r for r in group or [] if isinstance(r, str)]
    for requirement in requirements:
        m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", requirement) if isinstance(requirement, str) else None
        if m and " @ " not in requirement:
            names.append(m.group(1))
    poetry = (data.get("tool") or {}).get("poetry") or {}
    tables = [poetry.get("dependencies") or {}, poetry.get("dev-dependencies") or {}]
    tables += [(g or {}).get("dependencies") or {} for g in (poetry.get("group") or {}).values() if isinstance(g, dict)]
    for table in tables:
        for name, spec in table.items():
            if name.lower() != "python" and not (isinstance(spec, dict) and set(spec) & {"path", "git", "url"}):
                names.append(name)
    return names


NODE_BUILTINS = frozenset(
    "assert async_hooks buffer child_process cluster console constants crypto dgram diagnostics_channel dns domain events fs http http2 https "
    "inspector module net os path perf_hooks process punycode querystring readline repl stream string_decoder sys timers tls trace_events tty "
    "url util v8 vm wasi worker_threads zlib test".split()
)


def _local_module_names(paths) -> set[str]:
    """프로젝트 안의 모듈·패키지·폴더 이름(최상위 import 이름이 될 수 있는 것)"""
    names: set[str] = set()
    for rel in paths:
        parts = PurePosixPath(rel).parts
        names.update(p.lower() for p in parts[:-1])
        names.add(PurePosixPath(rel).stem.lower())
    return names


def _python_imports(src: SourceFile) -> list[tuple[int, str]]:
    found = []
    for node in src.nodes:
        if node.type == "import_statement":
            for child in node.named_children:
                name = child.child_by_field_name("name") if child.type == "aliased_import" else child
                if name is not None and name.type == "dotted_name":
                    found.append((src.line_of(node), src.text_of(name).split(".", 1)[0].lower()))
        elif node.type == "import_from_statement":
            module = node.child_by_field_name("module_name")
            if module is not None and module.type == "dotted_name" and src.text_of(module) != "__future__":
                found.append((src.line_of(node), src.text_of(module).split(".", 1)[0].lower()))
    return found


def _js_imports(src: SourceFile) -> list[tuple[int, str]]:
    found = []
    for node in src.nodes:
        spec = None
        if node.type in ("import_statement", "export_statement"):
            spec = node.child_by_field_name("source")
        elif node.type == "call_expression":
            fn = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if fn is not None and src.text_of(fn) in ("require", "import") and args is not None and args.named_children:
                spec = args.named_children[0]
        if spec is None or spec.type != "string":
            continue
        text = src.text_of(spec)[1:-1]
        if not text or text.startswith((".", "/", "node:", "~", "#", "@/", "virtual:", "http:", "https:")) or "$" in text:
            continue
        parts = text.split("/")
        package = "/".join(parts[:2]) if text.startswith("@") else parts[0]
        found.append((src.line_of(node), package.lower()))
    return found


def _first_lines(lines: list[str]) -> dict[str, int]:
    """잠금 파일에서 패키지 이름이 처음 나오는 줄"""
    first: dict[str, int] = {}
    for i, text in enumerate(lines, start=1):
        for token in re.findall(r"(@?[A-Za-z0-9][\w.-]*(?:/[\w.-]+)?)", text):
            first.setdefault(token.lower(), i)
    return first


class SupplyChainRule(AiRule):
    rule_id = "AI-111"
    name = "의존성·공급망 위험 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    plain = "AI가 존재하지 않는 패키지 이름을 지어내거나 인기 패키지와 한 글자 다른 이름을 쓰면, 그 이름으로 올려 둔 악성 패키지가 설치됩니다. 버전을 고정하지 않으면 어느 날 업데이트된 악성 버전이 자동 설치됩니다."
    how_to_fix = "패키지 이름이 공식 이름과 정확히 같은지 확인하고, 버전을 고정(락 파일 커밋)하세요. 설치 스크립트(postinstall)와 사설 저장소 설정을 점검하세요."
    loose = re.compile(r"""^(\*|latest|x|>=?.*|.*\bx\b.*|git\+.*|https?://.*|github:.*)$""")

    def check(self, src: SourceFile) -> list[Violation]:
        if src.path.name == "package.json":
            return self._package_json(src)
        if re.match(r"requirements.*\.txt$", src.path.name):
            return self._requirements(src)
        if src.path.name == "pyproject.toml":
            return self._pyproject(src)
        return []

    # -- 패키지 이름 판정: 철자 유사·색인에 없음·최근 게시를 한 지적으로 합친다 --
    def _index(self):
        path = self.config.policies.package_index if self.config is not None else None
        if not path:
            return None
        try:
            return load_index(path)
        except PackageIndexError:  # iron-laws: ignore[IL-301] 색인 오류는 점검기가 진단으로 따로 알리고, 규칙은 색인 없이 철자 검사만 한다
            return None

    def _private(self, name: str) -> bool:
        patterns = self.config.policies.private_packages if self.config is not None else []
        return any(fnmatch.fnmatchcase(name.lower(), p.lower()) for p in patterns)

    def _judge(self, src: SourceFile, line: int, ecosystem: str, name: str, typo: bool = True) -> Violation | None:
        if self._private(name):
            return None
        popular = POPULAR_NPM if ecosystem == "npm" else POPULAR_PY
        hit = self._typosquat(name, popular) if typo else None
        index = self._index()
        eco = index.usable(ecosystem) if index is not None else None
        missing = eco is not None and not eco.knows(name)
        where = f"{eco.ecosystem} 색인(수집 {eco.collected_at.isoformat()})" if eco is not None else ""
        if hit:
            extra = f" {where}에도 없는 이름입니다." if missing else ""
            return self.at_line(src, line, f"패키지 {name}은(는) 인기 패키지 {hit}와 철자가 비슷합니다. 오타이거나 악성/존재하지 않는 패키지일 수 있습니다.{extra}", severity=Severity.HIGH, confidence=Confidence.REVIEW)
        if missing:
            return self.at_line(src, line, f"패키지 {name}은(는) {where}에 없는 이름입니다. AI가 지어낸 이름이면 나중에 같은 이름으로 올라온 악성 패키지가 설치될 수 있습니다.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW)
        days = eco.is_new(name) if eco is not None else None
        if days is not None:
            return self.at_line(src, line, f"패키지 {name}은(는) {where} 기준 {days}일 전에 처음 게시된 패키지입니다. 게시자와 내려받기 수를 확인하십시오.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW)
        return None

    def _package_json(self, src: SourceFile) -> list[Violation]:
        found = []
        data = _load_json_object(src.text)
        if data is None:
            return [self.at_line(src, 1, "package.json을 JSON으로 해석할 수 없어 의존성을 점검하지 못했습니다.", severity=Severity.LOW)]
        lines = src.lines
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            deps = data.get(section) or {}
            if not isinstance(deps, dict):
                continue
            for name, version in deps.items():
                line = next((i for i, text_line in enumerate(lines, start=1) if f'"{name}"' in text_line), 1)
                spec = version.strip() if isinstance(version, str) else ""
                if section != "peerDependencies" and spec and self.loose.match(spec):
                    found.append(self.at_line(src, line, f"{name}의 버전 {version}이(가) 고정되지 않아 의도치 않은 버전이 설치될 수 있습니다.", severity=Severity.LOW))
                if EXCLUDED_SPEC.match(spec):
                    continue  # 작업공간·로컬 경로·Git 의존은 레지스트리 이름이 아니다
                judged = self._judge(src, line, "npm", _npm_alias_target(spec) or name)
                if judged is not None:
                    found.append(judged)
        scripts = data.get("scripts") or {}
        if isinstance(scripts, dict):
            for key in ("preinstall", "install", "postinstall", "prepare"):
                value = scripts.get(key)
                if isinstance(value, str) and re.search(r"curl|wget|\bnode\s+-e|powershell|base64|eval", value):
                    line = next((i for i, text_line in enumerate(lines, start=1) if f'"{key}"' in text_line), 1)
                    found.append(self.at_line(src, line, f"{key} 스크립트가 외부 다운로드·난독화 명령을 실행합니다: {value[:60]}", severity=Severity.HIGH, confidence=Confidence.REVIEW))
        return found

    def _requirements(self, src: SourceFile) -> list[Violation]:
        found = []
        unpinned = 0
        first_unpinned = 0
        for idx, line in enumerate(src.code_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("-r") or stripped.startswith("--"):
                if re.match(r"--(extra-)?index-url\s+http://|--trusted-host", stripped):
                    found.append(self.at_line(src, idx, "암호화되지 않거나 신뢰 검증을 건너뛰는 패키지 저장소 설정입니다.", severity=Severity.HIGH))
                elif stripped.startswith("--extra-index-url"):
                    found.append(self.at_line(src, idx, "추가 패키지 저장소는 의존성 혼동 공격에 취약합니다.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
                continue
            if stripped.startswith(("-e", "git+", "http", ".", "/")) or " @ " in stripped:
                continue
            name = re.split(r"[=<>!~\[; ]", stripped, maxsplit=1)[0].lower()
            if "==" not in stripped and "@" not in stripped:
                unpinned += 1
                first_unpinned = first_unpinned or idx
            judged = self._judge(src, idx, "pypi", name)
            if judged is not None:
                found.append(judged)
        if unpinned:
            found.append(self.at_line(src, first_unpinned, f"버전을 고정하지 않은 의존성이 {unpinned}개 있습니다 (==로 고정하고 락 파일을 쓰십시오).", severity=Severity.LOW))
        return found

    def _pyproject(self, src: SourceFile) -> list[Violation]:
        try:
            data = tomllib.loads(src.text)
        except tomllib.TOMLDecodeError:
            return [self.at_line(src, 1, "pyproject.toml을 해석할 수 없어 의존성을 점검하지 못했습니다.", severity=Severity.LOW)]
        found = []
        seen: set[str] = set()
        for name in _pyproject_names(data):
            key = normalize("pypi", name)
            if key in seen:
                continue
            seen.add(key)
            pattern = re.compile(rf"(?i)(^|[\"'\s]){re.escape(name)}([\s\"'=<>!~\[;]|$)")
            line = next((i for i, text_line in enumerate(src.lines, start=1) if pattern.search(text_line)), 1)
            judged = self._judge(src, line, "pypi", name)
            if judged is not None:
                found.append(judged)
        return found

    def _lock_files(self, project: ProjectContext) -> list[Violation]:
        """잠금 파일의 전체 의존(직접·간접)을 색인과 맞춘다. 색인이 없으면 하지 않는다(철자 검사는 직접 의존 파일에서만 한다)."""
        index = self._index()
        if index is None or project.root is None:
            return []
        base = project.root if project.root.is_dir() else project.root.parent
        by_path = {f.path.as_posix(): f for f in project.files}
        found = []
        for rel in sorted(project.all_paths):
            name = PurePosixPath(rel).name
            if name not in LOCK_PARSERS:
                continue
            try:
                src = by_path.get(rel) or SourceFile(Path(rel), (base / rel).read_text(encoding="utf-8", errors="replace"))  # uv.lock 등은 점검 대상 확장자가 아니어도 읽는다
                info = parse_lock(base / rel)
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                src = by_path.get(rel) or SourceFile(Path(rel), "")
                found.append(self.at_line(src, 1, f"{name}을(를) 해석할 수 없어 의존 패키지 이름을 색인과 맞추지 못했습니다.", severity=Severity.LOW))
                continue
            ecosystem = "npm" if info.ecosystem == "npm" else "pypi"
            if index.usable(ecosystem) is None:
                continue
            first_line = _first_lines(src.lines)
            for package in sorted({p.name for p in info.packages}):
                judged = self._judge(src, first_line.get(package.lower(), 1), ecosystem, package, typo=False)
                if judged is not None:
                    found.append(judged)
        return found

    @staticmethod
    def _typosquat(name: str, popular: set[str]) -> str | None:
        n = name.lower().lstrip("@").split("/")[-1]
        if n in popular or len(n) < 5:
            return None
        for pkg in popular:
            if len(pkg) >= 5 and 0 < _levenshtein(n, pkg) <= 1:
                return pkg
        return None

    def check_project(self, project: ProjectContext) -> list[Violation]:
        found = []
        lockfiles = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock", "npm-shrinkwrap.json"}
        for src in project.files:
            if src.path.name != "package.json":
                continue
            data = _load_json_object(src.text)
            if data is None or not data.get("dependencies"):
                continue
            folder = src.path.parent.as_posix()
            siblings = {PurePosixPath(p).name for p in project.all_paths if PurePosixPath(p).parent.as_posix() == folder}
            if siblings & lockfiles:
                continue
            found.append(self.at_line(src, 1, "package.json은 있으나 락 파일(package-lock.json 등)이 없어 설치 때마다 다른 버전이 설치될 수 있습니다.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
        return found + self._lock_files(project) + self._imports(project)

    def _imports(self, project: ProjectContext) -> list[Violation]:
        """코드의 import 이름을 색인과 맞춘다. Python은 모듈→배포 매핑(pypi-modules) 색인, JS·TS는 npm 색인이 완전할 때만 판정한다."""
        index = self._index()
        if index is None:
            return []
        py_modules = index.usable("pypi-modules")
        npm = index.usable("npm")
        local = _local_module_names(project.all_paths)
        found = []
        for src in project.files:
            if src.lang is Lang.PYTHON and py_modules is not None:
                for line, module in _python_imports(src):
                    if module in local or module in sys.stdlib_module_names or py_modules.knows(module) or self._private(module):
                        continue
                    found.append(self.at_line(src, line, f"import 이름 {module}을(를) 제공하는 배포 패키지가 PyPI 모듈 색인(수집 {py_modules.collected_at.isoformat()})에 없습니다. AI가 지어낸 모듈이면 같은 이름의 악성 패키지를 설치하게 될 수 있습니다.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
            elif src.lang in JS_FAMILY and npm is not None:
                for line, package in _js_imports(src):
                    if package in NODE_BUILTINS or npm.knows(package) or self._private(package) or package.split("/", 1)[0] in local:
                        continue
                    found.append(self.at_line(src, line, f"import 이름 {package}이(가) npm 색인(수집 {npm.collected_at.isoformat()})에 없습니다. AI가 지어낸 패키지이면 같은 이름의 악성 패키지를 설치하게 될 수 있습니다.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
        return found
