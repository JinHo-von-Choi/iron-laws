"""
오철칙 운영 기본기 규칙: 웹 서비스를 계속 돌리는 데 필요한 기본 장치가 빠졌는지 본다.

- OPS-101 CI가 시험을 돌리지 않음, OPS-102 DB 구조 변경 기록(마이그레이션) 없음, OPS-103 컨테이너 배포에 상태 확인 없음.
- 웹 라우트가 있는 프로젝트에만 적용한다. CLI 도구·라이브러리에는 지적하지 않는다.
- 파일 존재와 내용만 보고 판정하므로 모두 확인 필요(REVIEW)다. 지적 문구에 판정에 쓴 범위를 적는다.
- 의존성 고정(AI-111), 비밀 설정 분리(AI-101·AI-104), 시험 부재(ARC-206)는 기존 규칙이 본다.
작성자: 최진호
작성일: 2026-11-28
"""

import re
from pathlib import PurePosixPath

import yaml

from iron_laws.core.models import Confidence, IronLaw, RuleLayer, Severity, Violation
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.source import SourceFile
from iron_laws.rules.base import BaseRule

CI_FILE_RE = re.compile(r"^(?:\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|\.circleci/config\.ya?ml|Jenkinsfile|azure-pipelines\.ya?ml|bitbucket-pipelines\.ya?ml|\.drone\.ya?ml)$")
TEST_COMMAND_RE = re.compile(
    r"(?i)\b(?:pytest|tox|nox|python -m unittest|(?:npm|yarn|pnpm|bun)\s+(?:run\s+)?test|jest|vitest|mocha|go test|mvnw?\b.*\b(?:test|verify)|gradlew?\b.*\b(?:test|check|build)|dotnet test|cargo test|phpunit|rspec|deno test|make test)\b"
)
DB_USE_RE = re.compile(
    r"\b(?:sqlalchemy|psycopg2?|pymysql|asyncpg|django\.db|@prisma/client|PrismaClient|typeorm|sequelize|knex|drizzle-orm|mysql2|pg\.Pool|"
    r"javax\.persistence|jakarta\.persistence|org\.springframework\.data\.jpa|gorm\.io|database/sql|DbContext|Illuminate\\\\Database)\b"
)
MIGRATION_DIR_RE = re.compile(r"(?:^|/)(?:migrations|migration|migrate|alembic|Migrations|changelog|liquibase|drizzle)/")
MIGRATION_FILE_NAMES = frozenset({"alembic.ini", "flyway.conf", "knexfile.js", "knexfile.ts", "ormconfig.json", "drizzle.config.ts", "drizzle.config.js"})
HEALTH_PATH_RE = re.compile(r"(?i)/(?:health|healthz|healthcheck|ready|readyz|readiness|live|livez|liveness|ping)/?$")  # 마지막 경로 조각이 상태 확인 이름인 주소
# 상태 확인 근거는 그 근거가 의미 있는 파일에서만 인정한다(예제·문서 YAML에 우연히 든 healthcheck:를 근거로 보지 않는다)
HEALTH_EVIDENCE = (
    (lambda f: f.kind == "docker" or f.path.name.startswith("Dockerfile"), re.compile(r"(?im)^\s*HEALTHCHECK\b")),
    (lambda f: f.kind == "compose" and _built_service_has_healthcheck(f.text), re.compile(r"healthcheck:")),
    (lambda f: f.kind == "yaml" and re.search(r"(?m)^kind:\s*(?:Deployment|StatefulSet|DaemonSet|Pod)\b", f.text) is not None, re.compile(r"\b(?:livenessProbe|readinessProbe):")),
    (lambda f: f.path.name in ("pom.xml", "build.gradle", "build.gradle.kts", "libs.versions.toml"), re.compile(r"spring-boot-starter-actuator")),
)


def _built_service_has_healthcheck(text: str) -> bool:
    """compose에서 이 저장소를 빌드하는 서비스(build 키가 있는 서비스)에 healthcheck가 있다. DB·캐시 같은 다른 서비스의 healthcheck는 앱의 근거가 아니다"""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:  # iron-laws: ignore[IL-301] 읽지 못하는 compose는 상태 확인 근거로 쓰지 않는다
        return False
    services = data.get("services") if isinstance(data, dict) else None
    if not isinstance(services, dict):
        return False
    return any(isinstance(svc, dict) and "build" in svc and "healthcheck" in svc for svc in services.values())


class OpsRule(BaseRule):
    layer = RuleLayer.OPERATIONS
    gov_standard = None
    iron_law = IronLaw.LAW_5
    severity = Severity.LOW

    def check(self, src: SourceFile) -> list[Violation]:
        return []


def _service_anchor(project: ProjectContext) -> tuple[SourceFile, int] | None:
    """웹 서비스이면 지적을 달 위치(첫 라우트). 라우트가 없으면 None이며 운영 규칙을 적용하지 않는다"""
    files = {f.path.as_posix(): f for f in project.files}
    for route in sorted(project.routes(), key=lambda r: (r.file, r.line)):
        if route.file in files:
            return files[route.file], route.line
    return None


def _text(project: ProjectContext, rel: str) -> str:
    """점검 대상 파일이면 읽은 본문을, 아니면(Jenkinsfile 등) 디스크에서 읽는다. 읽지 못하면 빈 글이다"""
    for f in project.files:
        if f.path.as_posix() == rel:
            return f.text
    try:
        return (project.root / rel).read_text(encoding="utf-8", errors="replace") if project.root.is_dir() else ""
    except OSError:  # iron-laws: ignore[IL-301] 읽지 못한 CI 파일은 시험 명령이 없는 것으로 보지 않고 건너뛴다
        return ""


class CiRunsTestsRule(OpsRule):
    rule_id = "OPS-101"
    name = "CI가 시험을 돌리지 않음"
    plain = "코드를 올릴 때마다 시험을 자동으로 돌리는 CI가 없으면, AI가 고친 코드가 기존 기능을 망가뜨려도 배포할 때까지 아무도 모릅니다."
    how_to_fix = "GitHub Actions 같은 CI에 시험 명령(pytest, npm test 등)을 넣어, 커밋·PR마다 돌게 하세요. 시험이 실패하면 병합하지 않게 하세요."

    def check_project(self, project: ProjectContext) -> list[Violation]:
        anchor = _service_anchor(project)
        if anchor is None:
            return []
        ci_files = sorted(p for p in project.all_paths if CI_FILE_RE.match(p))
        if not ci_files:
            return [self.at_line(anchor[0], anchor[1], "CI 설정 파일이 없습니다(.github/workflows, .gitlab-ci.yml 등을 찾았습니다).", confidence=Confidence.REVIEW)]
        if any(TEST_COMMAND_RE.search(_text(project, p)) for p in ci_files):
            return []
        target = next((f for f in project.files if f.path.as_posix() == ci_files[0]), None)
        src, line = (target, 1) if target is not None else anchor
        return [self.at_line(src, line, f"CI 설정({', '.join(ci_files[:3])})에 시험을 돌리는 명령이 보이지 않습니다. 최근 CI 실행이 성공했는지는 확인하지 않았습니다.", confidence=Confidence.REVIEW)]


class MigrationRule(OpsRule):
    rule_id = "OPS-102"
    name = "DB 구조 변경 기록(마이그레이션) 없음"
    severity = Severity.MEDIUM
    plain = "DB 표 구조를 바꾸는 기록(마이그레이션)이 없으면 운영 DB를 손으로 고치게 되고, 그러다 열을 잘못 지우면 데이터가 사라집니다. 다른 환경에 같은 구조를 다시 만들 수도 없습니다."
    how_to_fix = "쓰는 도구에 맞는 마이그레이션을 쓰세요(Alembic, Django migrations, Prisma Migrate, Flyway, Liquibase 등). 표 구조는 마이그레이션 파일로만 바꾸고, 배포할 때 자동으로 적용하세요."

    def check_project(self, project: ProjectContext) -> list[Violation]:
        if _service_anchor(project) is None:
            return []
        use = None
        for f in project.source_files():
            m = DB_USE_RE.search(f.text)
            if m:
                use = (f, f.text.count("\n", 0, m.start()) + 1, m.group(0))
                break
        if use is None:
            return []
        if any(MIGRATION_DIR_RE.search(p) or PurePosixPath(p).name in MIGRATION_FILE_NAMES for p in project.all_paths):
            return []
        src, line, what = use
        return [self.at_line(src, line, f"DB를 쓰는데({what}) 마이그레이션 폴더·설정(migrations/, alembic.ini, prisma/migrations 등)이 없습니다.", confidence=Confidence.REVIEW)]


class HealthCheckRule(OpsRule):
    rule_id = "OPS-103"
    name = "컨테이너 배포에 상태 확인 없음"
    plain = "컨테이너로 배포하는 서비스에 상태 확인 주소나 HEALTHCHECK가 없으면, 앱이 멈춰도 배포 환경이 알아채지 못해 다시 띄우지 않고 요청이 계속 실패합니다."
    how_to_fix = "`/health`처럼 DB 연결까지 확인하는 가벼운 주소를 만들고, Dockerfile의 HEALTHCHECK나 배포 환경의 상태 확인(livenessProbe 등)에 연결하세요."

    def check_project(self, project: ProjectContext) -> list[Violation]:
        anchor = _service_anchor(project)
        if anchor is None:
            return []
        dockerfiles = [f for f in project.files if f.kind == "docker" or f.path.name.startswith("Dockerfile")]
        if not dockerfiles:
            return []
        if any(HEALTH_PATH_RE.search(r.path) for r in project.routes()):
            return []
        if any(applies(f) and pattern.search(f.text) for f in project.files if not f.is_test for applies, pattern in HEALTH_EVIDENCE):
            return []
        target = dockerfiles[0]
        return [self.at_line(target, 1, "컨테이너로 배포하는데 상태 확인 주소(/health 등)와 HEALTHCHECK가 없습니다.", confidence=Confidence.REVIEW)]
