"""
검토자가 자주 지적하는 항목: 업로드 검증, 로그인 제한, 자체 구현 보안 로직, 전역 예외 처리, 버전, 권한 구조
작성자: 최진호
작성일: 2026-10-04
"""

import re
from dataclasses import dataclass

from iron_laws.core.models import Confidence, IronLaw, RuleLayer, Severity, Violation
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.source import SourceFile
from iron_laws.rules.base import BaseRule
from iron_laws.standards import mois_ref


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _all_text(project: ProjectContext) -> str:
    return "\n".join(f.code_text for f in project.source_files(include_tests=True))


class UploadVerificationRule(BaseRule):
    rule_id = "IL-530"
    name = "업로드 파일 검증 체계 미흡 (콘텐츠 판정·확장자 허용 목록)"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    gov_standard = mois_ref("1-6")
    plain = "업로드 파일의 종류를 사용자가 보낸 Content-Type이나 확장자로만 판단하면, 실행 파일이나 스크립트를 이미지로 위장해 올릴 수 있습니다."
    how_to_fix = (
        "서버에서 파일 내용의 시그니처(매직 바이트)로 실제 형식을 판정하고(Tika, python-magic, file-type 등), "
        "허용 확장자 목록과 판정 결과의 일치를 검사하며, 어긋나면 400으로 거절하고 경고 로그를 남기세요. "
        "저장 파일명은 UUID로 바꾸고 원본 이름과 SHA-256 해시는 DB에 보관하세요."
    )
    upload_marker = re.compile(
        r"MultipartFile|request\.files|req\.files?\b|IFormFile|\$_FILES|\bmulter\b|UploadFile|FormFile|HttpPostedFile|FileUpload"
    )
    save_marker = re.compile(
        r"\.save\(|transferTo\(|writeFile(Sync)?\(|createWriteStream|move_uploaded_file|CopyTo(Async)?\(|SaveAs\(|os\.Create\(|Files\.(copy|write)|\.mv\("
    )
    client_type = re.compile(r"getContentType\(\)|\.content_type\b|\.mimetype\b|\.ContentType\b|\bfile\.type\b|\.Header\.Get\(\s*\"Content-Type\"")
    magic_libs = re.compile(
        r"(?i)\bTika\b|jmimemagic|python-?magic|\bimport\s+magic\b|\bfiletype\b|\bimghdr\b|file-type|libmagic|DetectContentType|MimeDetective|FileSignatures|FileTypeChecker|sniff"
    )
    ext_allow = re.compile(
        r"(?i)allowed_?(ext|types|mime)|whitelist|allowlist|\bALLOWED\b|endsWith\(|splitext|getExtension|GetExtension|extname|FilenameUtils|\.suffix\b|mimetypes|fileFilter|accept\b"
    )

    def check_project(self, project: ProjectContext) -> list[Violation]:
        magic_present = bool(self.magic_libs.search(_all_text(project)))
        found: list[Violation] = []
        for src in project.source_files():
            text = src.code_text
            if not self.upload_marker.search(text) or not self.save_marker.search(text):
                continue
            first = self.upload_marker.search(text)
            marker_line = _line_of(text, first.start()) if first else 1
            for idx, line in enumerate(src.code_lines, start=1):
                if self.client_type.search(line) and not magic_present:
                    found.append(
                        self.at_line(
                            src,
                            idx,
                            "클라이언트가 보낸 Content-Type(또는 확장자)에 의존해 업로드 파일을 판정합니다. 서버에서 파일 내용(매직 바이트)으로 실제 형식을 판정하십시오.",
                            confidence=Confidence.REVIEW,
                        )
                    )
                    break
            if not self.ext_allow.search(text):
                found.append(
                    self.at_line(
                        src,
                        marker_line,
                        "업로드 파일의 허용 확장자 목록(화이트리스트) 검증이 보이지 않습니다.",
                        severity=Severity.LOW,
                        confidence=Confidence.REVIEW,
                    )
                )
        return found


LOGIN_PATTERNS = [
    re.compile(r"(?m)^\s*(?:async\s+)?def\s+(login|signin|sign_in|authenticate_user|issue_token|create_token)\w*\s*\("),
    re.compile(r"""\.post\(\s*['"][^'"]*(login|signin|sign-in|auth/token)[^'"]*['"]"""),
    re.compile(r"""@PostMapping\(\s*(?:value\s*=\s*)?\{?\s*["'][^"']*(login|signin|sign-in)[^"']*["']"""),
    re.compile(r"(?m)^\s*(?:public|private|protected)\s+[\w<>\[\], ?]+\s+(login|signin|signIn)\w*\s*\("),
    re.compile(r"""Route::post\(\s*['"][^'"]*login"""),
    re.compile(r"""(?:HandleFunc|POST|Post)\(\s*"[^"]*(login|signin)[^"]*\""""),
    re.compile(r"\[HttpPost[^\]]*\][^{;]*\b(Login|SignIn)\w*\s*\("),
    re.compile(r"""\$_(?:POST|GET|REQUEST)\[\s*['"](?:password|passwd|pass)['"]\s*\]"""),
]
LIMIT_MARKERS = re.compile(
    r"(?i)rate_?limit|ratelimit|RateLimiter|throttl|slowapi|bucket4j|resilience4j|lockout|LockoutOnFailure|failed_?(login_?)?(attempts?|count)|"
    r"login_?attempts?|max_?(login_?)?attempts?|too ?many ?(requests|attempts)|\b429\b|TooManyRequests|account_?lock|isLocked|login_?fail|brute|captcha|express-brute"
)


class LoginRateLimitRule(BaseRule):
    rule_id = "IL-532"
    name = "로그인 시도 제한(무차별 대입 방어) 부재"
    iron_law = IronLaw.LAW_1
    severity = Severity.MEDIUM
    gov_standard = mois_ref("2-16")
    plain = "로그인 시도 횟수를 제한하지 않으면 공격자가 비밀번호를 자동으로 수만 번 대입해 계정을 뚫을 수 있습니다."
    how_to_fix = "계정과 IP를 함께 기준으로 실패 횟수를 세어 일정 횟수를 넘으면 잠시 잠그거나 지연시키고(429), 실패 이력을 로그로 남기세요. 계정 단위만 제한하면 남의 계정을 일부러 잠가 버리는 공격에 쓰이므로 IP 기준과 함께 쓰세요."

    def check_project(self, project: ProjectContext) -> list[Violation]:
        if LIMIT_MARKERS.search(_all_text(project)):
            return []
        for src in project.source_files():
            text = src.code_text
            for pattern in LOGIN_PATTERNS:
                m = pattern.search(text)
                if m:
                    return [
                        self.at_line(
                            src,
                            _line_of(text, m.start()),
                            "로그인 처리 코드가 있으나 프로젝트 어디에서도 시도 횟수 제한·잠금·레이트 리밋이 보이지 않습니다.",
                            confidence=Confidence.REVIEW,
                        )
                    ]
        return []


class AiRule(BaseRule):
    layer = RuleLayer.AI_CODE
    gov_standard = None


class CustomTokenRule(AiRule):
    rule_id = "AI-118"
    name = "자체 구현한 토큰·세션 처리 로직 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    plain = "HMAC과 문자열 분리(split)로 직접 만든 토큰은 구분자가 값에 섞이면 위조되거나 잘못 해석될 수 있고, 만료 전에 강제로 무효화하기도 어렵습니다. 검증된 라이브러리가 이미 이 문제들을 처리합니다."
    how_to_fix = "JWT 등 검증된 라이브러리(Java: JJWT·Nimbus, Python: PyJWT, Node: jsonwebtoken·jose, C#: System.IdentityModel.Tokens.Jwt)로 바꾸고, 만료 전 폐기를 위한 토큰 식별자(jti)와 거부 목록 또는 서버 세션 저장소를 두세요."
    hmac_marker = re.compile(r"Mac\.getInstance\(\s*\"Hmac|hmac\.(new|compare_digest)\(|createHmac\(|HMACSHA\d+|hmac\.New\(|hash_hmac\(")
    split_marker = re.compile(r"""\.split\(\s*(?:["'](?:\\\\)?[|.:;,]["']|Pattern\.quote\([^)]*\)|["']\\\\\|["'])|explode\(\s*['"][|.:;,]""")
    jwt_libs = re.compile(
        r"io\.jsonwebtoken|com\.auth0\.jwt|nimbusds|import\s+jwt\b|from\s+jwt\b|jsonwebtoken|\bjose\b|System\.IdentityModel\.Tokens|golang-jwt|firebase/php-jwt|jwt\.Parse|JwtSecurityToken"
    )
    revoke = re.compile(r"(?i)revoke|blacklist|denylist|blocklist|\bjti\b|invalidate|session_?store|logout")

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang is None or src.is_test:
            return []
        text = src.code_text
        hmac = self.hmac_marker.search(text)
        if not hmac or not self.split_marker.search(text) or self.jwt_libs.search(text):
            return []
        if not re.search(r"(?i)token|session|auth|sign|cookie", src.path.name + text[:2000]):
            return []
        extra = "" if self.revoke.search(text) else " 만료 전에 강제로 무효화하는 수단(폐기 목록·세션 저장소)도 보이지 않습니다."
        return [
            self.at_line(
                src,
                _line_of(text, hmac.start()),
                "HMAC과 문자열 분리(split)로 토큰을 직접 구현했습니다. 값에 구분자가 포함될 때의 처리와 검증 로직을 확인하고 JWT 같은 검증된 라이브러리 전환을 검토하십시오." + extra,
                confidence=Confidence.REVIEW,
            )
        ]


class FrameworkGuardRule(AiRule):
    rule_id = "AI-119"
    name = "프레임워크 보안 기능 없이 자체 보안 필터 사용 (Spring Security 미사용)"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    plain = "웹 프레임워크가 제공하는 보안 기능(CSRF, CORS, 세션 고정 방어, 보안 헤더)을 쓰지 않고 직접 필터로 만들면, 빠뜨린 방어가 있어도 아무도 모릅니다."
    how_to_fix = "Spring Security를 도입해 인증·인가·CSRF·CORS를 프레임워크 설정으로 처리하세요. 쓰지 않을 사유가 있다면 직접 만든 필터가 CSRF, CORS, 세션 고정, 보안 헤더를 모두 막는다는 검증 결과를 남기세요."
    custom_filter = re.compile(r"OncePerRequestFilter|implements\s+(?:javax\.servlet\.|jakarta\.servlet\.)?Filter\b|HandlerInterceptor")

    def check_project(self, project: ProjectContext) -> list[Violation]:
        build = [f for f in project.files if f.kind in ("xml", "gradle") and f.path.name in ("pom.xml", "build.gradle", "build.gradle.kts")]
        if not build:
            return []
        build_text = "\n".join(f.text for f in build)
        if "spring-boot-starter-web" not in build_text or re.search(r"spring-boot-starter-security|spring-security", build_text):
            return []
        if not self.custom_filter.search(_all_text(project)):
            return []
        target = next(f for f in build if "spring-boot-starter-web" in f.text)
        idx = target.text.index("spring-boot-starter-web")
        return [
            self.at_line(
                target,
                _line_of(target.text, idx),
                "Spring Boot 웹 프로젝트에 Spring Security 의존성이 없고 자체 필터·인터셉터로 요청을 처리합니다. 프레임워크 보안 기능을 쓰지 않은 사유와 대체 검증이 필요합니다.",
                confidence=Confidence.REVIEW,
            )
        ]


class GlobalExceptionHandlerRule(AiRule):
    rule_id = "AI-120"
    name = "전역 예외 처리기·일관된 오류 응답 형식 부재"
    iron_law = IronLaw.LAW_3
    severity = Severity.LOW
    plain = "오류 처리가 요청 처리기마다 제각각이면 오류 응답의 형식이 달라 화면이 깨지고, 내부 정보가 그대로 새어 나가는 곳이 생깁니다."
    how_to_fix = "전역 예외 처리기를 한 곳에 두고 모든 오류를 같은 응답 형식(코드, 메시지, 추적 ID)으로 돌려주세요. Spring: @RestControllerAdvice / Express: 4인자 오류 미들웨어 / FastAPI: exception_handler / ASP.NET: UseExceptionHandler"

    def check_project(self, project: ProjectContext) -> list[Violation]:
        text = _all_text(project)
        found: list[Violation] = []
        spring = [f for f in project.source_files() if f.lang is Lang.JAVA and re.search(r"@(Rest)?Controller\b", f.code_text)]
        if len(spring) >= 3 and not re.search(r"@(Rest)?ControllerAdvice|HandlerExceptionResolver|implements\s+ErrorController|@ExceptionHandler", text):
            found.append(self._at(spring[0], "Spring 컨트롤러 " + str(len(spring)) + "개가 있으나 @RestControllerAdvice 같은 전역 예외 처리기가 보이지 않습니다."))
        dotnet = [f for f in project.source_files() if f.lang is Lang.CSHARP and re.search(r":\s*(Controller|ControllerBase)\b|\[ApiController\]", f.code_text)]
        if len(dotnet) >= 3 and not re.search(r"UseExceptionHandler|IExceptionFilter|ExceptionFilterAttribute|AddProblemDetails|IExceptionHandler", text):
            found.append(self._at(dotnet[0], "ASP.NET 컨트롤러 " + str(len(dotnet)) + "개가 있으나 전역 예외 처리(UseExceptionHandler, 예외 필터)가 보이지 않습니다."))
        for src in project.source_files():
            if src.lang in JS_FAMILY and re.search(r"require\(['\"]express['\"]\)|from\s+['\"]express['\"]", src.code_text):
                routes = len(re.findall(r"\b(?:app|router)\.(?:get|post|put|patch|delete)\(", text))
                if routes >= 5 and not re.search(r"\(\s*err\w*\s*,\s*req\w*\s*,\s*res\w*\s*,\s*next\w*\s*\)", text):
                    found.append(self._at(src, "Express 라우트 " + str(routes) + "개가 있으나 4인자 오류 처리 미들웨어가 보이지 않습니다."))
                break
        for src in project.source_files():
            if src.lang is Lang.PYTHON and re.search(r"\bFastAPI\(", src.code_text):
                if len(re.findall(r"@\w+\.(?:get|post|put|patch|delete)\(", text)) >= 5 and not re.search(r"exception_handler|add_exception_handler", text):
                    found.append(self._at(src, "FastAPI 라우트가 여러 개이나 exception_handler가 보이지 않습니다."))
                break
        for src in project.source_files():
            if src.lang is Lang.PYTHON and re.search(r"\bFlask\(", src.code_text):
                if len(re.findall(r"@\w+\.route\(", text)) >= 5 and not re.search(r"errorhandler|register_error_handler", text):
                    found.append(self._at(src, "Flask 라우트가 여러 개이나 errorhandler가 보이지 않습니다."))
                break
        return found

    def _at(self, src: SourceFile, message: str) -> Violation:
        return self.at_line(src, 1, message, confidence=Confidence.REVIEW)


ADMIN_ROLES = {"admin", "administrator", "root", "superadmin", "superuser", "sysadmin"}
ROLE_PATTERNS = [
    re.compile(r"""hasRole\(\s*['"](?:ROLE_)?(\w+)['"]"""),
    re.compile(r"""hasAnyRole\(([^)]*)\)"""),
    re.compile(r"""@Secured\(\s*\{?\s*['"](?:ROLE_)?(\w+)"""),
    re.compile(r"""@RolesAllowed\(\s*\{?\s*['"](\w+)"""),
    re.compile(r"""\[Authorize\([^)]*Roles\s*=\s*"([^"]+)\""""),
    re.compile(r"""\brole\w*\s*(?:===?|==)\s*['"](\w+)['"]"""),
    re.compile(r"""has_role\(\s*['"](\w+)['"]"""),
    re.compile(r"""roles?_required\(\s*['"](\w+)['"]"""),
    re.compile(r"""require(?:Role|Roles)\(\s*['"](\w+)['"]"""),
    re.compile(r"""roles?\.includes\(\s*['"](\w+)['"]"""),
]


class SingleAdminRoleRule(AiRule):
    rule_id = "AI-122"
    name = "관리자 권한이 단일 역할로만 구성됨 (권한 세분화 부재)"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    plain = "관리자 권한이 하나뿐이면 모든 직원이 모든 정보를 보고 바꿀 수 있고, 누가 무엇을 했는지 책임을 가리기 어렵습니다. 운영 점검이나 감사에서 가장 먼저 지적되는 구조입니다."
    how_to_fix = "기능·직급·메뉴별로 역할을 나누고 읽기, 쓰기, 개인정보 마스킹 해제, 승인 같은 권한을 따로 부여하세요. 최고 관리자(root) 계정은 최소 인원으로 제한하고 권한 변경 이력을 남기세요."

    def check_project(self, project: ProjectContext) -> list[Violation]:
        roles: list[str] = []
        first: tuple[SourceFile, int] | None = None
        for src in project.source_files():
            text = src.code_text
            for pattern in ROLE_PATTERNS:
                for m in pattern.finditer(text):
                    names = re.findall(r"""['"]?(?:ROLE_)?(\w+)['"]?""", m.group(1))
                    names = [n for n in names if n and not n.isdigit()] or [m.group(1)]
                    roles.extend(n.lower() for n in names)
                    if first is None:
                        first = (src, _line_of(text, m.start()))
        guarded = [r for r in roles if r in ADMIN_ROLES or r not in ("user", "member")]
        if first is None or len(guarded) < 3 or not all(r in ADMIN_ROLES for r in guarded):
            return []
        return [
            self.at_line(
                first[0],
                first[1],
                f"권한 검사에 관리자 단일 역할({sorted(set(guarded))[0]})만 {len(guarded)}곳에서 쓰입니다. 업무·직급·기능별 권한 분리가 보이지 않습니다.",
                confidence=Confidence.REVIEW,
            )
        ]


@dataclass
class RuntimeUse:
    version: tuple[int, ...]
    src: SourceFile
    line: int
    label: str


CHANGELOG_DOC_RE = re.compile(r"(?i)(change|release|history|news|migration|upgrade|todo|roadmap)")


def _vt(value: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", value)[:3])


def _java_major(raw: str) -> int:
    raw = raw.strip()
    if raw.startswith("1."):
        return int(raw.split(".")[1])
    return int(re.match(r"\d+", raw).group(0))


class VersionRule(AiRule):
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
            found.extend(self._eol(runtime, uses))
        found.extend(self._spring_boot(project, policies))
        found.extend(self._dependencies(project, policies))
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
                if not m or "$" in line:
                    continue
                groups = [g for g in m.groups() if g]
                for raw in groups:
                    try:
                        value = (_java_major(raw.replace("_", ".")),) if runtime == "Java" else _vt(raw)
                    except (ValueError, AttributeError):  # iron-laws: ignore[IL-301] 숫자가 아닌 표기는 버전으로 보지 않는다
                        continue
                    if value and not (runtime == "Java" and value[0] < 6):
                        uses.append(RuntimeUse(value, src, idx, f"{src.path.as_posix()}:{idx}"))
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
        non_doc = [u for u in uses if self._kind_of(u.src) != "doc"]
        docs = [u for u in uses if self._kind_of(u.src) == "doc"]
        versions = {u.version for u in non_doc} | {u.version for u in docs}
        if len(versions) <= 1:
            return []
        if not non_doc and len({u.version for u in docs}) <= 1:
            return []
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
            elif _vt(version)[:1] and _vt(version)[0] <= 2:
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
            for name, minimum in named.items():
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


REVIEW_RULES: list[type[BaseRule]] = [
    UploadVerificationRule,
    LoginRateLimitRule,
    CustomTokenRule,
    FrameworkGuardRule,
    GlobalExceptionHandlerRule,
    SingleAdminRoleRule,
    VersionRule,
]
