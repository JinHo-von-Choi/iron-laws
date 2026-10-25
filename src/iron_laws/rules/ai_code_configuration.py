"""ai_code configuration 규칙."""


import fnmatch
import re
import sys
import tomllib
from pathlib import Path, PurePosixPath

from tree_sitter import Node

from iron_laws.core.masking import QUOTED_RE
from iron_laws.core.models import Confidence, IronLaw, Severity, Violation
from iron_laws.core.paths import TEST_DIR_NAMES
from iron_laws.deps.lockfiles import PARSERS as LOCK_PARSERS
from iron_laws.deps.lockfiles import parse_lock
from iron_laws.deps.package_index import PackageIndexError, load_index, normalize
from iron_laws.engine.ast_tools import (
    is_literal,
    is_string_node,
    iter_calls,
    string_value,
)
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.source import SourceFile
from iron_laws.rules.ai_code_common import (
    CODE_KINDS,
    MAX_PER_FILE,
    POPULAR_NPM,
    POPULAR_PY,
    AiRule,
    _levenshtein,
    _load_json_object,
)
from iron_laws.rules.secrets_crypto import SECRET_NAME, LineRegexRule

OPENVEX_NAMESPACE = "https://openvex.dev/ns/"


class HardcodedConfigRule(AiRule):
    version = 3
    rule_id = "AI-101"
    sensitive_snippet = True
    name = "하드코딩된 설정값(URL·IP·경로·포트) 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.MEDIUM
    plain = "주소·IP·내 컴퓨터 경로를 코드에 박아 두면 내 PC에서만 돌아가고, 배포하거나 환경이 바뀔 때마다 코드를 고쳐야 합니다. AI는 우선 돌아가게 하려고 이렇게 쓰는 경우가 많습니다."
    how_to_fix = "환경별로 달라지는 값(API 주소, DB 호스트, 포트, 파일 경로)은 환경변수나 설정 파일로 빼서 읽으세요. 예: BASE_URL = os.environ['API_BASE_URL'] / process.env.API_BASE_URL"
    url_re = re.compile(r"^(?P<scheme>https?|wss?|jdbc:\w+|mongodb|postgres(?:ql)?|mysql|redis|amqp)://(?P<host>[^/:\s?#@]+)")
    ip_re = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$")
    path_re = re.compile(r"^(?:/(?:home|Users)/[\w.\-]+|[A-Za-z]:\\\\?(?:Users|Documents|Projects|dev)\b)")
    doc_hosts = re.compile(
        r"(?i)(^|\.)(w3\.org|schemastore\.org|github\.com|githubusercontent\.com|npmjs\.(com|org)|pypi\.org|wikipedia\.org|stackoverflow\.com|mozilla\.org|"
        r"apache\.org|json-schema\.org|schema\.org|xmlsoap\.org|springframework\.org|example\.(com|org|net)|sun\.com|oracle\.com|microsoft\.com|"
        r"googleapis\.com|gstatic\.com|fonts\.googleapis\.com|cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|creativecommons\.org|ietf\.org|rfc-editor\.org|docs\.\w+\.\w+|readthedocs\.io|medium\.com|youtube\.com|youtu\.be)$"
    )
    # 고칠 대상을 알려 주려고 주소는 보여 주되, 계정 정보·비밀 이름의 질의 값·토큰처럼 긴 조각이 있는 주소는 가린다
    url_secret_re = re.compile(r"(?i)://[^/\s\"'`@]*@|[?&;#][\w.\-]*(?:pass|pwd|secret|token|key|auth|sig)[\w.\-]*=|[A-Za-z0-9_\-+=]{20,}")
    env_default_re = re.compile(r"process\.env|os\.environ|getenv|os\.Getenv|Environment\.GetEnvironmentVariable|System\.getenv|\$\{\w+:-")
    skip_context_re = re.compile(r"(?i)^(print|println|printf|console\.\w+|logger?\.\w+|logging\.\w+|log\.\w+|warn|warnings\.warn|raise|throw|Error|new\w*Exception|Exception|panic|fmt\.Print\w*|System\.out\.\w+|Console\.\w+|echo|error_log|import|require)")

    def check(self, src: SourceFile) -> list[Violation]:
        if src.kind not in CODE_KINDS or src.lang is None or src.root is None or src.is_test:
            return []
        found: list[Violation] = []
        for node in src.nodes:
            if len(found) >= MAX_PER_FILE:
                break
            if not is_string_node(node) or not is_literal(node):
                continue
            if node.parent is not None and is_string_node(node.parent):
                continue
            value = string_value(src, node)
            if not value or " " in value.strip() or "\n" in value or len(value) > 300:
                continue
            if self._in_skipped_call(src, node):
                continue
            if self.env_default_re.search(src.snippet_at(src.line_of(node))):
                continue
            v = self._classify(src, node, value)
            if v is not None:
                found.append(v)
        found.extend(self._ports(src))
        return found[:MAX_PER_FILE]

    def _in_skipped_call(self, src: SourceFile, node: Node) -> bool:
        parent = node.parent
        depth = 0
        while parent is not None and depth < 4:
            if parent.type in ("call", "call_expression", "method_invocation", "invocation_expression", "new_expression", "object_creation_expression", "raise_statement", "throw_statement", "import_statement", "import_from_statement", "import_declaration", "using_directive", "use_declaration", "echo_statement"):
                head = re.sub(r"\s+", "", src.text_of(parent))[:60]
                if self.skip_context_re.match(head) or parent.type in ("raise_statement", "throw_statement", "import_statement", "import_from_statement", "import_declaration", "using_directive", "use_declaration"):
                    return True
            parent = parent.parent
            depth += 1
        return False

    def _classify(self, src: SourceFile, node: Node, value: str) -> Violation | None:
        m = self.url_re.match(value)
        if m:
            host = m.group("host")
            # OSV 공개 조회 프로토콜은 환경별 배포 설정이 아니다. 경로까지 한정한다.
            public_protocol = value in ("https://api.osv.dev/v1/query", "https://api.osv.dev/v1/querybatch") or self._openvex_namespace(value)
            if public_protocol or self.doc_hosts.search(host) or host.startswith(("$", "{", "<")):
                return None
            local = bool(re.match(r"(?i)(localhost|127\.|0\.0\.0\.0|\[::1\]|host\.docker\.internal)", host))
            return self.at_node(
                src,
                node,
                f"URL {self._display_url(value)[:80]}이(가) 코드에 고정되어 있습니다. " + ("개발용 주소는 배포 환경에서 동작하지 않습니다." if local else "환경별로 바뀌는 주소는 설정으로 분리하십시오."),
                severity=Severity.MEDIUM if not local else Severity.LOW,
                confidence=Confidence.REVIEW,
            )
        if self.ip_re.match(value):
            ip = value.split(":")[0]
            if ip in ("0.0.0.0", "127.0.0.1", "255.255.255.255") or ip.startswith(("127.", "0.")):
                return None
            private = bool(re.match(r"(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)", ip))
            return self.at_node(
                src,
                node,
                f"IP 주소 {value}이(가) 코드에 고정되어 있습니다." + (" 내부망 IP는 누출금지 대상정보 제1호(정보시스템 내·외부 IP 현황)에 해당할 수 있습니다." if private else ""),
                confidence=Confidence.REVIEW,
            )
        if self.path_re.match(value):
            return self.at_node(src, node, f"개인 PC의 절대 경로 {value[:60]}이(가) 코드에 고정되어 있습니다.", severity=Severity.HIGH, confidence=Confidence.CONFIRMED)
        return None

    def public_values(self, line: str) -> set[str]:
        return {m.group("body") for m in QUOTED_RE.finditer(line) if self.url_re.match(m.group("body")) and not self.url_secret_re.search(m.group("body"))}

    @staticmethod
    def _openvex_namespace(value: str) -> bool:
        """OpenVEX 문서의 @context는 판본이 붙은 어휘 이름 공간이다(예: …/ns/v0.2.0)."""
        if value == OPENVEX_NAMESPACE:
            return True
        return value.startswith(OPENVEX_NAMESPACE) and re.fullmatch(r"v\d+(?:\.\d+)*", value[len(OPENVEX_NAMESPACE) :]) is not None

    @staticmethod
    def _display_url(value: str) -> str:
        """계정 정보와 질의·조각을 뺀 주소"""
        return re.split(r"[?#]", re.sub(r"(?<=://)[^/\s@]*@", "", value), maxsplit=1)[0]

    def _ports(self, src: SourceFile) -> list[Violation]:
        found = []
        for call in iter_calls(src):
            if re.search(r"(^|\.)(listen|run|serve)$", call.callee) and src.lang is not None:
                text = src.text_of(call.node)
                if re.search(r"\bport\s*=\s*[1-9]\d{3,4}\b" if src.lang is Lang.PYTHON else r"(?<![\w.])[1-9]\d{3,4}\b", text) and not re.search(r"environ|getenv|process\.env|config|settings|PORT", text):
                    if call.callee in ("app.listen", "server.listen", "app.run", "http.listen", "httpServer.listen") or src.lang in (Lang.PYTHON,) and call.callee.endswith(".run"):
                        found.append(self.at_node(src, call.node, "서버 포트가 코드에 고정되어 있습니다. 환경변수 PORT로 받으십시오.", severity=Severity.LOW, confidence=Confidence.REVIEW))
        return found


class SecretDefaultFallbackRule(AiRule):
    rule_id = "AI-102"
    sensitive_snippet = True
    name = "비밀 값의 기본값 폴백 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.HIGH
    plain = "환경변수가 없을 때 '기본 비밀번호/키'로 조용히 동작하게 만들면, 설정을 빼먹은 채 배포돼도 알아채지 못하고 공개된 기본 비밀로 운영됩니다."
    how_to_fix = "비밀 값에는 기본값을 두지 말고, 없으면 시작 단계에서 오류를 내어 실행을 멈추세요. 예: SECRET = os.environ['SECRET_KEY'] (KeyError로 즉시 실패)"
    name_re = re.compile(rf"(?i){SECRET_NAME}")
    patterns = [
        re.compile(r"""(?:os\.environ\.get|os\.getenv|environ\.get|config|env|getenv|env\.str|env\.get)\(\s*['"](?P<n>[A-Za-z0-9_]+)['"]\s*,\s*(?:default\s*=\s*)?(?P<q>['"])(?P<v>[^'"]+)(?P=q)"""),
        re.compile(r"""process\.env(?:\.(?P<n1>\w+)|\[\s*['"](?P<n2>\w+)['"]\s*\])\s*(?:\|\||\?\?)\s*(?P<q>['"`])(?P<v>[^'"`]+)(?P=q)"""),
        re.compile(r"""import\.meta\.env\.(?P<n>\w+)\s*(?:\|\||\?\?)\s*(?P<q>['"`])(?P<v>[^'"`]+)(?P=q)"""),
        re.compile(r"""(?:getOrDefault|getProperty|GetValue(?:<\w+>)?)\(\s*"(?P<n>[A-Za-z0-9_.]+)"\s*,\s*"(?P<v>[^"]+)"\s*\)"""),
        re.compile(r"""@Value\(\s*"\$\{(?P<n>[^:}]+):(?P<v>[^}]+)\}"\s*\)"""),
        re.compile(r"""(?:GetEnvironmentVariable\(\s*"(?P<n1>\w+)"\s*\)|Configuration\[\s*"(?P<n2>[\w:.]+)"\s*\])\s*\?\?\s*"(?P<v>[^"]+)\""""),
        re.compile(r"""\b\w*[Gg]et[Ee]nv\w*\(\s*"(?P<n>\w+)"\s*,\s*"(?P<v>[^"]+)"\s*\)|SetDefault\(\s*"(?P<n2>[\w.]+)"\s*,\s*"(?P<v2>[^"]+)"\s*\)"""),
        re.compile(r"""getenv\(\s*['"](?P<n>\w+)['"]\s*\)\s*\?:\s*['"](?P<v>[^'"]+)['"]|\benv\(\s*['"](?P<n2>\w+)['"]\s*,\s*['"](?P<v2>[^'"]+)['"]"""),
        re.compile(r"""env::var\(\s*"(?P<n>\w+)"\s*\)\s*\.unwrap_or(?:_else)?\(\s*(?:\|\|\s*)?(?:"|String::from\(")(?P<v>[^"]+)"""),
        re.compile(r"""\$\{(?P<n>[A-Za-z0-9_]+):-(?P<v>[^}]+)\}"""),
    ]

    def check(self, src: SourceFile) -> list[Violation]:
        if src.kind in ("xml", "json", "text", "sql", "rules") or src.is_test:
            return []
        found = []
        for idx, line in enumerate(src.code_lines, start=1):
            for pattern in self.patterns:
                m = pattern.search(line)
                if not m:
                    continue
                groups = m.groupdict()
                name = next((groups[k] for k in ("n", "n1", "n2") if groups.get(k)), "")
                value = next((groups[k] for k in ("v", "v2") if groups.get(k)), "")
                if not name or not value or not self.name_re.search(name) or "${" in value:
                    continue
                if re.fullmatch(r"(?i)(your[-_ ].*|<.*>|x{3,}|placeholder|change.?me|todo|none|null|empty|replace.?me)", value.strip()):
                    continue
                found.append(self.at_line(src, idx, f"환경변수 {name}에 기본값('{value[:20]}')이 있어 설정이 빠져도 공개된 기본 비밀로 조용히 동작합니다."))
                break
        return found


class FrontendSecretRule(LineRegexRule, AiRule):
    rule_id = "AI-103"
    sensitive_snippet = True
    name = "프론트엔드에 노출되는 비밀 환경변수 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.HIGH
    plain = "NEXT_PUBLIC_, VITE_ 같은 접두사가 붙은 환경변수는 브라우저로 내려가는 파일에 그대로 들어갑니다. 여기에 비밀 키를 넣으면 누구나 개발자 도구에서 볼 수 있습니다."
    how_to_fix = "비밀 키는 서버(API 라우트, 서버 함수)에서만 쓰고 접두사 없는 환경변수로 두세요. 브라우저에서 필요한 호출은 서버를 거쳐 프록시하세요."
    kinds = {"code", "env", "yaml", "json", "compose", "docker", "actions", "shell", "properties"}
    public_prefix = r"(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY|VUE_APP|STORYBOOK|PUBLIC)"
    patterns = [
        (
            re.compile(rf"\b{public_prefix}_[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|OPENAI|ANTHROPIC|STRIPE_SECRET|SENDGRID|TWILIO|AWS_SECRET|DATABASE_URL|DB_PASS|JWT|ADMIN|MONGO|REPLICATE|GROQ|OPENROUTER|GEMINI|CLAUDE)[A-Z0-9_]*\b"),
            "브라우저에 노출되는 접두사가 붙은 환경변수에 비밀 값으로 보이는 이름이 쓰였습니다.",
            Severity.HIGH,
        ),
        (
            re.compile(rf"\b{public_prefix}_[A-Z0-9_]*(?:API_KEY|APIKEY|ACCESS_KEY|TOKEN)\b"),
            "브라우저에 노출되는 환경변수에 API 키/토큰이 쓰였습니다. 공개용 키인지 확인하십시오.",
            Severity.MEDIUM,
        ),
        (re.compile(r"(?i)service_role"), "service_role 키는 모든 보안 규칙(RLS)을 우회합니다. 브라우저 코드에서 쓰면 안 됩니다.", Severity.CRITICAL),
    ]

    def check(self, src: SourceFile) -> list[Violation]:
        if src.is_test:
            return []
        found = []
        client_hint = bool(re.search(r"""['"]use client['"]""", src.text)) or bool(re.search(r"(^|/)(src|app|pages|components|public|client|frontend|web)/", src.path.as_posix()))
        for idx, line in enumerate(src.code_lines, start=1):
            if src.kind not in self.kinds:
                break
            for pattern, message, severity in self.patterns:
                if not pattern.search(line):
                    continue
                if "service_role" in pattern.pattern and not (client_hint and src.lang in JS_FAMILY):
                    continue
                if severity is Severity.MEDIUM and re.search(r"(?i)FIREBASE|MAPS|RECAPTCHA|SITE_KEY|PUBLISHABLE|ANON|ALGOLIA_SEARCH|SENTRY|POSTHOG|MIXPANEL|CLIENT_ID|SEGMENT", line):
                    continue
                found.append(self.at_line(src, idx, message, severity=severity))
                break
        return found


class CorsRule(AiRule):
    rule_id = "AI-105"
    name = "모든 출처를 허용하는 CORS 설정 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.MEDIUM
    plain = "CORS를 '*'(모두 허용)로 열어 두면 어떤 웹사이트든 내 API를 호출할 수 있고, 쿠키 인증과 함께 쓰면 사용자 대신 요청을 보내는 공격이 가능합니다. AI는 CORS 오류를 없애려고 흔히 이렇게 설정합니다."
    how_to_fix = "허용할 출처를 정확한 주소 목록으로 지정하세요. 예: origin: ['https://app.example.com'] / allow_origins=['https://app.example.com']. credentials와 '*'는 함께 쓰지 마세요."
    patterns = [
        re.compile(r"""Access-Control-Allow-Origin['"]?\s*[,:=]\s*['"]?\*"""),
        re.compile(r"""\bcors\(\s*\)"""),
        re.compile(r"""origin\s*:\s*(?:['"]\*['"]|true)\b"""),
        re.compile(r"""allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]|allow_origin_regex\s*=\s*['"]\.\*['"]"""),
        re.compile(r"""CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CORS_ORIGIN_ALLOW_ALL\s*=\s*True"""),
        re.compile(r"""(?<![\w.])CORS\(\s*app\s*\)"""),
        re.compile(r"""@CrossOrigin\s*(?:\(\s*(?:origins\s*=\s*)?["']\*["']\s*\))?\s*$|@CrossOrigin\(\s*(?:origins\s*=\s*)?["']\*["']"""),
        re.compile(r"""(?:setAllowedOrigins|addAllowedOrigin|allowedOrigins|allowedOriginPatterns|addAllowedOriginPattern)\([^)]*["']\*["']"""),
        re.compile(r"""AllowAnyOrigin\(\)|SetIsOriginAllowed\([^)]*=>\s*true"""),
        re.compile(r"""AllowAllOrigins\s*:\s*true|AllowedOrigins\s*:\s*\[\]string\{\s*"\*"\s*\}"""),
    ]
    credentials = re.compile(r"(?i)credentials\s*[:=(]\s*(true|True)|AllowCredentials|supports_credentials\s*=\s*True|allowCredentials")

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang is None and src.kind not in ("properties", "yaml"):
            return []
        found = []
        lines = src.code_lines
        for idx, line in enumerate(lines, start=1):
            if not any(p.search(line) for p in self.patterns):
                continue
            window = " ".join(lines[max(0, idx - 6) : idx + 5])
            with_cred = bool(self.credentials.search(window))
            found.append(
                self.at_line(
                    src,
                    idx,
                    "모든 출처를 허용하는 CORS 설정입니다." + (" 인증 정보(credentials) 허용과 함께 쓰여 위험합니다." if with_cred else ""),
                    severity=Severity.HIGH if with_cred else Severity.MEDIUM,
                    confidence=Confidence.REVIEW,
                )
            )
        return found


class InsecureSettingsRule(LineRegexRule, AiRule):
    rule_id = "AI-106"
    name = "운영에 위험한 보안 설정 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.MEDIUM
    plain = "개발 편의를 위해 풀어 둔 설정(모든 호스트 허용, 쿠키 보안 해제, 관리용 엔드포인트 공개)이 그대로 배포되면 공격 통로가 됩니다."
    how_to_fix = "운영 설정에서는 허용 호스트를 명시하고, 쿠키에 Secure/HttpOnly/SameSite를 켜고, 관리용 엔드포인트는 인증 뒤에 두거나 끄세요."
    kinds = {"code", "properties", "yaml", "env", "toml", "compose"}
    patterns = [
        (re.compile(r"""ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]"""), "Django ALLOWED_HOSTS가 '*'로 열려 있습니다.", Severity.MEDIUM),
        (re.compile(r"""(SESSION|CSRF)_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False"""), "세션/CSRF 쿠키 보안 옵션이 꺼져 있습니다.", Severity.MEDIUM),
        (re.compile(r"""\b(httpOnly|secure)\s*:\s*false\b"""), "쿠키/세션의 httpOnly/secure 옵션이 꺼져 있습니다.", Severity.MEDIUM),
        (re.compile(r"""management\.endpoints\.web\.exposure\.include\s*[:=]\s*['"]?\*|management\.security\.enabled\s*[:=]\s*false"""), "Spring Actuator 엔드포인트가 전부 공개되어 있습니다.", Severity.HIGH),
        (re.compile(r"""spring\.h2\.console\.enabled\s*[:=]\s*true|server\.error\.include-stacktrace\s*[:=]\s*always|server\.error\.include-message\s*[:=]\s*always"""), "H2 콘솔 또는 스택 트레이스 노출이 켜져 있습니다.", Severity.HIGH),
        (re.compile(r"""SECURE_SSL_REDIRECT\s*=\s*False|SECURE_HSTS_SECONDS\s*=\s*0\b"""), "HTTPS 강제 설정이 꺼져 있습니다.", Severity.LOW),
        (re.compile(r"""\bsameSite\s*:\s*['"]?none['"]?(?![^\n]*secure\s*:\s*true)"""), "SameSite=None 쿠키는 Secure와 함께여야 합니다.", Severity.LOW),
        (re.compile(r"""app\.disable\(\s*['"]x-powered-by['"]\s*\)\s*;?\s*//\s*TODO|trust\s+proxy['"]?\s*,\s*true"""), "프록시 신뢰 설정을 무조건 켜 두었습니다.", Severity.LOW),
    ]
    confidence = Confidence.REVIEW

    def check(self, src: SourceFile) -> list[Violation]:
        if src.is_test:
            return []
        return super().check(src)


class DevOpsConfigRule(AiRule):
    rule_id = "AI-110"
    name = "컨테이너·CI 배포 설정의 위험 요소 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    plain = "AI가 만든 Dockerfile·Compose·CI 설정은 '일단 돌아가게' 만들어서, 컨테이너가 관리자 권한으로 실행되거나 DB 포트가 인터넷에 열리거나 CI에서 비밀이 새는 경우가 많습니다."
    how_to_fix = "컨테이너는 USER로 일반 사용자 권한으로 실행하고, DB 포트는 127.0.0.1로만 열고, 이미지는 버전을 고정하고, CI에서는 외부 입력(PR 제목 등)을 run 스크립트에 직접 넣지 마세요."
    db_ports = r"(?:5432|3306|27017|6379|9200|5984|1433|11211|2181|9092)"

    def check(self, src: SourceFile) -> list[Violation]:
        if src.kind == "docker":
            return self._dockerfile(src)
        if src.kind == "compose":
            return self._compose(src)
        if src.kind == "actions":
            return self._actions(src)
        return []

    def _dockerfile(self, src: SourceFile) -> list[Violation]:
        found = []
        lines = src.code_lines
        from_lines = [i for i, text_line in enumerate(lines, start=1) if re.match(r"\s*FROM\b", text_line, re.IGNORECASE)]
        if not from_lines:
            return found
        last_from = from_lines[-1]
        if not any(re.match(r"\s*USER\s+(?!root\b|0\b)\S+", text_line, re.IGNORECASE) for text_line in lines[last_from - 1 :]):
            found.append(self.at_line(src, last_from, "컨테이너가 USER 지정 없이 root 권한으로 실행됩니다. 일반 사용자로 실행하십시오.", confidence=Confidence.REVIEW))
        for idx, line in enumerate(lines, start=1):
            m = re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?(?P<img>\S+)", line, re.IGNORECASE)
            if m:
                img = m.group("img")
                if img.lower() != "scratch" and not img.startswith("$") and (img.endswith(":latest") or (":" not in img and "@" not in img)) and " as " not in img.lower():
                    found.append(self.at_line(src, idx, f"기본 이미지 {img}의 버전이 고정되지 않았습니다 (latest). 태그나 다이제스트로 고정하십시오.", severity=Severity.LOW, confidence=Confidence.REVIEW))
            if re.match(r"\s*ADD\s+https?://", line, re.IGNORECASE):
                found.append(self.at_line(src, idx, "ADD로 원격 URL을 받습니다. 무결성 검증 없이 외부 파일이 이미지에 들어갑니다.", severity=Severity.LOW, confidence=Confidence.REVIEW))
        return found

    def _compose(self, src: SourceFile) -> list[Violation]:
        found = []
        for idx, line in enumerate(src.code_lines, start=1):
            if re.search(r"privileged\s*:\s*true|network_mode\s*:\s*['\"]?host|/var/run/docker\.sock", line):
                found.append(self.at_line(src, idx, "컨테이너에 호스트 전체 권한(privileged/host 네트워크/docker.sock)을 줍니다.", severity=Severity.HIGH))
            elif re.search(rf"""-\s*['"]?(?!127\.0\.0\.1:|\[::1\]:|localhost:)(\d+:)?{self.db_ports}:{self.db_ports}['"]?\s*$""", line):
                found.append(self.at_line(src, idx, "데이터베이스/캐시 포트가 모든 인터페이스에 공개됩니다. 127.0.0.1:포트로 제한하십시오.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
        return found

    def _actions(self, src: SourceFile) -> list[Violation]:
        found = []
        lines = src.code_lines
        if re.search(r"^\s*pull_request_target\b|\bon:\s*\[?[^\n]*pull_request_target", src.code_text, re.MULTILINE) and re.search(r"github\.(event\.pull_request\.head|head_ref)", src.code_text):
            idx = next(i for i, text_line in enumerate(lines, start=1) if "pull_request_target" in text_line)
            found.append(self.at_line(src, idx, "pull_request_target에서 PR 코드를 체크아웃해 실행하면 외부 기여자가 저장소 비밀을 탈취할 수 있습니다.", severity=Severity.HIGH))
        run_indent: int | None = None
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())
            if re.match(r"\s*-?\s*run\s*:", line):
                run_indent = indent
                body = line.split(":", 1)[1]
            elif run_indent is not None and stripped and indent <= run_indent:
                run_indent = None
                body = line
            else:
                body = line
            in_run = run_indent is not None
            if in_run and re.search(r"\$\{\{\s*github\.event\.(issue|pull_request|comment|review|head_commit|commits|discussion)[^}]*\.(title|body|message|name|ref|label|email|login)\s*\}\}", body):
                found.append(self.at_line(src, idx, "run 스크립트에 외부 입력(PR 제목/본문 등)이 직접 삽입되어 명령어 주입이 가능합니다. env로 전달하십시오.", severity=Severity.HIGH))
            if re.search(r"echo\s+[^\n]*\$\{\{\s*secrets\.", body):
                found.append(self.at_line(src, idx, "비밀 값을 echo로 출력합니다. 로그에 노출될 수 있습니다.", severity=Severity.HIGH))
            if re.match(r"\s*permissions\s*:\s*write-all\b", line):
                found.append(self.at_line(src, idx, "워크플로 권한이 write-all입니다. 필요한 권한만 지정하십시오.", severity=Severity.MEDIUM))
            if re.search(r"uses\s*:\s*[\w.\-]+/[\w.\-]+(?:/[\w./\-]+)?@(main|master)\b", line):
                found.append(self.at_line(src, idx, "외부 액션이 브랜치(main/master)에 고정되어 있어 코드가 바뀌면 그대로 실행됩니다. 커밋 SHA로 고정하십시오.", severity=Severity.LOW, confidence=Confidence.REVIEW))
        return found

    def check_project(self, project: ProjectContext) -> list[Violation]:
        found = []
        has_dockerignore = project.has_path(".dockerignore")
        for src in project.by_kind("docker"):
            if has_dockerignore:
                continue
            for idx, line in enumerate(src.code_lines, start=1):
                if re.match(r"\s*COPY\s+(--\S+\s+)*\.\s+\S+", line, re.IGNORECASE):
                    found.append(self.at_line(src, idx, ".dockerignore 없이 COPY . 로 전체를 복사합니다. .env, .git 같은 비밀이 이미지에 들어갈 수 있습니다.", confidence=Confidence.REVIEW))
                    break
        return found


class CommittedSecretFilesRule(AiRule):
    rule_id = "AI-104"
    sensitive_snippet = True
    name = "저장소에 포함된 비밀 파일(.env, 개인키) 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.CRITICAL
    plain = ".env 같은 비밀 파일을 .gitignore에 넣지 않으면 깃허브에 올라가는 순간 모든 키가 공개됩니다. 올라간 키는 삭제해도 기록에 남아 즉시 폐기해야 합니다."
    how_to_fix = ".gitignore에 .env*, *.pem, *.key, serviceAccount*.json을 추가하고, 이미 커밋했다면 파일을 지운 뒤 해당 키를 모두 폐기·재발급하세요 (git 기록에서 지우는 것만으로는 부족합니다)."
    secret_files = re.compile(
        r"(?i)(^|/)(id_(rsa|dsa|ecdsa|ed25519)|\.netrc|\.pypirc|credentials\.json|client_secret[^/]*\.json|service[-_]?account[^/]*\.json|[^/]*firebase-adminsdk[^/]*\.json|[^/]*\.(p12|pfx|jks|keystore)|[^/]*(private|secret)[^/]*\.(pem|key))$"
    )
    env_file = re.compile(r"(^|/)(\.env(\.[\w-]+)?|[^/]*\.env)$")
    env_template = re.compile(r"(?i)\.(example|sample|template|dist|defaults)$")

    def check_project(self, project: ProjectContext) -> list[Violation]:
        found = []
        by_path = {f.path.as_posix(): f for f in project.files}
        for path in sorted(project.all_paths):
            if any(part in TEST_DIR_NAMES for part in PurePosixPath(path).parts[:-1]):
                continue
            if self.env_file.search(path) and not self.env_template.search(path):
                if project.is_gitignored(path):
                    continue
                src = by_path.get(path)
                has_secret = src is not None and any(re.search(rf"(?i){SECRET_NAME}\s*=\s*\S{{4,}}", text_line) for text_line in src.code_lines)
                v = Violation(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    iron_law=self.iron_law,
                    severity=Severity.CRITICAL if has_secret else Severity.HIGH,
                    file_path=src.path if src else Path(path),
                    line_number=1,
                    snippet=path,
                    message=f"{path} 파일이 .gitignore에 제외되어 있지 않아 저장소에 올라갈 수 있습니다." + (" 비밀 값이 들어 있습니다." if has_secret else ""),
                    layer=self.layer,
                    confidence=Confidence.CONFIRMED if has_secret else Confidence.REVIEW,
                    plain=self.plain,
                    how_to_fix=self.how_to_fix,
                )
                found.append(v)
            elif self.secret_files.search(path) and not project.is_gitignored(path):
                found.append(
                    Violation(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        iron_law=self.iron_law,
                        severity=Severity.HIGH,
                        file_path=Path(path),
                        line_number=1,
                        snippet=path,
                        message=f"{path} 은(는) 비밀 키/자격 증명 파일로 보이며 .gitignore에 제외되어 있지 않습니다.",
                        layer=self.layer,
                        confidence=Confidence.REVIEW,
                        plain=self.plain,
                        how_to_fix=self.how_to_fix,
                    )
                )
        return found


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


class SecurityHardeningAdviceRule(AiRule):
    rule_id = "AI-114"
    name = "보안 헤더·요청 제한 미적용 안내"
    iron_law = IronLaw.LAW_5
    severity = Severity.LOW
    plain = "웹 서버에 보안 헤더와 요청 횟수 제한이 없으면 클릭재킹, 무차별 로그인 시도, 서버 과부하 공격에 그대로 노출됩니다."
    how_to_fix = "Express는 helmet과 express-rate-limit, FastAPI는 slowapi, Flask는 flask-talisman/flask-limiter, Django는 보안 미들웨어와 django-ratelimit를 쓰세요."

    def check(self, src: SourceFile) -> list[Violation]:
        return []

    def check_project(self, project: ProjectContext) -> list[Violation]:
        found = []
        texts = {f.path.as_posix(): f.text for f in project.files if f.kind in ("code", "json", "toml", "text")}
        blob = "\n".join(texts.values())
        pkg = next((f for f in project.files if f.path.name == "package.json"), None)
        if pkg is not None and '"express"' in pkg.text:
            missing = [n for n, pat in (("helmet", "helmet"), ("요청 제한(express-rate-limit 등)", r"rate-?limit|limiter")) if not re.search(pat, blob)]
            if missing:
                found.append(self.at_line(pkg, 1, "Express 서버에 " + ", ".join(missing) + " 사용이 보이지 않습니다.", confidence=Confidence.REVIEW))
        py_web = re.search(r"(?i)\b(fastapi|flask)\b", blob)
        marker_file = next((f for f in project.files if re.match(r"(requirements.*\.txt|pyproject\.toml)$", f.path.name)), None)
        if py_web and marker_file is not None and not re.search(r"(?i)slowapi|limiter|ratelimit|talisman|secure_headers|fastapi-limiter|throttl", blob):
            found.append(self.at_line(marker_file, 1, "Python 웹 서버에 요청 제한/보안 헤더 라이브러리 사용이 보이지 않습니다.", confidence=Confidence.REVIEW))
        return found
