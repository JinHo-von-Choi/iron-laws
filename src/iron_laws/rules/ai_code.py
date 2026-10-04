"""
AI 생성 코드 보정 계열: AI가 결과물만 목적으로 만들 때 자주 남기는 보안·설정 결함
작성자: 최진호
작성일: 2026-10-04
"""

import json
import re
from pathlib import Path, PurePosixPath

from tree_sitter import Node

from iron_laws.core.models import Confidence, IronLaw, RuleLayer, Severity, Violation
from iron_laws.core.paths import TEST_DIR_NAMES
from iron_laws.engine.ast_tools import (
    enclosing_function,
    identifiers_in,
    is_literal,
    is_string_node,
    iter_calls,
    iter_functions,
    string_value,
    walk,
)
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import is_tainted
from iron_laws.rules.base import BaseRule
from iron_laws.rules.secrets_crypto import SECRET_NAME, LineRegexRule
from iron_laws.rules.sinks import CS, GO, JAVA, JS, PHP, PY, Sink
from iron_laws.standards import mois_ref

CODE_KINDS = {"code"}
MAX_PER_FILE = 25


class AiRule(BaseRule):
    layer = RuleLayer.AI_CODE
    gov_standard = None


class HardcodedConfigRule(AiRule):
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
            if self.doc_hosts.search(host) or host.startswith(("$", "{", "<")):
                return None
            local = bool(re.match(r"(?i)(localhost|127\.|0\.0\.0\.0|\[::1\]|host\.docker\.internal)", host))
            return self.at_node(
                src,
                node,
                f"URL {value[:80]}이(가) 코드에 고정되어 있습니다. " + ("개발용 주소는 배포 환경에서 동작하지 않습니다." if local else "환경별로 바뀌는 주소는 설정으로 분리하십시오."),
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

    def _ports(self, src: SourceFile) -> list[Violation]:
        found = []
        for call in iter_calls(src):
            if re.search(r"(^|\.)(listen|run|serve)$", call.callee) and src.lang is not None:
                text = src.text_of(call.node)
                if re.search(r"(?<![\w.])(port\s*=\s*)?[1-9]\d{3,4}\b", text) and not re.search(r"environ|getenv|process\.env|config|settings|PORT", text):
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


class ClientSideAuthRule(AiRule):
    rule_id = "AI-109"
    name = "브라우저 저장소 값으로 하는 인증·권한 판단 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    plain = "관리자인지, 로그인했는지를 브라우저에 저장된 값(localStorage 등)으로만 판단하면, 사용자가 개발자 도구에서 값을 바꿔 관리자 화면에 들어갈 수 있습니다."
    how_to_fix = "화면 숨김은 편의일 뿐입니다. 권한 확인은 반드시 서버 API에서 세션/토큰으로 다시 검사하세요."
    pattern = re.compile(
        r"""(?:localStorage|sessionStorage|Cookies?)\.(?:getItem|get)\(\s*['"][^'"]*(?:admin|role|auth|logged|permission|isAdmin)[^'"]*['"]\s*\)\s*(?:===?|!==?|&&|\?|\|\|)|if\s*\(\s*(?:localStorage|sessionStorage)\.getItem\(\s*['"][^'"]*(?:admin|role|auth|logged|permission)""",
        re.IGNORECASE,
    )

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang not in JS_FAMILY:
            return []
        return [
            self.at_line(src, idx, "브라우저 저장소 값으로 권한/로그인 여부를 판단합니다. 서버에서 다시 검증해야 합니다.", confidence=Confidence.REVIEW)
            for idx, line in enumerate(src.code_lines, start=1)
            if self.pattern.search(line)
        ]


class LoggingSafetyRule(AiRule):
    rule_id = "AI-112"
    name = "민감정보 로깅 및 로그 주입 탐지"
    iron_law = IronLaw.LAW_3
    severity = Severity.HIGH
    plain = "비밀번호·토큰이 로그에 남으면 로그를 볼 수 있는 모든 사람(그리고 로그 수집 서비스)이 그 값을 보게 됩니다. 사용자 입력을 그대로 로그에 쓰면 줄바꿈으로 가짜 로그를 심을 수도 있습니다."
    how_to_fix = "비밀번호·토큰·카드번호는 로그에서 제외하거나 마스킹하세요. 사용자 입력은 repr()/JSON 인코딩으로 줄바꿈을 제거한 뒤 기록하세요."
    log_sinks = [
        Sink.of(PY, r"^(logger|logging|log|_logger|LOGGER|self\.logger|self\.log|current_app\.logger|app\.logger)\.(debug|info|warning|warn|error|exception|critical|fatal)$", None),
        Sink.of(PY, r"^print$", None),
        Sink.of(JS, r"^(console\.(log|info|debug|warn|error)|logger\.\w+|log\.\w+)$", None),
        Sink.of(JAVA, r"^(log|logger|LOG|LOGGER)\.(debug|info|warn|error|trace)$|^System\.out\.println$|^System\.out\.printf?$", None),
        Sink.of(CS, r"^(_?logger|Log)\.(Log\w*|Debug|Info|Warn|Error|Information|Warning)$|^Console\.Write(Line)?$", None),
        Sink.of(GO, r"^(log\.(Print\w*|Fatal\w*|Panic\w*)|slog\.\w+|logger\.\w+|fmt\.Print\w*)$", None),
        Sink.of(PHP, r"^(error_log|var_dump|print_r)$|\$logger->|->(info|error|warning|debug)$", None),
    ]
    sensitive = re.compile(r"(?i)^(pass(word|wd)?|pwd|secret|token|api_?key|apikey|authorization|credit_?card|card_?(no|number)|ssn|jumin|cvv|private_?key|access_?token|refresh_?token|client_?secret|passwd)$|password|passwd|secret|token|apikey|api_key")
    whole_request = re.compile(r"\b(request\.(json|form|data|get_json\(\))|req\.(body|headers)|request\.(body|headers))\b")
    sanitized = re.compile(r"(?i)repr\(|%r|json\.dumps|escape|sanitize|replace\(|encode|strip\(|quote\(|JSON\.stringify|StringEscapeUtils|Encode")

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        for call in iter_calls(src):
            if not any(src.lang in s.langs and s.callee.search(call.callee) for s in self.log_sinks):
                continue
            if call.callee == "print" and src.is_test:
                continue
            sensitive_hit = False
            for arg in call.args:
                if is_string_node(arg) and not any(n.type == "interpolation" for n in walk(arg)):
                    continue
                names = identifiers_in(src, arg)
                if any(self.sensitive.search(n) for n in names):
                    sensitive_hit = True
                    break
            if sensitive_hit:
                found.append(self.at_node(src, call.node, f"{call.callee}로 비밀번호·토큰 등 민감정보로 보이는 값을 기록합니다."))
                continue
            args_text = " ".join(src.text_of(a) for a in call.args)
            if self.whole_request.search(args_text):
                found.append(self.at_node(src, call.node, "요청 본문/헤더 전체를 로그에 기록합니다. 비밀번호·토큰이 포함될 수 있습니다.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
                continue
            if call.callee in ("print", "console.log", "console.info", "console.debug"):
                continue
            if any(not is_literal(a) and is_tainted(src, a) for a in call.args) and not self.sanitized.search(args_text):
                found.append(self.at_node(src, call.node, "사용자 입력을 정제 없이 로그에 기록합니다 (줄바꿈 삽입으로 로그 위조 가능).", severity=Severity.LOW, confidence=Confidence.REVIEW))
        return found


class IdorRule(AiRule):
    rule_id = "AI-113"
    name = "객체 소유자 검증 없는 조회(IDOR/BOLA) 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    gov_standard = mois_ref("2-2")
    layer = RuleLayer.STANDARD
    plain = "주소의 번호만 바꾸면 남의 주문·메시지·프로필이 보이는 취약점입니다. AI가 만든 CRUD API에서 가장 흔한 사고 원인입니다."
    how_to_fix = "ID로 조회할 때 반드시 '로그인한 사용자의 소유인지' 조건을 함께 거세요. 예: Order.objects.get(id=id, user=request.user) / findOne({_id: id, owner: req.user.id})"
    sinks = [
        Sink.of(PY, r"(\.objects\.get|get_object_or_404|\.query\.get|\.filter_by|session\.get|\.get_or_404)$", None),
        Sink.of(JS, r"(^|\.)(findById|findOne|findByPk|findUnique|findFirst|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|deleteOne|updateOne)$", None),
        Sink.of(JAVA, r"(^|\.)(findById|getById|getOne|deleteById|getReferenceById)$", None),
        Sink.of(CS, r"(^|\.)(FindAsync|Find|FirstOrDefaultAsync|SingleOrDefaultAsync|GetByIdAsync|FirstOrDefault)$", None),
    ]
    owner = re.compile(
        r"(?i)request\.user|current_user|\bowner|user_id|userId|req\.user|req\.auth|req\.session|session\[|getPrincipal|SecurityContext|Authentication|"
        r"User\.Identity|User\.FindFirst|ClaimTypes|HttpContext\.User|createdBy|created_by|\.user\b|ownerId|@AuthenticationPrincipal|g\.user|get_jwt_identity|where\s*:\s*\{[^}]*user|tenant|organization|org_id|\.is_staff|is_admin|isAdmin|hasRole|PreAuthorize|\[Authorize"
    )

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        for call in iter_calls(src):
            if not any(src.lang in s.langs and s.callee.search(call.callee) for s in self.sinks):
                continue
            tainted = any(not is_literal(a) and is_tainted(src, a) for a in call.args)
            if not tainted:
                continue
            fn = enclosing_function(call.node, src.lang)
            scope = src.text_of(fn) if fn is not None else src.text_of(call.node)
            if src.lang is Lang.JAVA or src.lang is Lang.CSHARP:
                cls = fn.parent if fn is not None else None
                while cls is not None and cls.type not in ("class_declaration",):
                    cls = cls.parent
                if cls is not None:
                    scope += " " + src.data[cls.start_byte : (cls.child_by_field_name("body") or cls).start_byte].decode("utf-8", "replace")
            if self.owner.search(scope):
                continue
            found.append(
                self.at_node(src, call.node, f"요청의 ID로 {call.callee} 조회를 하지만 소유자·권한 조건이 보이지 않습니다 (남의 데이터 조회 가능성).", confidence=Confidence.REVIEW)
            )
        return found


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


class DatabaseAccessPolicyRule(AiRule):
    rule_id = "AI-108"
    name = "Supabase·Firebase 접근 규칙 누락/개방 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.HIGH
    plain = "Supabase·Firebase는 브라우저에서 DB를 직접 호출하는 구조라서 '접근 규칙(RLS/보안 규칙)'이 곧 보안의 전부입니다. 규칙이 없거나 모두 허용이면 누구나 전체 데이터를 읽고 지울 수 있습니다."
    how_to_fix = "모든 테이블에 `alter table ... enable row level security;`를 켜고 `auth.uid() = user_id` 같은 소유자 조건의 policy를 만드세요. Firebase는 `allow read, write: if request.auth != null && request.auth.uid == resource.data.uid` 형태로 제한하세요."
    open_rules = re.compile(r"allow\s+[\w\s,]+:\s*if\s+true\b")
    timebomb = re.compile(r"request\.time\s*<\s*timestamp\.date\(")
    json_open = re.compile(r"""["']\.(read|write)["']\s*:\s*(true|["']true["'])""")
    open_policy = re.compile(r"(?is)create\s+policy\b[^;]*?\b(?:using|with\s+check)\s*\(\s*true\s*\)")
    anon_write = re.compile(r"(?is)create\s+policy\b[^;]*?\bfor\s+(all|insert|update|delete)\b[^;]*?\bto\s+(anon|public)\b[^;]*?\b(?:using|with\s+check)\s*\(\s*true\s*\)")

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.kind == "rules":
            for idx, line in enumerate(src.code_lines, start=1):
                if self.open_rules.search(line):
                    found.append(self.at_line(src, idx, "누구나 읽고 쓸 수 있도록 규칙이 `if true`로 열려 있습니다.", severity=Severity.CRITICAL))
                elif self.timebomb.search(line):
                    found.append(self.at_line(src, idx, "기간 한정 전체 공개(테스트 모드) 규칙입니다. 기간이 지나기 전에 실제 규칙으로 교체하십시오.", severity=Severity.HIGH))
        elif src.kind == "json" and re.search(r"rules|database", src.path.name, re.IGNORECASE):
            for idx, line in enumerate(src.code_lines, start=1):
                if self.json_open.search(line):
                    found.append(self.at_line(src, idx, "Realtime Database 규칙이 읽기/쓰기를 누구에게나 허용합니다.", severity=Severity.CRITICAL))
        elif src.kind == "sql":
            text = src.code_text
            for m in self.anon_write.finditer(text):
                found.append(self.at_line(src, text.count("\n", 0, m.start()) + 1, "anon/public 역할에게 조건 없이 쓰기를 허용하는 policy입니다.", severity=Severity.CRITICAL))
            seen = {v.line_number for v in found}
            for m in self.open_policy.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                if line not in seen:
                    found.append(self.at_line(src, line, "using (true) 정책은 모든 행을 모두에게 공개합니다.", confidence=Confidence.REVIEW))
        return found

    def check_project(self, project: ProjectContext) -> list[Violation]:
        sql_files = project.by_kind("sql")
        if not sql_files:
            return []
        joined = "\n".join(f.code_text for f in project.files if f.kind in ("sql", "code", "json", "toml", "env", "yaml"))
        if not re.search(r"(?i)supabase|auth\.uid\(\)|create\s+policy|row\s+level\s+security", joined):
            return []
        enabled = {m.group(1).lower() for m in re.finditer(r"(?is)alter\s+table\s+(?:only\s+)?(?:public\.)?\"?(\w+)\"?\s+enable\s+row\s+level\s+security", "\n".join(f.code_text for f in sql_files))}
        found = []
        for src in sql_files:
            text = src.code_text
            for m in re.finditer(r"(?is)create\s+table\s+(?:if\s+not\s+exists\s+)?(?P<schema>\"?\w+\"?\.)?\"?(?P<name>\w+)\"?", text):
                schema = (m.group("schema") or "public.").strip('".').lower()
                if schema not in ("public",):
                    continue
                name = m.group("name").lower()
                if name not in enabled:
                    found.append(self.at_line(src, text.count("\n", 0, m.start()) + 1, f"테이블 {name}에 Row Level Security가 켜져 있지 않습니다. 브라우저에서 누구나 접근할 수 있습니다.", confidence=Confidence.REVIEW))
        return found


ROUTE_DECORATOR = re.compile(r"@\s*(?:\w+\.)*(route|get|post|put|patch|delete|api_view|websocket)\b")
SENSITIVE_PATH = re.compile(r"(?i)admin|user|delete|remove|payment|pay|account|order|password|secret|internal|manage|dashboard|upload|export|import|settings|billing|token|profile|invoice|config")
PUBLIC_PATH = re.compile(r"(?i)^/?(login|logout|register|signup|sign-up|signin|sign-in|auth|health|healthz|ping|status|public|webhook|callback|oauth|token|refresh|forgot|reset|verify|docs|openapi|static|favicon|robots|metrics|$)")
AUTH_MARKER = re.compile(
    r"(?i)login_required|jwt_required|permission|require_?auth|requires?_?\w*role|Depends\(|Security\(|current_user|request\.user|g\.user|session\[|token_required|verify_?token|HTTPBearer|OAuth2|"
    r"authenticat|authoriz|auth\b|passport|protect|isLoggedIn|requireLogin|guard|ensureAuth|req\.user|req\.session|req\.auth|getServerSession|getSession|currentUser|jwt\.verify|@PreAuthorize|@Secured|@RolesAllowed|\[Authorize|get_jwt|firebase.*verifyIdToken|supabase\.auth\.getUser|Authorization|api_key|apikey|x-api-key"
)


class UnauthenticatedEndpointRule(BaseRule):
    rule_id = "IL-525"
    name = "인증 확인이 보이지 않는 중요 기능 엔드포인트 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    gov_standard = mois_ref("2-1")
    plain = "데이터를 바꾸거나 관리자·사용자 정보를 다루는 API에 '로그인 확인'이 없으면 로그인하지 않은 누구나 그 기능을 호출할 수 있습니다. AI는 화면 기능만 만들고 서버 쪽 인증을 빼먹는 경우가 많습니다."
    how_to_fix = "쓰기·관리·개인정보 API에는 인증 미들웨어/데코레이터를 붙이고, 서버에서 사용자와 권한을 확인하세요. 예: @login_required / app.post('/x', authenticate, handler) / @PreAuthorize / [Authorize]"
    languages = None

    def check(self, src: SourceFile) -> list[Violation]:
        return []

    def check_project(self, project: ProjectContext) -> list[Violation]:
        found = []
        all_text = "\n".join(f.code_text for f in project.source_files())
        spring_secured = bool(re.search(r"SecurityFilterChain|@EnableWebSecurity|WebSecurityConfigurerAdapter|authorizeHttpRequests|authorizeRequests", all_text))
        dotnet_global = bool(re.search(r"FallbackPolicy|AuthorizeFilter|RequireAuthorization\(\)|UseAuthorization", all_text)) and bool(re.search(r"FallbackPolicy|AuthorizeFilter|AddAuthorizationBuilder", all_text))
        for src in project.source_files():
            if src.lang is Lang.PYTHON:
                found.extend(self._python(src))
            elif src.lang in JS_FAMILY:
                found.extend(self._express(src))
            elif src.lang is Lang.JAVA and not spring_secured:
                found.extend(self._spring(src))
            elif src.lang is Lang.CSHARP and not dotnet_global:
                found.extend(self._aspnet(src))
        return found

    def _sensitive(self, method: str, path: str) -> bool:
        if PUBLIC_PATH.match(path.lstrip("/")) and not SENSITIVE_PATH.search(path):
            return False
        if re.match(r"(?i)^/?(login|logout|register|signup|signin|auth|health|ping|webhook|callback|oauth|token|refresh|forgot|reset)\b", path):
            return False
        return method.lower() in ("post", "put", "patch", "delete") or bool(SENSITIVE_PATH.search(path))

    @staticmethod
    def _head(src: SourceFile, fn) -> str:
        end = fn.body.start_byte if fn.body is not None else fn.node.end_byte
        return src.data[fn.node.start_byte : end].decode("utf-8", errors="replace")

    def _make(self, src: SourceFile, node: Node, what: str) -> Violation:
        return self.at_node(src, node, f"{what}에 인증·권한 확인이 보이지 않습니다. 로그인하지 않은 사용자도 호출할 수 있는지 확인하십시오.", confidence=Confidence.REVIEW)

    def _python(self, src: SourceFile) -> list[Violation]:
        found = []
        assert src.root is not None
        for node in src.nodes:
            if node.type != "decorated_definition":
                continue
            decorators = [c for c in node.named_children if c.type == "decorator"]
            definition = node.child_by_field_name("definition")
            if definition is None or definition.type != "function_definition":
                continue
            route = next((d for d in decorators if ROUTE_DECORATOR.search(src.text_of(d))), None)
            if route is None:
                continue
            rtext = src.text_of(route)
            m = re.search(r"\(\s*[rbf]?['\"]([^'\"]*)['\"]", rtext)
            path = m.group(1) if m else ""
            method_m = re.search(r"@\s*(?:\w+\.)*(get|post|put|patch|delete)\b", rtext)
            methods = [method_m.group(1)] if method_m else [x.lower() for x in re.findall(r"['\"](GET|POST|PUT|PATCH|DELETE)['\"]", rtext)] or ["get"]
            if not any(self._sensitive(mm, path) for mm in methods):
                continue
            scope = src.code_of(node)
            if AUTH_MARKER.search(scope):
                continue
            found.append(self._make(src, definition, f"{' '.join(m.upper() for m in methods)} {path or '(경로 미상)'} 핸들러"))
        return found

    def _express(self, src: SourceFile) -> list[Violation]:
        found = []
        for call in iter_calls(src):
            m = re.match(r"^(?:app|router|api|server|r|route)\.(get|post|put|patch|delete)$", call.callee)
            if not m or len(call.args) < 2:
                continue
            path_arg = call.args[0]
            if path_arg.type not in ("string", "template_string"):
                continue
            path = string_value(src, path_arg)
            if not self._sensitive(m.group(1), path):
                continue
            scope = src.code_of(call.node)
            if AUTH_MARKER.search(scope):
                continue
            file_has_global = re.search(r"(?:app|router)\.use\(\s*(?:['\"][^'\"]*['\"]\s*,\s*)?(?:\w*auth\w*|passport\.authenticate|jwt\w*|protect|verifyToken)", src.code_text, re.IGNORECASE)
            if file_has_global:
                continue
            found.append(self._make(src, call.node, f"{m.group(1).upper()} {path} 라우트"))
        return found

    def _spring(self, src: SourceFile) -> list[Violation]:
        found = []
        if "@RestController" not in src.text and "@Controller" not in src.text:
            return found
        class_secured = bool(re.search(r"@(PreAuthorize|Secured|RolesAllowed)", src.text.split("class ", 1)[0]))
        if class_secured:
            return found
        for fn in iter_functions(src):
            text = src.code_of(fn.node)
            head = self._head(src, fn)
            m = re.search(r"@(Get|Post|Put|Patch|Delete|Request)Mapping(?:\(([^)]*)\))?", head)
            if not m:
                continue
            method = m.group(1)
            path_m = re.search(r"\"([^\"]*)\"", m.group(2) or "")
            path = path_m.group(1) if path_m else ""
            if not self._sensitive("get" if method in ("Get", "Request") else method.lower(), path):
                continue
            if re.search(r"@(PreAuthorize|Secured|RolesAllowed)|Principal|Authentication|SecurityContext", text):
                continue
            found.append(self._make(src, fn.node, f"{method.upper()} {path} 컨트롤러 메서드"))
        return found

    def _aspnet(self, src: SourceFile) -> list[Violation]:
        found = []
        if not re.search(r":\s*(Controller|ControllerBase)\b|\[ApiController\]", src.text):
            return found
        if re.search(r"\[Authorize\b", src.text.split("class ", 1)[0]):
            return found
        for fn in iter_functions(src):
            text = src.code_of(fn.node)
            head = self._head(src, fn)
            m = re.search(r"\[Http(Get|Post|Put|Patch|Delete)(?:\(\s*\"([^\"]*)\"\s*\))?\]", head)
            if not m:
                continue
            if re.search(r"\[Authorize|\[AllowAnonymous\]|User\.Identity|HttpContext\.User", text):
                continue
            if self._sensitive(m.group(1).lower(), m.group(2) or fn.name):
                found.append(self._make(src, fn.node, f"{m.group(1).upper()} {fn.name} 액션"))
        return found


def _levenshtein(a: str, b: str) -> int:
    """전위(인접 글자 교환)를 1회로 세는 편집 거리"""
    if abs(len(a) - len(b)) > 2:
        return 3
    rows = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        rows[i][0] = i
    for j in range(len(b) + 1):
        rows[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            rows[i][j] = min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)
    return rows[-1][-1]


POPULAR_PY = {
    "requests", "numpy", "pandas", "flask", "django", "fastapi", "pydantic", "sqlalchemy", "pytest", "boto3", "scipy", "matplotlib", "pillow", "openai", "anthropic", "langchain",
    "beautifulsoup4", "lxml", "aiohttp", "httpx", "uvicorn", "gunicorn", "celery", "redis", "psycopg2", "pymysql", "cryptography", "pyjwt", "bcrypt", "passlib", "python-dotenv",
    "pyyaml", "jinja2", "click", "typer", "rich", "tqdm", "scikit-learn", "tensorflow", "torch", "transformers", "streamlit", "selenium", "playwright", "alembic", "websockets",
    "python-dateutil", "pytz", "setuptools", "wheel", "urllib3", "certifi", "colorama", "attrs", "six", "markdown", "docker", "paramiko", "pexpect", "tornado", "starlette", "sentry-sdk",
}
POPULAR_NPM = {
    "react", "react-dom", "next", "express", "lodash", "axios", "typescript", "vue", "angular", "svelte", "webpack", "vite", "eslint", "prettier", "jest", "mocha", "chai", "moment",
    "dayjs", "uuid", "dotenv", "cors", "body-parser", "mongoose", "sequelize", "prisma", "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "socket.io", "ws", "chalk", "commander",
    "yargs", "inquirer", "nodemon", "ts-node", "tailwindcss", "postcss", "autoprefixer", "redux", "zustand", "swr", "tanstack", "react-router-dom", "styled-components", "classnames",
    "cheerio", "puppeteer", "playwright", "firebase", "supabase", "openai", "anthropic", "zod", "joi", "yup", "helmet", "morgan", "multer", "nodemailer", "stripe", "node-fetch", "cross-env",
}


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
        return []

    def _package_json(self, src: SourceFile) -> list[Violation]:
        found = []
        data = _load_json_object(src.text)
        if data is None:
            return [self.at_line(src, 1, "package.json을 JSON으로 해석할 수 없어 의존성을 점검하지 못했습니다.", severity=Severity.LOW)]
        lines = src.lines
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(section) or {}
            if not isinstance(deps, dict):
                continue
            for name, version in deps.items():
                line = next((i for i, text_line in enumerate(lines, start=1) if f'"{name}"' in text_line), 1)
                if isinstance(version, str) and self.loose.match(version.strip()):
                    found.append(self.at_line(src, line, f"{name}의 버전 {version}이(가) 고정되지 않아 의도치 않은 버전이 설치될 수 있습니다.", severity=Severity.LOW))
                hit = self._typosquat(name, POPULAR_NPM)
                if hit:
                    found.append(self.at_line(src, line, f"패키지 {name}은(는) 인기 패키지 {hit}와 철자가 비슷합니다. 오타이거나 악성/존재하지 않는 패키지일 수 있습니다.", severity=Severity.HIGH, confidence=Confidence.REVIEW))
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
            if stripped.startswith(("-e", "git+", "http")):
                continue
            name = re.split(r"[=<>!~\[; ]", stripped, maxsplit=1)[0].lower()
            if "==" not in stripped and "@" not in stripped:
                unpinned += 1
                first_unpinned = first_unpinned or idx
            hit = self._typosquat(name, POPULAR_PY)
            if hit:
                found.append(self.at_line(src, idx, f"패키지 {name}은(는) 인기 패키지 {hit}와 철자가 비슷합니다. 오타이거나 악성/존재하지 않는 패키지일 수 있습니다.", severity=Severity.HIGH, confidence=Confidence.REVIEW))
        if unpinned:
            found.append(self.at_line(src, first_unpinned, f"버전을 고정하지 않은 의존성이 {unpinned}개 있습니다 (==로 고정하고 락 파일을 쓰십시오).", severity=Severity.LOW))
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
        return found


def _load_json_object(text: str) -> dict | None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:  # iron-laws: ignore[IL-301] 해석 실패는 None 반환으로 호출자에게 전달한다
        return None
    return data if isinstance(data, dict) else None


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


class CookieFlagsRule(AiRule):
    rule_id = "AI-115"
    name = "쿠키 보안 속성(Secure·HttpOnly) 누락 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.MEDIUM
    plain = "Secure가 없으면 암호화되지 않은 연결로도 쿠키가 전송되고, HttpOnly가 없으면 스크립트(XSS)가 로그인 쿠키를 읽어 갈 수 있습니다."
    how_to_fix = "로그인·세션 쿠키에는 Secure, HttpOnly, SameSite=Lax(또는 Strict)를 항상 지정하세요. 예: set_cookie(name, value, secure=True, httponly=True, samesite='Lax') / res.cookie(name, value, {httpOnly: true, secure: true, sameSite: 'lax'})"
    session_name = re.compile(r"(?i)sess|token|auth|sid|jwt|login|remember|refresh")
    sinks = [
        Sink.of(PY, r"(^|\.)set_cookie$", None),
        Sink.of(JS, r"^(res|response|reply)\.cookie$", None),
        Sink.of(PHP, r"^(setcookie|setrawcookie)$", None),
        Sink.of(CS, r"Cookies\.Append$", None),
        Sink.of(GO, r"^http\.SetCookie$", None),
    ]

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        for call in iter_calls(src):
            if src.lang is Lang.JAVA:
                continue
            if not any(src.lang in sk.langs and sk.callee.search(call.callee) for sk in self.sinks):
                continue
            text = src.text_of(call.node)
            missing = self._missing(src, call, text)
            if not missing:
                continue
            important = bool(self.session_name.search(text))
            found.append(
                self.at_node(
                    src,
                    call.node,
                    f"쿠키 설정에 {', '.join(missing)}이(가) 보이지 않습니다.",
                    severity=Severity.MEDIUM if important else Severity.LOW,
                    confidence=Confidence.REVIEW,
                )
            )
        found.extend(self._java(src))
        found.extend(self._session_middleware(src))
        return found

    def _session_middleware(self, src: SourceFile) -> list[Violation]:
        if src.lang not in JS_FAMILY or not re.search(r"express-session|cookie-session", src.text):
            return []
        found = []
        for call in iter_calls(src):
            if call.callee not in ("session", "expressSession", "cookieSession") or not call.args:
                continue
            text = src.text_of(call.node)
            lowered = text.lower()
            secure = re.search(r"secure\s*:\s*true", lowered) is not None
            httponly = re.search(r"httponly\s*:\s*true", lowered) is not None
            if secure and httponly:
                continue
            missing = [n for n, ok in (("Secure", secure), ("HttpOnly", httponly)) if not ok]
            found.append(
                self.at_node(
                    src,
                    call.node,
                    f"세션 미들웨어 설정에 쿠키 {', '.join(missing)} 옵션이 명시되어 있지 않습니다 (secure 기본값은 꺼져 있습니다).",
                    confidence=Confidence.REVIEW,
                )
            )
        return found

    @staticmethod
    def _missing(src: SourceFile, call, text: str) -> list[str]:
        lowered = text.lower()
        secure = re.search(r"secure\s*[:=]\s*(true|1)|secure\s*=\s*true|'secure'\s*=>\s*true", lowered) is not None
        httponly = re.search(r"http_?only\s*[:=]\s*(true|1)|httponly\s*=\s*true|'httponly'\s*=>\s*true", lowered) is not None
        if src.lang is Lang.PHP and len(call.args) >= 7:
            secure = httponly = True  # 위치 인자로 지정된 경우는 값 확인 대신 지정 자체를 신뢰한다
        missing = []
        if not secure:
            missing.append("Secure")
        if not httponly:
            missing.append("HttpOnly")
        return missing

    def _java(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.lang is not Lang.JAVA:
            return found
        for call in iter_calls(src):
            if call.callee != "newCookie":
                continue
            fn = enclosing_function(call.node, src.lang)
            scope = src.text_of(fn) if fn is not None else src.text
            missing = [n for n, pat in (("Secure", r"setSecure\(\s*true"), ("HttpOnly", r"setHttpOnly\(\s*true")) if not re.search(pat, scope)]
            if missing:
                found.append(
                    self.at_node(src, call.node, f"쿠키에 {', '.join(missing)} 설정이 보이지 않습니다.", confidence=Confidence.REVIEW)
                )
        return found


AI_RULES: list[type[BaseRule]] = [
    HardcodedConfigRule,
    SecretDefaultFallbackRule,
    FrontendSecretRule,
    CommittedSecretFilesRule,
    CorsRule,
    InsecureSettingsRule,
    UnauthenticatedEndpointRule,
    DatabaseAccessPolicyRule,
    ClientSideAuthRule,
    DevOpsConfigRule,
    SupplyChainRule,
    LoggingSafetyRule,
    IdorRule,
    SecurityHardeningAdviceRule,
    CookieFlagsRule,
]

