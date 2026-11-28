"""
검토자가 자주 지적하는 인증·기록 항목: 로그인·인증번호 확인의 시도 제한(IL-532), 중요 기능·보안 실패 처리의 감사 기록(AI-128)
작성자: 최진호
작성일: 2026-11-23
"""

import re

from iron_laws.core.models import Confidence, IronLaw, Severity, Violation
from iron_laws.engine.ast_tools import iter_calls
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.source import SourceFile
from iron_laws.rules.ai_code_common import AiRule
from iron_laws.rules.base import BaseRule
from iron_laws.rules.review_rules import _all_text, _line_of
from iron_laws.standards import mois_ref

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
    r"login_?attempts?|max_?(login_?)?attempts?|fail_?(cnt|count)\b|attempts?_?count|retry_?count|too ?many ?(requests|attempts)|\b429\b|TooManyRequests|account_?lock|isLocked|login_?fail|brute|captcha|express-brute"
)


# 프레임워크·라이브러리 수준의 요청 제한. 프로젝트에 있으면 라우트마다 따지지 않는다
FRAMEWORK_LIMITERS = re.compile(
    r"(?i)\bslowapi\b|flask_limiter|flask-limiter|express-rate-limit|rate-limiter-flexible|\bbucket4j\b|resilience4j[\w.-]*ratelimiter|"
    r"@RateLimiter\b|\bRateLimiter\.create\b|AddRateLimiter|UseRateLimiter|django_ratelimit|django-axes|\baxes\b|express-brute|@nestjs/throttler|ThrottlerModule"
)
LOGIN_ROUTE_TOKENS = frozenset({"login", "signin"})
CHECK_TOKENS = frozenset({"verify", "verification", "certify", "confirm", "check", "validate"})
FACTOR_TOKENS = frozenset({"otp", "totp", "sms", "code", "mfa", "2fa", "auth", "certification", "phone"})
ROUTE_LANGS = frozenset({Lang.PYTHON, Lang.JAVA, Lang.CSHARP, *JS_FAMILY})


def _limited_route_kind(route) -> str | None:
    """시도 제한이 있어야 하는 라우트: 로그인 처리(login)와 인증번호 확인(code)"""
    from iron_laws.engine.routes import _tokens

    if route.method == "GET":
        return None
    words = set(_tokens(route.path)) | set(_tokens(route.handler))
    if words & LOGIN_ROUTE_TOKENS and not words & {"logout", "signout"}:
        return "login"
    if (words & CHECK_TOKENS and words & FACTOR_TOKENS) or words & {"otp", "totp", "mfa", "2fa"} and route.kind == "auth_flow":
        return "code"
    return None


def chain_text(src: SourceFile, node) -> str:
    """핸들러와, 핸들러가 부르는 프로젝트 함수(같은 파일·주입 필드 1단계)의 본문"""
    from iron_laws.engine.taint import resolve_any

    parts = [src.code_of(node)]
    for call in iter_calls(src):
        if not (node.start_byte <= call.node.start_byte and call.node.end_byte <= node.end_byte):
            continue
        for hsrc, fn in resolve_any(src, call.callee, len(call.args)):
            parts.append(hsrc.code_of(fn.node))
    return "\n".join(parts)


class LoginRateLimitRule(BaseRule):
    version = 2
    rule_id = "IL-532"
    name = "로그인 시도 제한(무차별 대입 방어) 부재"
    iron_law = IronLaw.LAW_1
    severity = Severity.MEDIUM
    gov_standard = mois_ref("2-16")
    plain = "로그인이나 인증번호 확인의 시도 횟수를 제한하지 않으면 공격자가 비밀번호·인증번호를 자동으로 수만 번 대입해 계정을 뚫을 수 있습니다."
    how_to_fix = "계정과 IP를 함께 기준으로 실패 횟수를 세어 일정 횟수를 넘으면 잠시 잠그거나 지연시키고(429), 실패 이력을 로그로 남기세요. 계정 단위만 제한하면 남의 계정을 일부러 잠가 버리는 공격에 쓰이므로 IP 기준과 함께 쓰세요. 인증번호는 번호마다 오입력 횟수를 제한하고 넘으면 폐기하세요."

    def check_project(self, project: ProjectContext) -> list[Violation]:
        text = _all_text(project)
        if FRAMEWORK_LIMITERS.search(text):
            return []
        found: list[Violation] = []
        by_path = {f.path.as_posix(): f for f in project.source_files()}
        for route in project.routes():
            kind = _limited_route_kind(route)
            src = by_path.get(route.file)
            if kind is None or src is None or route.node is None:
                continue
            if LIMIT_MARKERS.search(chain_text(src, route.node)):
                continue
            what = "로그인 처리" if kind == "login" else "인증번호 확인"
            found.append(
                self.at_node(
                    src,
                    route.node,
                    f"{route.method} {route.path} {what} 라우트와 그 호출 사슬에 시도 횟수 제한·잠금·레이트 리밋이 보이지 않습니다.",
                    confidence=Confidence.REVIEW,
                )
            )
        # 라우트를 복원하지 못하는 언어(PHP·Go 등)는 프로젝트 전체의 제한 표지와 로그인 처리 코드로 판정한다
        if found or LIMIT_MARKERS.search(text):
            return found
        for src in project.source_files():
            if src.lang in ROUTE_LANGS:
                continue
            code = src.code_text
            for pattern in LOGIN_PATTERNS:
                m = pattern.search(code)
                if m:
                    return [
                        self.at_line(
                            src,
                            _line_of(code, m.start()),
                            "로그인 처리 코드가 있으나 프로젝트 어디에서도 시도 횟수 제한·잠금·레이트 리밋이 보이지 않습니다.",
                            confidence=Confidence.REVIEW,
                        )
                    ]
        return found


# 감사 기록이 있어야 할 중요 기능: 비밀번호 변경·초기화, 계정 생성·잠금, 접속 IP 정책(두 낱말이 함께 있을 때), 정산·출금·이체·권한(한 낱말로)
CRITICAL_WORDS = (
    ({"password", "passwd", "pwd", "pw"}, {"change", "reset", "update", "modify", "init", "initialize"}),
    ({"user", "account", "member", "admin", "operator", "staff"}, {"create", "register", "regist", "add", "delete", "lock", "unlock", "join", "signup"}),
    ({"ip", "whitelist", "allowlist"}, {"policy", "allow", "access", "add", "delete", "update", "register", "regist"}),
)
CRITICAL_SINGLE = frozenset({"withdraw", "withdrawal", "payout", "transfer", "remit", "remittance", "settle", "settlement", "refund", "deposit", "bank", "role", "roles", "permission", "authority", "grant", "revoke", "privilege"})
AUDIT_MARKERS = re.compile(r"(?i)\baudit\w*\s*[.(]|\bsecurityEvent|\bsecurity_?log|securityLogger|getLogger\(\s*[\"']security")
SECURITY_HANDLERS = re.compile(r"\bimplements\s+[^{]*\b(AuthenticationFailureHandler|AccessDeniedHandler|AuthenticationEntryPoint)\b")


class AuditTrailRule(AiRule):
    rule_id = "AI-128"
    name = "중요 기능·보안 실패 처리에 감사 기록 없음"
    iron_law = IronLaw.LAW_3
    severity = Severity.MEDIUM
    plain = "비밀번호 변경, 정산계좌 변경, 출금 신청, 권한 변경 같은 기능에 누가 언제 무엇을 했는지 남기지 않으면, 침해가 일어나도 알아차리지 못하고 사고 뒤에 경위를 밝힐 수 없습니다."
    how_to_fix = "중요 기능과 인증 실패·권한 거부 처리에서 사용자, 대상, 시각, 접속 IP, 결과를 감사 로그(또는 보안 이벤트)로 남기고, 실패가 반복되면 담당자에게 알림이 가게 하세요. 감사 기록 함수는 설정의 audit.markers, 보안 이벤트 타입은 audit.event_types에 적습니다."

    def _evidence(self, text: str) -> bool:
        config = self.config
        markers = [re.escape(m) for m in (config.audit.markers if config is not None else [])]
        if AUDIT_MARKERS.search(text) or (markers and re.search(r"\b(?:" + "|".join(markers) + r")\b", text)):
            return True
        types = [re.escape(e) for e in (config.audit.event_types if config is not None else [])]
        return bool(types) and bool(re.search(r"\bpublish\w*\(\s*(?:new\s+)?(?:" + "|".join(types) + r")\b", text))

    def _critical(self, route) -> bool:
        from iron_laws.engine.routes import _tokens

        extra = [re.compile(p) for p in (self.config.audit.critical_routes if self.config is not None else [])]
        if any(p.search(f"{route.path} {route.handler}") for p in extra):
            return True
        words = set(_tokens(route.path)) | set(_tokens(route.handler))
        return bool(words & CRITICAL_SINGLE) or any(words & a and words & b for a, b in CRITICAL_WORDS)

    def check_project(self, project: ProjectContext) -> list[Violation]:
        found: list[Violation] = []
        by_path = {f.path.as_posix(): f for f in project.source_files()}
        for route in project.routes():
            src = by_path.get(route.file)
            if src is None or route.node is None or route.method == "GET" or not self._critical(route):
                continue
            if self._evidence(chain_text(src, route.node)):
                continue
            found.append(self.at_node(src, route.node, f"{route.method} {route.path} 라우트는 중요 기능인데 감사 기록(감사 로그·보안 이벤트)이 보이지 않습니다.", confidence=Confidence.REVIEW))
        for src in project.by_lang(Lang.JAVA, Lang.KOTLIN):
            if src.is_test:
                continue
            m = SECURITY_HANDLERS.search(src.code_text)
            if m is None or self._evidence(src.code_text):
                continue
            found.append(self.at_line(src, _line_of(src.code_text, m.start()), f"{m.group(1)} 구현에 감사 기록이 보이지 않습니다. 인증 실패·권한 거부를 보안 이벤트로 남기십시오.", confidence=Confidence.REVIEW))
        return found
