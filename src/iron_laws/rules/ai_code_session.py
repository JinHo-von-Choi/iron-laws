"""
오철칙 세션 설정 규칙: 세션 제한시간 정책 위반과 세션 고정 방어 해제(AI-126), Spring 설정 파일을 펴서 읽는 도구
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


def spring_profile(name: str) -> str | None:
    """application.properties → '' (기본), application-prod.yml → 'prod', 그 밖의 파일 → None"""
    m = re.fullmatch(r"(?i)(?:application|bootstrap)(?:-([\w.-]+))?\.(?:properties|ya?ml)", name)
    if m is None:
        return None
    return m.group(1) or ""


def flat_settings(src: SourceFile) -> list[tuple[int, str, str]]:
    """properties·yaml 설정을 (줄, 점으로 이은 키, 값) 목록으로 편다. yaml은 들여쓰기로 부모 키를 잇는다."""
    out: list[tuple[int, str, str]] = []
    if src.kind == "properties":
        for idx, line in enumerate(src.code_lines, start=1):
            m = re.match(r"\s*([\w.\-\[\]]+)\s*[=:]\s*(.*?)\s*$", line)
            if m:
                out.append((idx, m.group(1), m.group(2).strip("'\"")))
        return out
    stack: list[tuple[int, str]] = []
    for idx, line in enumerate(src.code_lines, start=1):
        m = re.match(r"^(\s*)([\w.\-]+)\s*:\s*(.*?)\s*$", line)
        if m is None:
            continue
        indent = len(m.group(1))
        while stack and stack[-1][0] >= indent:
            stack.pop()
        key = ".".join([k for _i, k in stack] + [m.group(2)])
        value = m.group(3).strip("'\"")
        if value:
            out.append((idx, key, value))
        else:
            stack.append((indent, m.group(2)))
    return out


DURATION_UNITS = {"ms": 0.001, "s": 1, "sec": 1, "m": 60, "min": 60, "h": 3600, "d": 86400}


def parse_duration(text: str, default_unit: str = "s") -> float | None:
    """'10m'·'600s'·'PT10M'·'1h'·'3600'(기본 단위) → 초"""
    text = text.strip().strip("'\"")
    iso = re.fullmatch(r"(?i)PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?", text)
    if iso and any(iso.groups()):
        h, m, s = (int(g or 0) for g in iso.groups())
        return h * 3600 + m * 60 + s
    m = re.fullmatch(r"(?i)(\d+(?:\.\d+)?)\s*(ms|sec|min|s|m|h|d)?", text)
    if m is None:
        return None
    return float(m.group(1)) * DURATION_UNITS[(m.group(2) or default_unit).lower()]


def _int_expr(text: str) -> int | None:
    """60 * 60 같은 정수 곱셈식의 값"""
    if not re.fullmatch(r"[\d\s*L]+", text):
        return None
    value = 1
    for part in text.replace("L", "").split("*"):
        part = part.strip()
        if not part.isdigit():
            return None
        value *= int(part)
    return value


SESSION_RENEW = re.compile(r"\.invalidate\(\)|changeSessionId\(|session\.regenerate|req\.session\.regenerate|cycle_key\(|rotate_token\(|session\.clear\(\)|RenewSession|SignInAsync")
SPRING_SECURITY = re.compile(r"SecurityFilterChain|@EnableWebSecurity|WebSecurityConfigurerAdapter")


class SessionPolicyRule(AiRule):
    rule_id = "AI-126"
    name = "세션 제한시간 정책 위반과 세션 고정 방어 해제"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    plain = "세션이 오래 살아 있으면 자리를 비운 사이나 탈취한 세션으로 남이 그대로 쓸 수 있습니다. 로그인 전에 받은 세션 ID를 로그인 뒤에도 그대로 쓰면, 공격자가 미리 심어 둔 세션 ID로 로그인 상태를 가로챌 수 있습니다(세션 고정)."
    how_to_fix = "세션 제한시간을 기관 정책(예: 10분) 이하로 설정하고, 로그인에 성공하면 세션 ID를 새로 발급하세요. 예: request.changeSessionId() / session.regenerate() / Spring Security 기본값(migrateSession) 유지"

    def _limit(self) -> float | None:
        raw = self.config.policies.session_timeout_max if self.config is not None else None
        return parse_duration(raw) if raw else None

    def check(self, src: SourceFile) -> list[Violation]:
        if src.is_test:
            return []
        found: list[Violation] = []
        limit = self._limit()
        for idx, line in enumerate(src.code_lines if src.lang in (Lang.JAVA, Lang.KOTLIN) else [], start=1):
            if re.search(r"sessionFixation\(\)\s*\.\s*none\(\)|sessionFixation\(\s*\w*\s*->\s*\w+\.none\(\)\s*\)|SessionFixationConfigurer::none", line):
                found.append(self.at_line(src, idx, "로그인할 때 세션 ID를 새로 발급하지 않도록(sessionFixation none) 설정했습니다."))
        if limit is None:
            return found
        for line, seconds, label in self._timeouts(src):
            if seconds > limit:
                found.append(self.at_line(src, line, f"{label} 설정값 {int(seconds)}초가 정책 상한 {int(limit)}초보다 깁니다."))
        return found

    def _timeouts(self, src: SourceFile) -> list[tuple[int, float, str]]:
        out: list[tuple[int, float, str]] = []
        if src.kind in ("properties", "yaml") and spring_profile(src.path.name) is not None:
            for line, key, value in flat_settings(src):
                if key in ("server.servlet.session.timeout", "server.session.timeout", "spring.session.timeout"):
                    seconds = parse_duration(value)
                    if seconds is not None:
                        out.append((line, seconds, "세션 제한시간"))
        if src.kind == "xml" and src.path.name == "web.xml":
            for m in re.finditer(r"<session-timeout>\s*(\d+)\s*</session-timeout>", src.text):
                out.append((src.text.count("\n", 0, m.start()) + 1, int(m.group(1)) * 60, "web.xml 세션 제한시간"))
        if src.lang in (Lang.JAVA, Lang.KOTLIN):
            for call in iter_calls(src):
                if call.callee.endswith("setMaxInactiveInterval") and call.args and (value := _int_expr(src.text_of(call.args[0]))) is not None:
                    out.append((call.line, value, "세션 제한시간(setMaxInactiveInterval)"))
        if src.lang is Lang.PYTHON:
            for idx, line in enumerate(src.code_lines, start=1):
                m = re.search(r"\bSESSION_COOKIE_AGE\s*=\s*([\d\s*]+)$", line)
                if m and (value := _int_expr(m.group(1).strip())) is not None:
                    out.append((idx, value, "SESSION_COOKIE_AGE"))
                m = re.search(r"PERMANENT_SESSION_LIFETIME\s*=\s*(?:\w+\.)?timedelta\(([^)]*)\)", line)
                if m:
                    kw = dict(re.findall(r"(\w+)\s*=\s*(\d+)", m.group(1)))
                    seconds = int(kw.get("days", 0)) * 86400 + int(kw.get("hours", 0)) * 3600 + int(kw.get("minutes", 0)) * 60 + int(kw.get("seconds", 0))
                    out.append((idx, seconds, "PERMANENT_SESSION_LIFETIME"))
        if src.lang in JS_FAMILY:
            for call in iter_calls(src):
                if call.callee in ("session", "expressSession", "cookieSession") and call.args:
                    m = re.search(r"maxAge\s*:\s*([\d\s*]+)", src.text_of(call.node))
                    if m and (value := _int_expr(m.group(1).strip())) is not None:
                        out.append((call.line, value / 1000, "세션 쿠키 maxAge"))
        return out

    def check_project(self, project: ProjectContext) -> list[Violation]:
        """자체 로그인: 비밀번호를 대조한 뒤 세션에 사용자를 넣는데 세션 ID를 새로 발급하지 않는 경우(Spring Security를 쓰면 기본값이 새로 발급한다)"""
        from iron_laws.rules.auth_flow import guard_status, login_sinks

        if any(SPRING_SECURITY.search(f.code_text) for f in project.by_lang(Lang.JAVA, Lang.KOTLIN)):
            return []
        found: list[Violation] = []
        by_path = {f.path.as_posix(): f for f in project.source_files()}
        for route in project.routes():
            src = by_path.get(route.file)
            if src is None or route.node is None:
                continue
            for sink, value in login_sinks(src, route.node):
                if guard_status(src, sink, route.node, value) != "checked" or SESSION_RENEW.search(src.text_of(route.node)):
                    continue
                found.append(self.at_node(src, sink, f"{route.method} {route.path} 로그인 처리가 세션 ID를 새로 발급하지 않고 로그인 상태를 저장합니다.", confidence=Confidence.REVIEW))
        return found
