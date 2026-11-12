"""
오철칙 정보 노출·전송 규칙: 평문 전송(IL-109), 약한 비밀번호 정책(IL-110), 주석 속 민감 정보(IL-111), 쿠키 보안 속성(IL-112), 내려받아 실행(IL-113), 과도한 권한(IL-114)
작성자: 최진호
작성일: 2026-11-12
"""
# iron-laws: ignore-file[IL-114] 과도한 권한 설정을 탐지하는 패턴 정의

import re

from iron_laws.core.models import Confidence, IronLaw, Severity, Violation
from iron_laws.engine.ast_tools import (
    is_literal,
    iter_calls,
    string_value,
)
from iron_laws.engine.source import SourceFile
from iron_laws.rules.base import BaseRule
from iron_laws.rules.secrets_crypto import SECRET_NAME, SIGNATURES, LineRegexRule, _is_placeholder
from iron_laws.rules.sinks import CS, GO, JAVA, JS, PHP, PY, Sink
from iron_laws.standards import mois_ref


class PlaintextTransportRule(BaseRule):
    rule_id = "IL-109"
    name = "암호화되지 않은 통신 주소 사용 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.MEDIUM
    gov_standard = mois_ref("2-5")
    plain = "http:// 처럼 암호화되지 않은 주소로 통신하면 같은 와이파이/중간 장비에서 비밀번호와 개인정보가 그대로 보입니다."
    how_to_fix = "외부 서비스 주소는 https://(웹소켓은 wss://)로 바꾸세요. 내부망이라도 인증 정보가 오가면 TLS를 쓰세요."
    url_re = re.compile(r"""^(?P<scheme>http|ftp|telnet|ws)://(?P<host>[^/:\s?#]+)""", re.IGNORECASE)
    safe_hosts = re.compile(
        r"(?i)^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal|.*\.local|.*\.localhost|.*\.test|.*\.example|example\.(com|org|net)|"
        r"www\.w3\.org|schemas?\..*|.*\.xmlsoap\.org|java\.sun\.com|xmlns.*|maven\.apache\.org|www\.apache\.org|.*\.svg|purl\.org|json-schema\.org|"
        r"ns\.adobe\.com|xml\.org|www\.opengis\.net|www\.springframework\.org|.*\.internal|\$.*|\{.*|<.*)$"
    )

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang is None or src.root is None:
            return []
        from iron_laws.engine.ast_tools import is_string_node

        found = []
        for node in src.nodes:
            if not is_string_node(node) or not is_literal(node):
                continue
            value = string_value(src, node)
            m = self.url_re.match(value)
            if not m or self.safe_hosts.match(m.group("host")):
                continue
            if re.search(r"(?i)xmlns|schema|namespace|doctype|dtd", src.snippet_at(src.line_of(node))):
                continue
            found.append(self.at_node(src, node, f"{m.group('scheme').lower()}:// 로 암호화되지 않은 통신 주소를 사용합니다 ({m.group('host')}).", confidence=Confidence.REVIEW))
        return found


class WeakPasswordPolicyRule(BaseRule):
    rule_id = "IL-110"
    name = "취약한 비밀번호 허용 (짧은 최소 길이) 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.MEDIUM
    gov_standard = mois_ref("2-9")
    plain = "비밀번호 최소 길이가 너무 짧으면 쉽게 추측되거나 대입으로 뚫립니다."
    how_to_fix = "비밀번호는 최소 8자(영문·숫자·특수문자 조합이면 8자, 아니면 10자 이상)를 요구하고, 흔한 비밀번호 목록은 차단하세요."
    patterns = [
        re.compile(r"(?i)(?:min_?length|minlength|MinimumLength|RequiredLength|minLen|min_len)\s*[:=]\s*(\d+)"),
        re.compile(r"(?i)pass(?:word|wd)?\w*(?:\.|\()?\s*(?:len|length|size)\W{0,4}\s*(?:>=|>)\s*(\d+)"),
        re.compile(r"(?i)len\(\s*\w*pass(?:word|wd)?\w*\s*\)\s*(?:>=|>)\s*(\d+)"),
    ]

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang is None:
            return []
        found = []
        lines = src.code_lines
        for idx, line in enumerate(lines, start=1):
            window = " ".join(lines[max(0, idx - 3) : idx + 2])
            if not re.search(r"(?i)pass(word|wd)?|pwd", window):
                continue
            for pattern in self.patterns:
                m = pattern.search(line)
                if m and 0 < int(m.group(1)) < 8:
                    found.append(self.at_line(src, idx, f"비밀번호 최소 길이가 {m.group(1)}자로 짧습니다.", confidence=Confidence.REVIEW))
                    break
        return found


class CommentSensitiveInfoRule(BaseRule):
    rule_id = "IL-111"
    sensitive_snippet = True
    name = "주석 안의 시스템 주요정보 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.MEDIUM
    gov_standard = mois_ref("2-13")
    plain = "주석은 배포된 파일에 그대로 남습니다. 주석에 적어 둔 비밀번호·내부 주소는 코드를 보는 누구에게나 보입니다."
    how_to_fix = "주석에서 비밀번호, 키, 내부 IP, 접속 문자열을 지우세요. 이미 저장소에 올라갔다면 해당 값을 폐기하고 새로 발급하세요."
    secret_re = re.compile(rf"(?i)\b{SECRET_NAME}\b\s*[:=]\s*[\"']?(?P<v>[^\s\"']{{4,}})")
    ip_re = re.compile(r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b")

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        entries: list[tuple[int, str]] = []
        if src.root is not None:
            for node in src.comment_nodes:
                text = src.text_of(node)
                for offset, part in enumerate(text.splitlines() or [text]):
                    entries.append((node.start_point[0] + 1 + offset, part))
        elif src.kind in ("shell", "yaml", "env", "properties", "docker", "compose", "actions"):
            for idx, line in enumerate(src.lines, start=1):
                m = re.search(r"(?:^|\s)#(.*)$", line)
                if m:
                    entries.append((idx, m.group(1)))
        for line_no, text in entries:
            sig = next((d for d, p, _ in SIGNATURES if p.search(text)), None)
            if sig:
                found.append(self.at_line(src, line_no, f"주석에 {sig}이(가) 남아 있습니다.", severity=Severity.HIGH))
                continue
            m = self.secret_re.search(text)
            if m and not _is_placeholder(m.group("v")) and not re.fullmatch(r"[A-Za-z_]+", m.group("v")):
                found.append(self.at_line(src, line_no, "주석에 비밀번호/키로 보이는 값이 남아 있습니다."))
            elif self.ip_re.search(text):
                found.append(self.at_line(src, line_no, "주석에 내부망 IP 주소가 남아 있습니다 (누출금지 대상정보 제1호 관련).", severity=Severity.LOW))
        return found


class SensitiveCookieRule(BaseRule):
    version = 2
    rule_id = "IL-112"
    name = "쿠키에 중요정보 저장 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.HIGH
    gov_standard = mois_ref("2-12")
    plain = "쿠키는 사용자의 PC에 파일로 남습니다. 비밀번호나 개인정보를 쿠키에 담으면 PC가 털릴 때 함께 유출됩니다."
    how_to_fix = "쿠키에는 서버가 발급한 무작위 세션 ID만 담고, 중요정보는 서버 세션이나 DB에 두세요."
    sinks = [
        Sink.of(PY, r"(^|\.)set_cookie$", None),
        Sink.of(JS, r"(^|\.)cookie$", None),
        Sink.of(JAVA, r"^newCookie$", None),
        Sink.of(CS, r"Cookies\.Append$|^newHttpCookie$", None),
        Sink.of(GO, r"^http\.SetCookie$|^newhttp\.Cookie$", None),
        Sink.of(PHP, r"^setcookie$", None),
    ]
    sensitive = re.compile(r"(?i)pass(word|wd)?|pwd|secret|ssn|card_?(no|number)|jumin|resident|주민|cvv")

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        for call in iter_calls(src):
            if not any(src.lang in s.langs and s.callee.search(call.callee) for s in self.sinks):
                continue
            if call.callee.endswith(".cookie") and not call.callee.startswith(("res.", "response.", "reply.")):
                continue
            if self.sensitive.search(" ".join(src.text_of(a) for a in call.args[:2])):
                found.append(self.at_node(src, call.node, "쿠키에 비밀번호·개인정보로 보이는 값을 저장합니다."))
        return found


class DownloadAndExecuteRule(LineRegexRule):
    rule_id = "IL-113"
    name = "무결성 검사 없는 코드 다운로드 및 실행 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.MEDIUM
    gov_standard = mois_ref("2-15")
    plain = "인터넷에서 받은 스크립트를 내용 확인 없이 바로 실행하면, 그 서버가 해킹되거나 주소가 바뀌었을 때 내 서버가 같이 감염됩니다."
    how_to_fix = "다운로드한 파일은 해시(sha256sum) 또는 서명을 검증한 뒤 실행하고, 버전을 고정하세요. 가능하면 패키지 매니저를 쓰세요."
    patterns = [
        (re.compile(r"\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b"), "다운로드한 스크립트를 검증 없이 셸로 실행합니다.", Severity.MEDIUM),
        (re.compile(r"(?i)(iex|Invoke-Expression)\s*\(?\s*(iwr|Invoke-WebRequest|\(New-Object\s+Net\.WebClient\))"), "다운로드한 코드를 검증 없이 실행합니다.", Severity.MEDIUM),
        (re.compile(r"\bexec\(\s*(requests|urllib\.request|urlopen)\b|\beval\(\s*await\s+fetch|\beval\(\s*(await\s+)?(axios|got)\."), "네트워크에서 받은 문자열을 코드로 실행합니다.", Severity.HIGH),
    ]


class PermissionRule(LineRegexRule):
    rule_id = "IL-114"
    name = "중요 자원에 대한 잘못된 권한 설정 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.HIGH
    gov_standard = mois_ref("2-3")
    plain = "파일을 '누구나 읽고 쓰고 실행' 가능하게 열어 두면 같은 서버의 다른 프로그램이나 침입자가 내용을 바꿔 시스템을 장악할 수 있습니다."
    how_to_fix = "필요한 최소 권한만 주세요. 파일은 640/600, 실행 파일은 750을 쓰고, 클라우드 저장소는 public-read를 쓰지 마세요."
    patterns = [
        (re.compile(r"\bchmod\s+(-R\s+)?0?777\b|\bchmod\s+(-R\s+)?a\+rwx\b"), "chmod 777로 모든 사용자에게 전체 권한을 줍니다.", Severity.HIGH),
        (re.compile(r"os\.chmod\([^,]+,\s*0o?777\)|os\.(makedirs|mkdir)\([^)]*mode\s*=\s*0o?777"), "파일 권한을 777로 설정합니다.", Severity.HIGH),
        (re.compile(r"\bumask\(\s*0\s*\)|setWritable\(\s*true\s*,\s*false\s*\)|setReadable\(\s*true\s*,\s*false\s*\)|rwxrwxrwx"), "모든 사용자에게 권한을 열어 둡니다.", Severity.HIGH),
        (re.compile(r"os\.(Chmod|MkdirAll|OpenFile|Mkdir)\([^)]*0o?777"), "파일 권한을 0777로 설정합니다.", Severity.HIGH),
        (re.compile(r"""\bACL['"]?\s*[:=]\s*['"]public-read(-write)?['"]|\ballUsers\b|\bAllUsers\b|public-read-write"""), "저장소 객체를 누구나 읽을 수 있게 공개합니다.", Severity.HIGH),
        (re.compile(r"mkdir\s+-m\s+0?777|install\s+-m\s+0?777"), "디렉터리를 777 권한으로 만듭니다.", Severity.HIGH),
    ]
