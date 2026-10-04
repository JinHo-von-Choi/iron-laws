"""
제1철칙: 타협과 묵인은 없다 - 보안기능 계열 (행안부 2021 구현단계 2장)
작성자: 최진호
작성일: 2026-10-04
"""
# iron-laws: ignore-file[IL-102,IL-106,IL-114] 취약 알고리즘과 설정을 탐지하는 패턴 정의

import base64
import json
import re

from iron_laws.core.models import Confidence, IronLaw, Severity, Violation
from iron_laws.engine.ast_tools import (
    Call,
    enclosing_function,
    is_literal,
    iter_calls,
    iter_functions,
    string_value,
)
from iron_laws.engine.languages import Lang
from iron_laws.engine.source import SourceFile
from iron_laws.rules.base import BaseRule
from iron_laws.rules.sinks import CS, GO, JAVA, JS, PHP, PY, Sink
from iron_laws.standards import mois_ref

PLACEHOLDER_RE = re.compile(
    r"(?i)changeme|change_me|change-me|your[_-]|example|sample|placeholder|dummy|xxxx|todo|"
    r"<[^>]*>|\*{3,}|\bnone\b|\bnull\b|\bundefined\b|\btrue\b|\bfalse\b|^\s*$|replace[_-]?me|insert[_-]|"
    r"redacted|secret_here|your_|enter_|\$\{|\$\(|^\$\w|\{\{|%\(|%s|\.\.\."
)
ENV_TEMPLATE_RE = re.compile(r"(?i)\.env\.(example|sample|template|dist|defaults)$|\.example$|\.sample$")

SECRET_NAME = (
    r"(?:pass(?:word|wd)?|pwd|secret(?:[_-]?key)?|api[_-]?key|apikey|access[_-]?key|private[_-]?key|"
    r"auth[_-]?token|access[_-]?token|refresh[_-]?token|token|client[_-]?secret|jwt[_-]?secret|"
    r"signing[_-]?key|encryption[_-]?key|conn(?:ection)?[_-]?str(?:ing)?|db[_-]?pass(?:word)?)"
)
ASSIGN_QUOTED_RE = re.compile(
    rf"""(?ix)
    (?P<name>[A-Za-z0-9_.\-\[\]'"]*{SECRET_NAME}[A-Za-z0-9_\-\]'"]*)
    \s*(?::=|[:=]|=>)\s*
    (?:b|r|u|f)?(?P<q>["'])(?P<value>[^"'\n]{{4,}})(?P=q)"""
)
ASSIGN_BARE_RE = re.compile(
    rf"""(?ix)^\s*(?:export\s+|ENV\s+|set\s+)?
    (?P<name>[A-Za-z0-9_.\-]*{SECRET_NAME}[A-Za-z0-9_\-]*)
    \s*[:=]\s*(?P<value>[^\s#"'][^\s#]{{3,}})\s*$"""
)
SIGNATURES: list[tuple[str, re.Pattern[str], Severity]] = [
    ("AWS 액세스 키", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.CRITICAL),
    ("GitHub 토큰", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"), Severity.CRITICAL),
    ("OpenAI/Anthropic API 키", re.compile(r"\bsk-(?:proj-|ant-[a-z0-9]+-)?[A-Za-z0-9_\-]{32,}\b"), Severity.CRITICAL),
    ("Stripe 비밀 키", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b"), Severity.CRITICAL),
    ("Stripe 테스트 키", re.compile(r"\b[sr]k_test_[A-Za-z0-9]{16,}\b"), Severity.HIGH),
    ("Slack 토큰", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), Severity.CRITICAL),
    ("SendGrid API 키", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b"), Severity.CRITICAL),
    ("npm 토큰", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), Severity.CRITICAL),
    ("Hugging Face 토큰", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"), Severity.CRITICAL),
    ("Supabase 비밀 키", re.compile(r"\bsb_secret_[A-Za-z0-9_\-]{20,}\b"), Severity.CRITICAL),
    ("Telegram 봇 토큰", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b"), Severity.HIGH),
    ("평문 개인키", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"), Severity.CRITICAL),
    (
        "자격 증명이 포함된 접속 문자열",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|sqlserver)://[^\s:/@'\"]+:(?P<pw>[^\s@/'\"]{3,})@"),
        Severity.CRITICAL,
    ),
]
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.(eyJ[A-Za-z0-9_\-]{10,})\.[A-Za-z0-9_\-]{10,}\b")
GOOGLE_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")

LITERAL_KEY_SINKS = [
    Sink.of(PY, r"^(jwt\.(encode|decode)|AES\.new|Fernet|hmac\.new|ChaCha20\.new|DES3\.new)$", 1),
    Sink.of(PY, r"^(Fernet|AES\.new|hmac\.new|ChaCha20\.new)$", 0),
    Sink.of(JS, r"^(jwt|jsonwebtoken)\.(sign|verify)$", 1),
    Sink.of(JS, r"^crypto\.(createHmac|createCipheriv|createDecipheriv)$", 1),
    Sink.of(JAVA, r"^newSecretKeySpec$", 0),
    Sink.of(JAVA, r"(^|\.)(HMAC256|HMAC384|HMAC512|signWith|setSigningKey)$", None),
    Sink.of(CS, r"^newSymmetricSecurityKey$|^Encoding\.\w+\.GetBytes$", 0),
    Sink.of(GO, r"^jwt\.New\w+$|^hmac\.New$", None),
    Sink.of(PHP, r"^(JWT::encode|JWT::decode|hash_hmac|openssl_encrypt|openssl_decrypt)$", None),
]
LITERAL_KEY_CALLEE_NEEDS_KEYWORD = re.compile(r"(?i)key|secret|jwt|hmac|crypt|cipher|AES|Symmetric|Fernet")


def _is_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER_RE.search(value))


def _jwt_role(token_payload: str) -> str:
    padded = token_payload + "=" * (-len(token_payload) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, json.JSONDecodeError):  # iron-laws: ignore[IL-301] JWT처럼 보이는 문자열의 본문 해석 실패는 역할 없음으로 취급한다
        return ""
    return str(data.get("role", "")) if isinstance(data, dict) else ""


class HardcodedSecretRule(BaseRule):
    rule_id = "IL-101"
    sensitive_snippet = True
    name = "하드코딩된 패스워드 및 비밀키 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.CRITICAL
    gov_standard = mois_ref("2-6", leak_no=3)
    plain = "비밀번호나 API 키가 코드에 적혀 있으면 코드를 공유하거나 깃허브에 올리는 순간 누구나 그 키로 서비스와 데이터를 쓸 수 있습니다."
    how_to_fix = (
        "비밀 값은 코드에서 빼서 환경변수나 비밀 관리 서비스에서 읽으세요. 이미 올라간 키는 즉시 폐기하고 새로 발급하세요. "
        "예: os.environ['DB_PASSWORD'] / process.env.DB_PASSWORD / System.getenv(\"DB_PASSWORD\")"
    )
    scanned_kinds = {"code", "env", "yaml", "properties", "json", "xml", "shell", "docker", "compose", "actions", "toml", "text"}

    def check(self, src: SourceFile) -> list[Violation]:
        if src.kind not in self.scanned_kinds or ENV_TEMPLATE_RE.search(src.path.name):
            return []
        found: list[Violation] = []
        reported: set[int] = set()
        for idx, line in enumerate(src.code_lines, start=1):
            if not line.strip():
                continue
            hit = self._signature_hit(line) or self._assignment_hit(src, line)
            if hit is None:
                continue
            desc, severity = hit
            reported.add(idx)
            found.append(
                self.at_line(src, idx, f"{desc}이(가) 코드에 직접 적혀 있습니다. 비밀 값을 환경변수나 비밀 저장소로 옮기십시오.", severity=severity)
            )
        found.extend(self._literal_keys(src, reported))
        return found

    def _signature_hit(self, line: str) -> tuple[str, Severity] | None:
        for desc, pattern, severity in SIGNATURES:
            m = pattern.search(line)
            if not m:
                continue
            if "pw" in pattern.groupindex and _is_placeholder(m.group("pw")):
                continue
            return desc, severity
        m = JWT_RE.search(line)
        if m:
            role = _jwt_role(m.group(1))
            if role == "service_role":
                return "Supabase service_role 키(JWT)", Severity.CRITICAL
            if role in ("anon", "authenticated"):
                return None
            return "서명된 JWT 토큰", Severity.HIGH
        return None

    def _assignment_hit(self, src: SourceFile, line: str) -> tuple[str, Severity] | None:
        quoted = ASSIGN_QUOTED_RE.search(line)
        if quoted:
            value = quoted.group("value")
            name = quoted.group("name")
            if _is_placeholder(value) or not self._plausible(name, value):
                return None
            if re.search(r"(?i)os\.getenv|environ|process\.env|getenv|Environment\.|System\.getenv", line):
                return None
            return "하드코딩된 비밀번호/비밀키", Severity.CRITICAL
        if src.kind in ("env", "properties", "yaml", "docker", "compose", "toml", "actions", "shell"):
            bare = ASSIGN_BARE_RE.search(line)
            if bare:
                value = bare.group("value").strip()
                name = bare.group("name")
                if _is_placeholder(value) or not self._plausible(name, value):
                    return None
                return "설정 파일에 적힌 비밀번호/비밀키", Severity.CRITICAL
        return None

    NON_SECRET_VALUES = frozenset(
        {"hashed", "encrypted", "required", "string", "nullable", "password", "secret", "text", "varchar", "hash", "token", "bearer", "basic", "true", "false", "none", "null"}
    )
    NON_SECRET_NAME_SUFFIX = re.compile(r"(?i)(hash|hashed|salt|policy|regex|pattern|prompt|placeholder|label|text|hint|description|message|title|help|error|invalid|required|purpose|identifier|kind|scheme)$")

    @classmethod
    def _plausible(cls, name: str, value: str) -> bool:
        lowered = name.lower()
        if value.lower() in cls.NON_SECRET_VALUES or cls.NON_SECRET_NAME_SUFFIX.search(name):
            return False
        if re.search(r"[()?]|\s\+\s|\+\s*$|^\s*\+|\.value\b", value) or any(ord(ch) > 127 for ch in value):
            return False  # 문자열 결합·코드 조각이거나 한글 등 사람이 읽는 문구
        if re.fullmatch(r"[A-Z][A-Z0-9_]{4,}", value):
            return False  # 환경변수 이름을 담은 상수
        strong = re.search(r"(?i)(pass(word|wd)?|pwd|passcode)$", name) is not None
        if not strong and re.fullmatch(r"[A-Za-z][A-Za-z_\-]{3,}", value) and not re.search(r"\d", value) and len(value) < 24:
            return False  # 숫자·기호 없는 단어형 값은 키·토큰 이름 상수로 본다
        if re.search(r"(?i)(path|file|dir|url|uri|header|name|field|label|type|prefix|length|min|max|policy|regex|pattern|param|placeholder|hint|message|expired?|ttl|timeout|enabled?|required|confirm)", lowered):
            if not re.search(r"(?i)(password|secret|api[_-]?key|private[_-]?key)$", lowered):
                return False
        if re.fullmatch(r"[a-z_]+(\.[a-z_]+)+", value):
            return False
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\(\))?", value) and not re.search(r"\d", value) and len(value) < 8 and "pass" not in lowered:
            return False
        if "token" in lowered and len(value) < 12:
            return False
        if re.search(r"(?i)(key|secret)$", lowered) and len(value) < 8:
            return False
        return True

    def _literal_keys(self, src: SourceFile, already: set[int]) -> list[Violation]:
        found = []
        if src.lang is None:
            return found
        for call in iter_calls(src):
            if call.line in already:
                continue
            for sink in LITERAL_KEY_SINKS:
                if src.lang not in sink.langs or not sink.callee.search(call.callee):
                    continue
                indices = range(len(call.args)) if sink.arg is None else [sink.arg]
                for i in indices:
                    if i >= len(call.args):
                        continue
                    arg = call.args[i]
                    literal = self._literal_in(src, arg)
                    if literal is None or _is_placeholder(literal):
                        continue
                    if call.callee.startswith("Encoding.") and not LITERAL_KEY_CALLEE_NEEDS_KEYWORD.search(src.text_of(call.node.parent) if call.node.parent else ""):
                        continue
                    found.append(
                        self.at_node(src, call.node, f"암호화·서명 키가 {call.callee} 호출에 문자열 상수로 들어가 있습니다.", severity=Severity.CRITICAL)
                    )
                    already.add(call.line)
                    break
                break
        return found

    @staticmethod
    def _literal_in(src: SourceFile, node) -> str | None:
        if node.type in ("string", "string_literal", "interpreted_string_literal", "raw_string_literal", "verbatim_string_literal") and is_literal(node):
            value = string_value(src, node)
            return value if len(value) >= 1 else None
        for child in node.named_children:
            if child.type in ("string", "string_literal", "interpreted_string_literal") and is_literal(child):
                value = string_value(src, child)
                if value:
                    return value
        return None


class HardcodedCredentialCompareRule(BaseRule):
    rule_id = "IL-108"
    sensitive_snippet = True
    name = "비밀번호/토큰을 문자열 상수와 비교하는 인증 코드 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.CRITICAL
    gov_standard = mois_ref("2-6")
    plain = "비밀번호를 코드 안의 글자와 비교해 로그인시키면, 코드를 본 사람은 누구나 그 비밀번호로 들어올 수 있습니다."
    how_to_fix = "계정은 데이터베이스에 저장하고, 비밀번호는 bcrypt/argon2로 해시해 두었다가 해시 검증 함수로 비교하세요. 관리자 기본 계정은 첫 실행 때 강제로 바꾸게 하세요."
    name_part = r"[A-Za-z_\.]*(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|passcode)[A-Za-z_\.\]\[\(\)'\"]*"
    cmp_patterns = [
        re.compile(rf"(?i)(?P<l>{name_part})\s*(?:===?|!==?)\s*(?P<q>[\"'])(?P<v>[^\"']{{1,}})(?P=q)"),
        re.compile(rf"(?i)(?P<q>[\"'])(?P<v>[^\"']{{1,}})(?P=q)\s*(?:===?|!==?)\s*(?P<l>{name_part})"),
        re.compile(rf"(?i)(?P<l>{name_part})\.(?:equals|Equals|equalsIgnoreCase)\(\s*(?P<q>[\"'])(?P<v>[^\"']{{1,}})(?P=q)\s*\)"),
        re.compile(rf"(?i)(?P<q>[\"'])(?P<v>[^\"']{{1,}})(?P=q)\.(?:equals|Equals)\(\s*(?P<l>{name_part})\s*\)"),
        re.compile(rf"(?i)\bstrcmp\(\s*(?P<l>{name_part})\s*,\s*(?P<q>[\"'])(?P<v>[^\"']{{1,}})(?P=q)\s*\)"),
    ]
    skip_names = re.compile(r"(?i)(empty|length|type|name|kind|mode|field|status|state|placeholder|label|prefix)$")

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang is None:
            return []
        found = []
        for idx, line in enumerate(src.code_lines, start=1):
            for pattern in self.cmp_patterns:
                m = pattern.search(line)
                if not m:
                    continue
                value = m.group("v")
                left = m.group("l")
                if self.skip_names.search(left) or _is_placeholder(value) or value.lower() in ("password", "token", "secret", "bearer", "basic"):
                    continue
                if len(value) < 4 or not re.search(r"[A-Za-z0-9]", value):
                    continue
                found.append(self.at_line(src, idx, "비밀번호/토큰을 코드 안의 상수와 직접 비교하고 있습니다. 하드코딩된 인증 우회·기본 계정이 됩니다."))
                break
        return found


class LineRegexRule(BaseRule):
    """주석을 지운 코드 줄에 정규식을 적용하는 규칙의 공통 구현"""

    patterns: list[tuple[re.Pattern[str], str, Severity]] = []
    kinds: set[str] | None = None
    confidence: Confidence = Confidence.CONFIRMED

    def check(self, src: SourceFile) -> list[Violation]:
        if self.kinds is not None and src.kind not in self.kinds:
            return []
        found = []
        for idx, line in enumerate(src.code_lines, start=1):
            for pattern, message, severity in self.patterns:
                if pattern.search(line):
                    found.append(self.at_line(src, idx, message, severity=severity, confidence=self.confidence))
                    break
        return found


class InsecureCryptoRule(BaseRule):
    rule_id = "IL-102"
    name = "취약한 암호 알고리즘 사용 금지"
    iron_law = IronLaw.LAW_1
    severity = Severity.CRITICAL
    gov_standard = mois_ref("2-4")
    plain = "예전에 만들어진 암호·해시 방식(DES, RC4, MD5, SHA-1 등)은 이미 깨져서, 이것으로 보호한 정보는 쉽게 복구되거나 위조됩니다."
    how_to_fix = (
        "대칭키 암호는 AES-GCM(또는 ARIA/SEED), 해시는 SHA-256 이상을 쓰세요. 비밀번호 저장에는 해시가 아니라 bcrypt/argon2/scrypt를 쓰세요. "
        "예: hashlib.sha256 / crypto.createHash('sha256') / Cipher.getInstance(\"AES/GCM/NoPadding\")"
    )
    cipher_re = re.compile(
        r"""\b(?:DES|RC2|RC4|RC5|RC6|ARCFOUR|ARC4)\b|DESCryptoServiceProvider|RC2CryptoServiceProvider|Crypto\.Cipher\.(?:DES|ARC4)|crypto/(?:des|rc4)\b"""
    )
    hash_re = re.compile(r"(?i)\b(?:md4|md5|sha-?1)\b|MD5CryptoServiceProvider|SHA1Managed|SHA1CryptoServiceProvider|MD5Cng|SHA1Cng")
    ecb_re = re.compile(r"(?i)AES/ECB|MODE_ECB|CipherMode\.ECB|aes-\d{3}-ecb")
    quoted_cipher_re = re.compile(r"[\"'](?:DES|RC2|RC4|RC5|RC6|ARCFOUR|ARC4)(?:[/_\-][A-Za-z0-9/_\-]*)?[\"']", re.IGNORECASE)
    security_context = re.compile(r"(?i)pass(word|wd)?|pwd|secret|token|sign|auth|credential|salt|hmac|session|cookie|jwt|login|hash_password|digest")
    skip_line = re.compile(r"usedforsecurity\s*=\s*False")

    @staticmethod
    def _function_name_at(src: SourceFile, line_number: int) -> str:
        best = ""
        for fn in iter_functions(src):
            if fn.start_line <= line_number <= fn.end_line:
                best = fn.name
        return best

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        lines = src.code_lines
        bare_lines = src.code_text_without_strings.splitlines() if src.root is not None else lines
        for idx, line in enumerate(lines, start=1):
            if self.skip_line.search(line):
                continue
            bare = bare_lines[idx - 1] if idx - 1 < len(bare_lines) else line
            if self.cipher_re.search(bare) or self.quoted_cipher_re.search(line):
                found.append(self.at_line(src, idx, "가이드가 취약 알고리즘으로 명시한 대칭키 암호(DES/RC2/RC4/RC5/RC6)가 사용됩니다. AES 등으로 교체하십시오."))
            elif self.ecb_re.search(line):
                found.append(self.at_line(src, idx, "ECB 운용 모드는 같은 평문이 같은 암호문이 되어 패턴이 노출됩니다 (CWE-327). GCM 또는 CBC+인증으로 교체하십시오."))
            elif self.hash_re.search(line):
                if self.security_context.search(line + " " + self._function_name_at(src, idx)):
                    found.append(self.at_line(src, idx, "가이드가 취약 알고리즘으로 명시한 해시(MD4/MD5/SHA-1)가 보안 용도로 보이는 곳에 쓰입니다. SHA-256 이상으로 교체하십시오."))
                else:
                    found.append(
                        self.at_line(
                            src,
                            idx,
                            "취약한 해시(MD4/MD5/SHA-1)가 사용됩니다. 보안 용도가 아닌 체크섬이라면 사유를 남기고, 아니라면 SHA-256 이상으로 교체하십시오.",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.REVIEW,
                        )
                    )
        return found


class KeyLengthRule(BaseRule):
    rule_id = "IL-103"
    name = "충분하지 않은 키 길이 사용 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.HIGH
    gov_standard = mois_ref("2-7")
    plain = "암호 키가 너무 짧으면 요즘 컴퓨터로 무차별 대입해 풀 수 있습니다."
    how_to_fix = "RSA/DSA는 2048비트 이상(권장 3072), 타원곡선은 256비트 이상, AES는 128비트 이상 키를 쓰세요."
    patterns = [
        re.compile(r"key_size\s*=\s*(\d+)"),
        re.compile(r"RSA\.generate\(\s*(\d+)"),
        re.compile(r"modulusLength\s*:\s*(\d+)"),
        re.compile(r"KeyPairGenerator[^;\n]*|\.initialize\(\s*(\d+)"),
        re.compile(r"new\s+RSACryptoServiceProvider\(\s*(\d+)"),
        re.compile(r"RSA\.Create\(\s*(\d+)"),
        re.compile(r"rsa\.GenerateKey\([^,]+,\s*(\d+)"),
        re.compile(r"genrsa\b[^\n]*?\b(\d{3,4})\b|-newkey\s+rsa:(\d+)"),
        re.compile(r"RSA_generate_key(?:_ex)?\([^,]+,\s*(\d+)"),
    ]

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        text_lines = src.code_lines
        for idx, line in enumerate(text_lines, start=1):
            if "RSA" not in line.upper() and "KEY" not in line.upper() and "modulus" not in line and "genrsa" not in line:
                continue
            for pattern in self.patterns:
                for m in pattern.finditer(line):
                    bits = [g for g in m.groups() if g and g.isdigit()]
                    if bits and 256 <= int(bits[0]) < 2048 and int(bits[0]) % 8 == 0:
                        found.append(self.at_line(src, idx, f"{bits[0]}비트 키가 사용됩니다. RSA/DSA는 2048비트 이상이어야 합니다."))
                        break
                else:
                    continue
                break
        return found


class WeakRandomRule(BaseRule):
    rule_id = "IL-104"
    name = "보안 용도의 예측 가능한 난수 사용 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.HIGH
    gov_standard = mois_ref("2-8")
    plain = "일반 난수 함수는 다음 값을 예측할 수 있어서, 이걸로 만든 토큰·인증번호·비밀번호는 공격자가 맞출 수 있습니다."
    how_to_fix = "보안 용도에는 암호학적 난수를 쓰세요. Python: secrets.token_urlsafe() / JS: crypto.randomBytes() / Java: SecureRandom / C#: RandomNumberGenerator / PHP: random_bytes()"
    sinks = [
        Sink.of(PY, r"^random\.(random|randint|randrange|choice|choices|sample|getrandbits|uniform|shuffle)$"),
        Sink.of(JS, r"^Math\.random$"),
        Sink.of(JAVA, r"^newRandom$|^Math\.random$|ThreadLocalRandom\.current$"),
        Sink.of(CS, r"^newRandom$|^Random\.Shared\.\w+$"),
        Sink.of(GO, r"^rand\.(Int|Intn|Int31|Int31n|Int63|Int63n|Read|Float64|Uint32|Uint64|Seed)$"),
        Sink.of(PHP, r"^(rand|mt_rand|uniqid|lcg_value|shuffle|str_shuffle|array_rand)$"),
        Sink.of(frozenset({Lang.C, Lang.CPP}), r"^(rand|random|srand)$"),
    ]
    context_re = re.compile(
        r"(?i)token|secret|passw|pwd|otp|nonce|\bsalt|session|csrf|api_?key|apikey|auth|verif\w*|reset\w*|\bpin\b|captcha|invite|activation|credential|signature|iv\b|temp_?pass|sid\b"
    )

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.lang is Lang.GO and "math/rand" not in src.text:
            return found
        for call in iter_calls(src):
            matched = any(src.lang in s.langs and s.callee.search(call.callee) for s in self.sinks)
            if not matched:
                continue
            if src.lang is Lang.JAVA and call.callee == "newRandom" and "SecureRandom" in src.text_of(call.node):
                continue
            if self._security_context(src, call):
                found.append(self.at_node(src, call.node, f"{call.callee}는 예측 가능한 난수입니다. 토큰·인증번호·키 생성에는 암호학적 난수를 쓰십시오."))
        return found

    def _security_context(self, src: SourceFile, call: Call) -> bool:
        node = call.node
        stmt = node
        while stmt.parent is not None and not stmt.type.endswith(("_statement", "_declaration", "declaration", "_definition", "_item")):
            stmt = stmt.parent
        if self.context_re.search(src.text_of(stmt)[:400]):
            return True
        fn = enclosing_function(node, src.lang)
        if fn is not None:
            name = fn.child_by_field_name("name")
            if name is not None and self.context_re.search(src.text_of(name)):
                return True
        return False


class JwtVerificationRule(LineRegexRule):
    rule_id = "IL-105"
    name = "전자서명(토큰) 검증 생략 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.HIGH
    gov_standard = mois_ref("2-10")
    plain = "토큰의 서명을 확인하지 않으면 누구나 내용을 고쳐 관리자 토큰을 만들어 낼 수 있습니다."
    how_to_fix = "서명을 반드시 검증하고 허용 알고리즘을 명시하세요. 예: jwt.decode(token, key, algorithms=['HS256']) / jwt.verify(token, secret, {algorithms: ['HS256']})"
    patterns = [
        (re.compile(r"verify_signature['\"]?\s*[:=]\s*(False|false)|verify\s*=\s*False\b.*jwt|jwt\.decode\([^)]*verify\s*=\s*False"), "JWT 서명 검증을 끕니다.", Severity.CRITICAL),
        (re.compile(r"algorithms\s*[:=]\s*\[\s*['\"]none['\"]|alg['\"]?\s*[:=]\s*['\"]none['\"]|algorithm\s*=\s*['\"]none['\"]", re.IGNORECASE), "서명 알고리즘 none을 허용합니다.", Severity.CRITICAL),
        (re.compile(r"ignoreExpiration\s*:\s*true|verify_exp['\"]?\s*[:=]\s*(False|false)|ValidateLifetime\s*=\s*false"), "토큰 만료 검증을 끕니다.", Severity.HIGH),
        (re.compile(r"ValidateIssuerSigningKey\s*=\s*false|RequireSignedTokens\s*=\s*false"), "토큰 서명 키 검증을 끕니다.", Severity.CRITICAL),
        (re.compile(r"\bParseUnverified\b|\bJwts\.parser\(\)(?:(?!parseClaimsJws|parseSignedClaims).)*\.parse\("), "서명을 검증하지 않고 토큰을 파싱합니다.", Severity.HIGH),
    ]


class TlsVerificationRule(LineRegexRule):
    rule_id = "IL-106"
    name = "인증서(TLS) 유효성 검증 비활성화 탐지"
    iron_law = IronLaw.LAW_1
    severity = Severity.HIGH
    gov_standard = mois_ref("2-11")
    plain = "HTTPS 인증서 검사를 끄면 중간 공격자가 통신 내용을 훔치거나 바꿀 수 있습니다. 개발 중에만 끈다고 해도 그대로 배포되는 경우가 많습니다."
    how_to_fix = "인증서 검증을 켜 두세요. 사설 인증서는 검증을 끄지 말고 CA 인증서를 신뢰 저장소에 추가하세요. (verify=True, rejectUnauthorized: true 등)"
    patterns = [
        (re.compile(r"\bverify\s*=\s*False\b|ssl\._create_unverified_context|\bCERT_NONE\b|check_hostname\s*=\s*False"), "인증서 검증을 끕니다.", Severity.HIGH),
        (re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['\"]?0|strictSSL\s*:\s*false|strict-ssl\s+false"), "인증서 검증을 끕니다.", Severity.HIGH),
        (re.compile(r"ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|TrustAllStrategy|TrustSelfSignedStrategy|setHostnameVerifier\([^)]*->\s*true|checkServerTrusted\([^)]*\)\s*(throws[^{]*)?\{\s*\}"), "모든 인증서·호스트를 신뢰합니다.", Severity.HIGH),
        (re.compile(r"ServerCertificateValidationCallback\s*\+?=.*true|DangerousAcceptAnyServerCertificateValidator|CheckCertificateRevocationList\s*=\s*false"), "모든 서버 인증서를 신뢰합니다.", Severity.HIGH),
        (re.compile(r"InsecureSkipVerify\s*:\s*true"), "TLS 인증서 검증을 건너뜁니다.", Severity.HIGH),
        (re.compile(r"CURLOPT_SSL_VERIFY(PEER|HOST)\s*,\s*(false|0)|['\"]verify['\"]\s*=>\s*false|SSL_VERIFY_NONE"), "SSL 검증을 끕니다.", Severity.HIGH),
        (re.compile(r"danger_accept_invalid_(certs|hostnames)\(\s*true\s*\)"), "잘못된 인증서를 허용합니다.", Severity.HIGH),
        (re.compile(r"\bcurl\b[^|\n]*\s(-k|--insecure)\b|--no-check-certificate|sslVerify\s+false|http\.sslVerify\s*=\s*false"), "명령줄에서 인증서 검증을 끕니다.", Severity.MEDIUM),
    ]


class UnsaltedPasswordHashRule(BaseRule):
    rule_id = "IL-107"
    name = "솔트 없이 일방향 해시로 비밀번호 저장"
    iron_law = IronLaw.LAW_1
    severity = Severity.HIGH
    gov_standard = mois_ref("2-14")
    plain = "비밀번호를 그냥 해시(SHA-256 등)해서 저장하면, 유출 시 미리 계산된 표로 대부분 즉시 복구됩니다."
    how_to_fix = "비밀번호 전용 해시를 쓰세요. Python: bcrypt/argon2-cffi / Node: bcrypt, argon2 / Java: BCryptPasswordEncoder / C#: PasswordHasher<T> / PHP: password_hash()"
    sinks = [
        Sink.of(PY, r"^hashlib\.(md5|sha1|sha224|sha256|sha384|sha512|blake2\w+)$", None),
        Sink.of(JS, r"createHash\(.*\)\.update$", None),
        Sink.of(JAVA, r"(^|\.)digest$", None),
        Sink.of(CS, r"(^|\.)ComputeHash$", None),
        Sink.of(GO, r"^(sha256|sha512|sha1|md5)\.(Sum\w*|New)$", None),
        Sink.of(PHP, r"^(md5|sha1|hash|crc32)$", None),
    ]
    pass_re = re.compile(r"(?i)pass(word|wd)?|pwd")
    safe_re = re.compile(r"(?i)salt|bcrypt|argon|scrypt|pbkdf2|PasswordHasher|password_hash|Rfc2898|hmac")

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        for call in iter_calls(src):
            if not any(src.lang in s.langs and s.callee.search(call.callee) for s in self.sinks):
                continue
            arg_text = " ".join(src.text_of(a) for a in call.args)
            call_text = src.text_of(call.node)
            if not self.pass_re.search(arg_text):
                continue
            if src.lang is Lang.PYTHON and call.node.parent is not None and call.node.parent.type == "call":
                pass
            window = src.text_of(call.node.parent) if call.node.parent is not None else call_text
            fn = enclosing_function(call.node, src.lang)
            scope_text = src.text_of(fn) if fn is not None else window
            if self.safe_re.search(scope_text):
                continue
            found.append(self.at_node(src, call.node, "비밀번호를 솔트 없이 일반 해시 함수로 처리합니다. bcrypt/argon2 같은 비밀번호 전용 해시를 쓰십시오."))
        return found


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


SECRETS_CRYPTO_RULES: list[type[BaseRule]] = [
    HardcodedSecretRule,
    InsecureCryptoRule,
    KeyLengthRule,
    WeakRandomRule,
    JwtVerificationRule,
    TlsVerificationRule,
    UnsaltedPasswordHashRule,
    HardcodedCredentialCompareRule,
    PlaintextTransportRule,
    WeakPasswordPolicyRule,
    CommentSensitiveInfoRule,
    SensitiveCookieRule,
    DownloadAndExecuteRule,
    PermissionRule,
]
