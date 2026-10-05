"""
AI 공격면 점검 계열(AIA): AI 에이전트·LLM 앱·AI 코딩 도구를 겨냥한 공격이 저장소에 남기는 흔적을 점검한다.
근거는 OWASP Top 10 for LLM Applications 2025와 OWASP Top 10 for Agentic Applications 2026이며, 행안부 항목이 아닌 오철칙 자체 규칙이다.
정적 점검이므로 모델의 실제 동작을 시험하지 않는다. 호모글리프(모양이 같은 다른 글자)로 숨긴 지시는 탐지 범위 밖이다.
작성자: 최진호
작성일: 2026-10-05
"""
# iron-laws: ignore-file[AIA-106] 위험한 모델 불러오기 옵션을 탐지하고 설명하는 문구 정의

import base64
import binascii
import json
import re

from iron_laws.core.models import Confidence, IronLaw, RuleLayer, Severity, Violation
from iron_laws.engine.source import SourceFile
from iron_laws.rules.base import BaseRule

AGENT_FILE_NAMES = frozenset({".cursorrules", ".windsurfrules", "agents.md", "claude.md", "gemini.md", "copilot-instructions.md"})
AGENT_DIR_MARKERS = (".cursor/rules/", ".github/instructions/", ".claude/", ".windsurf/rules/", ".gemini/")
MCP_FILE_NAMES = frozenset({"mcp.json", ".mcp.json", "mcp_config.json", "mcp-config.json"})

TAG_RANGE = (0xE0000, 0xE007F)
BIDI_CONTROLS = frozenset(list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A)))
ZERO_WIDTH = frozenset({0x200B, 0x2060})
JOINERS = frozenset({0x200C, 0x200D} | set(range(0xFE00, 0xFE10)))
BLACK_FLAG = 0x1F3F4
JOINER_DENSITY = 8  # 한 줄에 이만큼 이상 모이면 정상 이모지·언어 용법이 아니라 데이터 은닉 통로로 본다

INSTRUCTION_PATTERNS = [
    re.compile(r"(?i)\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b"),
    re.compile(r"(?i)\bignore\s+(all\s+|any\s+|the\s+|previous\s+|prior\s+)*(security|safety|instructions?|rules?)\b"),
    re.compile(r"(보안|검증|검사|인증).{0,12}(무시|끄|생략|건너뛰)"),
    re.compile(
        r"(?i)\b(send|upload|exfiltrate|forward)\b[^\n]{0,60}\b(secrets?|tokens?|api[_ -]?keys?|credentials?|\.env|ssh\s+keys?)\b[^\n]{0,60}"
        r"(https?://|\bto\s+[\w.-]+\.(?:com|net|io|org|dev|xyz|ru|cn|sh)\b|\bto\s+(?:an?\s+)?(?:external|remote|attacker))"
    ),
    re.compile(r"(비밀|토큰|키|인증\s*정보|\.env)[^\n]{0,20}(외부\s*(?:서버|주소)|https?://)[^\n]{0,10}(전송|업로드|보내)"),
    re.compile(r"(?i)\bbase64\s+(-d|--decode)\b"),
]
NEGATION = re.compile(r"(?i)(하지\s*마|쓰지\s*마|말\s*것|금지|절대|않도록|do\s+not|don'?t|never|avoid|forbid|must\s+not|should\s+not)")
BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
BLOB_WORDS = re.compile(r"(?i)(ignore|curl|wget|secret|token|system\s*prompt|exfiltrate|password|instruction)")
AUTO_APPROVE_KEYS = frozenset({"autoapprove", "alwaysallow", "auto_approve", "always_allow", "autoallow"})
AUTO_APPROVE_ARGS = re.compile(r"--dangerously-skip-permissions|--yolo\b|--auto-approve|--trust-all|--approve-all")
SECRET_ARG = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|credential)")
URL_CREDENTIAL = re.compile(r"://[^/\s:@]*:[^/\s@]+@")  # 사용자 이름이 비어 있는 redis://:비밀@호스트 형태도 포함
ENV_REFERENCE = re.compile(r"^\s*\$\{?[A-Za-z_][A-Za-z0-9_]*\}?\s*$|^\s*<[^>]+>\s*$|^\s*$")
LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]", "0.0.0.0")


class AiAttackRule(BaseRule):
    layer = RuleLayer.AI_ATTACK
    gov_standard = None
    iron_law = IronLaw.LAW_5


def _is_agent_rule_file(src: SourceFile) -> bool:
    path = src.path.as_posix().lower()
    if src.path.name.lower() in AGENT_FILE_NAMES:
        return True
    return any(marker in f"/{path}" for marker in AGENT_DIR_MARKERS) and src.kind in ("doc", "yaml", "json", "text")


class AgentRuleFileRule(AiAttackRule):
    rule_id = "AIA-101"
    name = "AI 코딩 도구 규칙 파일에 숨은 지시 탐지"
    severity = Severity.HIGH
    plain = (
        "AI 코딩 도구는 `.cursorrules`, `AGENTS.md`, `CLAUDE.md` 같은 규칙 파일을 믿고 그대로 따릅니다. "
        "사람 눈에는 보이지 않는 글자(보이지 않는 유니코드)로 지시를 숨겨 두면 AI가 몰래 악성 코드를 끼워 넣거나 비밀을 밖으로 보낼 수 있고, 코드 리뷰에서도 보이지 않습니다. "
        "(참고: OWASP LLM01 프롬프트 주입, OWASP 에이전트 ASI01. '규칙 파일 백도어' 공격)"
    )
    how_to_fix = (
        "해당 글자를 지우고 파일을 편집기에서 다시 저장하세요. 규칙 파일은 출처가 확실한 것만 쓰고, 코드 리뷰에서 규칙 파일 변경을 따로 확인하세요. "
        "보이지 않는 글자는 `grep -nP '[\\x{200B}\\x{2060}\\x{202A}-\\x{202E}\\x{2066}-\\x{2069}]'` 같은 명령으로 찾을 수 있습니다."
    )

    def applies_to(self, src: SourceFile) -> bool:
        return _is_agent_rule_file(src)

    def check(self, src: SourceFile) -> list[Violation]:
        if not _is_agent_rule_file(src):
            return []
        found: list[Violation] = []
        for number, line in enumerate(src.text.split("\n"), start=1):
            found.extend(self._hidden_characters(src, number, line, first_line=number == 1))
            found.extend(self._instructions(src, number, line))
            found.extend(self._encoded_blob(src, number, line))
        return found[:50]

    def _hidden_characters(self, src: SourceFile, number: int, line: str, first_line: bool) -> list[Violation]:
        found: list[Violation] = []
        points = [ord(ch) for ch in line]
        tags = [i for i, cp in enumerate(points) if TAG_RANGE[0] <= cp <= TAG_RANGE[1]]
        if tags:
            runs: list[list[int]] = []
            for i in tags:
                if runs and i == runs[-1][-1] + 1:
                    runs[-1].append(i)
                else:
                    runs.append([i])
            for run in runs:
                flag_sequence = run[0] > 0 and points[run[0] - 1] == BLACK_FLAG and points[run[-1]] == TAG_RANGE[1]
                if flag_sequence:
                    continue  # 국기 이모지(잉글랜드·스코틀랜드·웨일스)의 정상 구성
                hidden = "".join(chr(points[i] - TAG_RANGE[0]) for i in run if 0x20 <= points[i] - TAG_RANGE[0] < 0x7F)
                detail = f" 숨은 문구: {hidden[:80]!r}" if hidden else ""
                found.append(self.at_line(src, number, f"눈에 보이지 않는 태그 문자 {len(run)}개가 있습니다.{detail}", severity=Severity.HIGH))
        bidi = [cp for cp in points if cp in BIDI_CONTROLS]
        if bidi:
            found.append(self.at_line(src, number, f"글자 표시 방향을 바꾸는 제어 문자 {len(bidi)}개가 있습니다. 화면에 보이는 문장과 AI가 읽는 문장이 달라질 수 있습니다.", severity=Severity.HIGH))
        zero = [i for i, cp in enumerate(points) if cp in ZERO_WIDTH or (cp == 0xFEFF and not (first_line and i == 0))]
        if zero:
            found.append(
                self.at_line(src, number, f"폭이 없는 보이지 않는 글자 {len(zero)}개가 있습니다.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW)
            )
        joiners = [cp for cp in points if cp in JOINERS]
        if len(joiners) >= JOINER_DENSITY:
            found.append(
                self.at_line(src, number, f"결합 문자·변이 선택자가 한 줄에 {len(joiners)}개 모여 있습니다. 이모지 조합이 아니라면 데이터를 숨긴 것일 수 있습니다.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW)
            )
        return found

    def _instructions(self, src: SourceFile, number: int, line: str) -> list[Violation]:
        for pattern in INSTRUCTION_PATTERNS:
            m = pattern.search(line)
            if m is None:
                continue
            window = line[max(0, m.start() - 40) : m.end() + 40]
            if NEGATION.search(window):
                continue  # "curl | sh를 쓰지 마라" 같은 방어 지침은 악성 지시가 아니다
            return [
                self.at_line(
                    src,
                    number,
                    "AI에게 보안 검사를 건너뛰게 하거나 비밀을 밖으로 보내게 하거나 내려받은 코드를 바로 실행하게 하는 지시처럼 보입니다. 의도한 내용인지 확인하세요.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.REVIEW,
                )
            ]
        return []

    def _encoded_blob(self, src: SourceFile, number: int, line: str) -> list[Violation]:
        if "data:" in line[:200] or "BEGIN " in line:
            return []  # 이미지 데이터 주소와 인증서·키 블록은 제외
        for m in BLOB.finditer(line):
            raw = m.group(0)
            try:
                decoded = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\n\t")
            if decoded and printable / len(decoded) > 0.9 and BLOB_WORDS.search(decoded):
                return [
                    self.at_line(src, number, "긴 인코딩 덩어리를 풀면 지시문처럼 읽히는 문장이 나옵니다. 규칙 파일에 인코딩된 내용을 둘 이유가 없습니다.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW)
                ]
        return []


def _line_of(src: SourceFile, needle: str, start: int = 1) -> int:
    """needle이 처음 나오는 줄(start줄부터). 없으면 start줄"""
    for number, text in enumerate(src.lines[start - 1 :], start=start):
        if needle in text:
            return number
    return start


def _unpinned_package(command: str, args: list[str]) -> str | None:
    """npx·pnpm dlx·bunx·uvx로 실행하는 패키지가 버전 고정 없이 지정되었으면 그 이름"""
    runner = command.rsplit("/", 1)[-1].lower()
    rest = [a for a in args if isinstance(a, str)]
    if runner == "pnpm" and rest[:1] == ["dlx"]:
        rest = rest[1:]
    elif runner == "uv" and rest[:2] == ["tool", "run"]:
        rest = rest[2:]
        runner = "uvx"
    elif runner not in ("npx", "bunx", "uvx", "pipx"):
        return None
    for arg in rest:
        if arg.startswith("-"):
            continue
        if runner in ("npx", "bunx", "pnpm"):
            name = arg
            version = name.rsplit("@", 1)[1] if "@" in name[1:] else ""
            if version in ("", "latest", "next") or not re.match(r"^[~^]?\d", version):
                return arg
            return None
        if "==" in arg or "@" in arg and not arg.startswith("@"):
            return None
        return arg
    return None


class McpConfigRule(AiAttackRule):
    rule_id = "AIA-102"
    name = "MCP 서버 설정의 공급망·인증 위험 탐지"
    severity = Severity.MEDIUM
    sensitive_snippet = True
    plain = (
        "MCP는 AI 에이전트에 도구를 붙이는 규격입니다. 설정에서 패키지 버전을 고정하지 않으면 어느 날 작성자가 악성 업데이트를 올려도 그대로 내려받아 실행됩니다. "
        "주소에 비밀번호를 적거나 인증 없는 원격 서버를 쓰거나 도구 호출을 자동 승인으로 두면, 도구 설명에 숨긴 지시로 AI가 조종당할 때 막을 수단이 없습니다. "
        "(참고: OWASP LLM03 공급망, OWASP 에이전트 ASI02·ASI04, MCP 도구 오염)"
    )
    how_to_fix = (
        "`npx -y 패키지@1.2.3`처럼 버전을 고정하고, 비밀은 설정 파일이 아니라 환경변수(`${변수}`)로 넘기세요. "
        "원격 서버는 https와 인증을 쓰고, 파일·셸·DB 쓰기 도구는 자동 승인 목록에서 빼세요."
    )

    def applies_to(self, src: SourceFile) -> bool:
        return src.kind == "json" and src.path.name.lower() in MCP_FILE_NAMES

    def check(self, src: SourceFile) -> list[Violation]:
        if not self.applies_to(src):
            return []
        try:
            data = json.loads(src.text)
        except ValueError:  # iron-laws: ignore[IL-301] 깨진 JSON은 MCP 설정으로 읽을 수 없으니 이 규칙의 대상이 아니다(문법 오류는 다른 점검 몫)
            return []
        servers = data.get("mcpServers") or data.get("servers") if isinstance(data, dict) else None
        if not isinstance(servers, dict):
            return []
        found: list[Violation] = []
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            base = _line_of(src, f'"{name}"')
            command, args = str(spec.get("command") or ""), spec.get("args") or []
            args = args if isinstance(args, list) else []
            # 메시지에 서버·패키지 이름을 넣지 않는다. 비밀 가림이 따옴표로 묶인 값을 함께 가리므로 위치(줄)로 알려 준다
            package = _unpinned_package(command, args) if command else None
            if package:
                found.append(self.at_line(src, _line_of(src, package, base), "이 MCP 서버가 버전을 고정하지 않은 패키지를 실행합니다.", severity=Severity.MEDIUM))
            url = str(spec.get("url") or spec.get("serverUrl") or "")
            if url.startswith("http://") and not any(host in url for host in LOCAL_HOSTS):
                found.append(self.at_line(src, _line_of(src, url, base), "이 MCP 서버가 암호화되지 않은 http 주소를 씁니다.", severity=Severity.MEDIUM))
            if URL_CREDENTIAL.search(url) or any(URL_CREDENTIAL.search(str(a)) for a in args):
                found.append(self.at_line(src, _line_of(src, "://", base), "이 MCP 서버의 주소나 인자에 비밀번호가 직접 적혀 있습니다.", severity=Severity.HIGH))
            else:
                secret_line = self._literal_secret(spec, args)
                if secret_line:
                    found.append(self.at_line(src, _line_of(src, secret_line, base), "이 MCP 서버의 설정에 비밀로 보이는 값이 직접 적혀 있습니다. 환경변수로 넘기세요.", severity=Severity.HIGH))
            approved = self._auto_approved(spec, args)
            if approved:
                found.append(self.at_line(src, _line_of(src, approved, base), "이 MCP 서버의 도구 호출이 자동 승인으로 설정되어 있습니다.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
        return found

    @staticmethod
    def _literal_secret(spec: dict, args: list) -> str:
        """비밀로 보이는 값이 설정에 직접 적혀 있으면 그 위치를 찾는 데 쓸 키(없으면 빈 문자열)"""
        env = spec.get("env") if isinstance(spec.get("env"), dict) else {}
        for key, value in env.items():
            if SECRET_ARG.search(str(key)) and isinstance(value, str) and not ENV_REFERENCE.match(value):
                return f'"{key}"'
        headers = spec.get("headers") if isinstance(spec.get("headers"), dict) else {}
        for key, value in headers.items():
            if re.search(r"(?i)authorization|api[-_]?key|token", str(key)) and isinstance(value, str) and not ENV_REFERENCE.match(re.sub(r"(?i)^(bearer|basic)\s+", "", value)):
                return f'"{key}"'
        for index, arg in enumerate(args):
            text = str(arg)
            if re.match(r"(?i)^--?(password|passwd|token|secret|api[-_]?key)=.+", text) and not ENV_REFERENCE.match(text.split("=", 1)[1]):
                return text
            if re.match(r"(?i)^--?(password|passwd|token|secret|api[-_]?key)$", text) and index + 1 < len(args) and not ENV_REFERENCE.match(str(args[index + 1])):
                return text
        return ""

    @staticmethod
    def _auto_approved(spec: dict, args: list) -> str:
        """자동 승인 설정이면 그 위치를 찾는 데 쓸 키 또는 인자(없으면 빈 문자열)"""
        for key, value in spec.items():
            if str(key).lower() in AUTO_APPROVE_KEYS and value not in (False, None, [], ""):
                return f'"{key}"'
        if spec.get("trust") is True:
            return '"trust"'
        for arg in args:
            if AUTO_APPROVE_ARGS.search(str(arg)):
                return str(arg)
        return ""


class ModelLoadingRule(AiAttackRule):
    rule_id = "AIA-106"
    name = "위험한 모델 불러오기 옵션 탐지"
    severity = Severity.HIGH
    languages = None
    plain = (
        "허깅페이스 같은 곳의 모델을 불러올 때 `trust_remote_code=True`를 주면 모델 저장소에 든 파이썬 코드가 내 컴퓨터에서 그대로 실행됩니다. "
        "버전(리비전)을 고정하지 않으면 작성자가 나중에 파일을 바꿔도 알 수 없습니다. "
        "(참고: OWASP LLM03 공급망, LLM04 데이터·모델 오염. pickle·`torch.load`는 IL-515가 점검합니다)"
    )
    how_to_fix = (
        "`trust_remote_code`는 코드를 직접 읽고 믿을 수 있을 때만 쓰고, 가능하면 끄세요. `from_pretrained(\"이름\", revision=\"커밋해시\")`로 버전을 고정하고, "
        "모델은 코드를 실행하지 않는 safetensors 형식을 고르세요."
    )
    trust = re.compile(r"\btrust_remote_code\s*=\s*True\b")

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang is None or src.lang.value != "python":
            return []
        found: list[Violation] = []
        for number, line in enumerate(src.code_lines, start=1):
            if self.trust.search(line):
                found.append(self.at_line(src, number, "`trust_remote_code=True`는 모델 저장소의 코드를 내 컴퓨터에서 실행합니다.", severity=Severity.HIGH))
        return found


AIA_RULES: list[type[BaseRule]] = [
    AgentRuleFileRule,
    McpConfigRule,
    ModelLoadingRule,
]
