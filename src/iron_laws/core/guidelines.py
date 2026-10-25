"""
지침 강제 대응표: 규칙을 코딩 에이전트 지침(CLAUDE.md·AGENTS.md)으로 내보내고, 지침 문장마다 무엇이 그것을 강제하는지 밝힌다

- 내보내기: 규칙마다 지침 한 줄과 강제 수단(차단·실행 검증·보고)과 시험으로 검증된 언어를 붙인다.
- 대조: 사람이 쓴 지침 파일에서 지시 문장을 뽑아 대응 규칙과 강제 수단을 붙인다. 대응 규칙이 없는 문장은
  모델이 읽고 따르기만 하는 문장이며, 오철칙·hook·권한 설정 어느 것도 그 문장을 확인하지 않는다.
- 판정은 결정적이다(규칙 메타데이터·지원 행렬·주제 대응표). LLM을 쓰지 않는다.
작성자: 최진호
작성일: 2026-10-26
"""

import re
from dataclasses import dataclass, field

from iron_laws.core.ledger import FAMILY_RULES
from iron_laws.core.models import Severity
from iron_laws.core.support_matrix import build_support_matrix
from iron_laws.rules.base import BaseRule

SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
RULE_ID_RE = re.compile(r"\b(?:AIA|AI|ARC|IL|PERF|TYP)-\d{3}\b")
DIRECTIVE_RE = re.compile(
    r"(?i)\b(?:must|never|do not|don't|always|avoid|prefer|should|shall|required?|prohibit(?:ed)?|forbid(?:den)?)\b"
    r"|금지|지 ?않|지 ?말|말 ?것|반드시|항상|절대|안 ?된다|않도록"
)
# 사람이 쓴 지침 문장을 규칙에 잇는 주제 대응표. 문장에 규칙 ID가 있으면 그것을 먼저 쓴다.
TOPICS: tuple[tuple[str, re.Pattern[str], tuple[str, ...]], ...] = tuple(
    (name, re.compile(pattern, re.IGNORECASE), rules)
    for name, pattern, rules in (
        ("비밀값", r"secrets?\b|api[ _-]?keys?|\bpasswords?\b|passwd|credentials?|private keys?|\.env\b|비밀|자격 ?증명|개인키", ("IL-101", "AI-102", "AI-103", "AI-104", "IL-108")),
        ("비밀번호 정책", r"passwords?.{0,30}(?:length|chars?\b|characters|complex)|비밀번호.{0,20}(?:길이|자리)", ("IL-110",)),
        ("SQL", r"\bsql\b|parameteri[sz]ed quer|prepared statement|쿼리 문자열|바인드 변수", ("IL-501",)),
        ("NoSQL", r"nosql|\$where", ("IL-533",)),
        ("명령 실행", r"shell (?:command|injection|=\s*true)|subprocess|os\.system|command injection|child_process|명령(?:어)? ?(?:실행|삽입)|셸 명령", ("IL-504",)),
        ("동적 코드", r"\beval\b|dynamic code|동적 코드", ("IL-503",)),
        ("경로", r"path traversal|(?:user|untrusted)[- ]?(?:supplied|provided|input)? ?(?:file ?)?paths?|\.\./|경로 조작", ("IL-502",)),
        ("XSS", r"\bxss\b|innerhtml|dangerouslysetinnerhtml|escap\w* (?:html|output)|html 이스케이프|스크립트 삽입", ("IL-505",)),
        ("SSRF", r"\bssrf\b|server[- ]side request", ("IL-506",)),
        ("CSRF", r"\bcsrf\b", ("IL-510",)),
        ("리다이렉트", r"open redirect|redirect (?:to )?(?:user|untrusted|external)|리다이렉트", ("IL-507",)),
        ("XML", r"\bxxe\b|xml (?:parser|entit)|xpath", ("IL-509", "IL-527")),
        ("역직렬화", r"deseriali[sz]|\bpickle\b|yaml\.load|역직렬화", ("IL-515",)),
        ("업로드", r"file uploads?|upload(?:ed)? files?|업로드", ("IL-513", "IL-530")),
        ("암호·해시", r"\bmd5\b|\bsha-?1\b|\bdes\b|\becb\b|encrypt|cipher|password hash|hash(?:ing)? passwords?|암호화|해시", ("IL-102", "IL-103", "IL-107")),
        ("난수", r"(?:secure|cryptographic\w*|insecure|predictable) random|random (?:tokens?|passwords?|secrets?)|보안.{0,10}난수|난수", ("IL-104",)),
        ("TLS", r"\btls\b|\bssl\b|certificates?|verify ?= ?false|plain http\b|http://|인증서", ("IL-106", "IL-109")),
        ("토큰 서명", r"\bjwt\b|token signatures?|(?:verify|validate)\w* (?:the )?signatures?|서명 검증", ("IL-105", "AI-118")),
        ("인증·권한", r"authenticat|authoriz|access control|permission checks?|\blogin\b|인증|인가|권한", ("IL-303", "IL-525", "AI-113", "AI-122")),
        ("요청 제한", r"\brate[ -]?limit|brute[- ]?force|throttl|무차별|요청 제한", ("IL-532", "AI-114")),
        ("예외 처리", r"swallow|silently (?:ignore|catch|fail)|empty catch|bare except|catch[- ]all|error handling|\bexcept\b|예외|(?:오류|에러)를? ?(?:삼키|무시)", ("IL-301", "IL-304", "IL-305", "IL-307")),
        ("시험 회피", r"(?:delete|skip|disable|remove|comment out)\w* (?:the |a |any |failing )?tests?|tests? (?:skip|deletion)|xfail|@disabled|\.skip\(|without assert|테스트를? ?(?:삭제|건너|끄|지우)|시험을? ?(?:삭제|건너|지우)", ("IL-302", "IL-306")),
        ("민감정보 로그", r"\blog(?:s|ging|ged)?\b.{0,40}(?:passwords?|secrets?|tokens?|pii|personal|sensitive)|(?:passwords?|secrets?|tokens?|pii|sensitive).{0,40}\blog(?:s|ging|ged)?\b|로그.{0,20}(?:비밀|민감|개인)|(?:비밀|민감|개인).{0,20}로그", ("AI-112",)),
        ("CORS", r"\bcors\b", ("AI-105",)),
        ("쿠키", r"cookies?|쿠키", ("AI-115", "IL-112")),
        ("디버그", r"debug (?:mode|code|flag|statements?|prints?)|debug ?= ?true|디버그 (?:코드|모드)", ("IL-520", "AI-106")),
        ("하드코딩", r"hard-?cod|하드코딩|magic (?:numbers?|strings?)", ("AI-101", "ARC-205")),
        ("중복 함수", r"duplicat\w* (?:code|functions?|helpers?|logic)|existing (?:functions?|helpers?|utilit)|중복 (?:함수|코드)|이미 있는 함수", ("ARC-204",)),
        ("타입 회피", r"`any`|\bany type|\bas any\b|type: ?ignore|ts-ignore|@ts-expect-error|unchecked cast|타입 (?:회피|무시)", ("TYP-301", "TYP-302", "TYP-303", "TYP-304", "TYP-305")),
        ("구조", r"circular (?:imports?|dependenc)|(?:inner|outer|domain|lower|upper) layers?|layer(?:ed)? (?:architecture|boundar)|순환 (?:참조|의존)|계층", ("ARC-203", "ARC-207")),
        ("컨트롤러 DB 접근", r"controllers?\b.{0,40}\b(?:db|database|repositor\w*|sql|orm)\b|컨트롤러.{0,20}(?:DB|데이터베이스)", ("ARC-202",)),
        ("반복 안 조회", r"n\+1|quer(?:y|ies) (?:in|inside) (?:a )?loops?|반복문 안|루프 안", ("ARC-212", "PERF-101", "PERF-103")),
        ("공급망", r"(?:pin|lock)\w* (?:dependenc|versions?|packages?)|lock ?files?|typosquat|공급망", ("AI-111",)),
        ("배포 설정", r"dockerfile|run(?:s|ning)? as root|container (?:images?|user|privileg)|github actions|컨테이너 (?:이미지|권한)", ("AI-110",)),
        ("LLM", r"\bllm (?:output|response)s?|prompt injection|system prompt|프롬프트 (?:주입|삽입)", ("AIA-103", "AIA-104", "AIA-108", "AIA-109")),
        ("MCP 설정", r"mcp (?:servers?|config)|\.mcp\.json|mcp 서버", ("AIA-102", "AIA-105")),
        ("데이터베이스 규칙", r"supabase|firebase|row level security|\brls\b", ("AI-108",)),
    )
)


@dataclass
class Enforcement:
    rule_id: str
    name: str
    severity: str
    blocking: bool  # hook·check의 --fail-on 기준 이상이라 지적이 있으면 작업이 멈춘다
    executed: bool  # verify-patch 회귀시험과 근거 장부가 실행으로 확인하는 계열
    verified_languages: list[str] = field(default_factory=list)

    def tags(self) -> list[str]:
        tags = ["차단" if self.blocking else "보고"]
        if self.executed:
            tags.append("실행 검증")
        tags.append("검증 언어: " + ", ".join(self.verified_languages) if self.verified_languages else "시험 검증 없음")
        return tags


def _sentence(rule: BaseRule) -> str:
    """고치는 방법의 첫 문장. 코드 표기(`...`) 안의 마침표에서는 끊지 않는다."""
    text = (rule.how_to_fix or rule.plain or rule.name).strip()
    for end in re.finditer(r"(?:다|요)\.?(?=\s|$)|\.(?=\s|$)", text):
        if text.count("`", 0, end.end()) % 2 == 0:
            return text[: end.end()].strip()
    return text


def enforcement_table(rules: list[BaseRule], fail_on: Severity = Severity.HIGH, languages: set[str] | None = None) -> dict[str, Enforcement]:
    """규칙마다 강제 수단. languages를 주면 그 언어에서 적용되는 규칙만 담고 검증 언어도 그 안에서만 센다."""
    executed = {cls.rule_id for cls in FAMILY_RULES.values()}
    rows = {row.rule_id: row for row in build_support_matrix(rules)}
    table: dict[str, Enforcement] = {}
    for rule in sorted(rules, key=lambda r: r.rule_id):
        cells = rows[rule.rule_id].cells
        applicable = [lang for lang, cell in cells.items() if cell.status != "미지원" and (languages is None or lang in languages)]
        if not applicable:
            continue
        table[rule.rule_id] = Enforcement(
            rule.rule_id,
            rule.name,
            rule.severity.value,
            SEVERITY_ORDER.index(rule.severity) >= SEVERITY_ORDER.index(fail_on),
            rule.rule_id in executed,
            [lang for lang in applicable if cells[lang].verified],
        )
    return table


def export_guidelines(rules: list[BaseRule], fail_on: Severity = Severity.HIGH, languages: set[str] | None = None, min_severity: Severity = Severity.LOW) -> str:
    table = enforcement_table(rules, fail_on, languages)
    by_id = {r.rule_id: r for r in rules}
    picked = [e for e in table.values() if SEVERITY_ORDER.index(Severity(e.severity)) >= SEVERITY_ORDER.index(min_severity)]
    blocking = sum(1 for e in picked if e.blocking)
    lines = [
        "# 코드 작성 지침 (오철칙 규칙에서 생성)",
        "",
        "각 줄 끝의 꼬리표는 그 지침을 무엇이 확인하는지 나타냅니다.",
        f"- 차단: `iron-laws hook`·`check --fail-on {fail_on.value}`가 지적하면 작업이 멈춥니다.",
        "- 실행 검증: `iron-laws verify-patch`가 수정 전후를 격리 실행해 결함 동작이 사라졌는지 확인합니다.",
        "- 보고: 지적은 하지만 작업을 멈추지 않습니다.",
        "- 검증 언어: 양성·음성 시험으로 확인된 언어입니다. 그 밖의 언어에서는 판정이 시험으로 확인되지 않았습니다.",
        "",
        f"지침 {len(picked)}줄 가운데 차단 {blocking}줄, 실행 검증 {sum(1 for e in picked if e.executed)}줄입니다.",
        "",
    ]
    for e in picked:
        lines.append(f"- {_sentence(by_id[e.rule_id])} ({e.rule_id} {e.name}) [{' · '.join(e.tags())}]")
    return "\n".join(lines) + "\n"


@dataclass
class Directive:
    line: int
    text: str
    rules: list[str]
    topics: list[str]


# 더 구체적인 주제가 맞으면 빼는 일반 주제(비밀번호 길이 정책은 비밀값 하드코딩 규칙의 지침이 아니다)
NARROWER = {"비밀번호 정책": ("비밀값",), "NoSQL": ("SQL",)}
SENTENCE_SPLIT = re.compile(r"(?<=[.!?。])\s+")
PRONOUN_START = re.compile(r"^(?:\*\*)?(?:it|this|they|these|that)\b|^(?:이것|이는|그것)", re.IGNORECASE)


def _directive_topics(line: str) -> list[str]:
    """지시어가 있는 문장 안의 주제만 센다. 설명 문장에만 나온 낱말(jwt, innerHTML)을 지시로 보지 않는다.
    지시 문장이 대명사(It·This 등)로 시작하면 바로 앞 문장의 주제를 이어받는다."""
    found: list[str] = []
    previous = ""
    for sentence in SENTENCE_SPLIT.split(line):
        if DIRECTIVE_RE.search(sentence):
            scope = f"{previous} {sentence}" if PRONOUN_START.search(sentence.strip()) else sentence
            found += [name for name, pattern, _ in TOPICS if pattern.search(scope) and name not in found]
        previous = sentence
    shadowed = {general for name in found for general in NARROWER.get(name, ())}
    return [name for name in found if name not in shadowed]


def extract_directives(text: str) -> list[Directive]:
    """마크다운 지침에서 지시 문장을 줄 단위로 뽑아 대응 규칙을 붙인다. 코드 블록과 제목은 건너뛴다."""
    found: list[Directive] = []
    fenced = False
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line.startswith(("```", "~~~")):
            fenced = not fenced
            continue
        if fenced or not line or line.startswith("#"):
            continue
        explicit = sorted(set(RULE_ID_RE.findall(line)))
        if not explicit and not DIRECTIVE_RE.search(line):
            continue
        topics = [] if explicit else _directive_topics(line)
        rules = explicit or sorted({rule for name, pattern, ids in TOPICS if name in topics for rule in ids})
        found.append(Directive(number, re.sub(r"^[-*+]\s+|^\d+[.)]\s+", "", line), rules, topics))
    return found


def check_guidelines(text: str, rules: list[BaseRule], fail_on: Severity = Severity.HIGH, languages: set[str] | None = None) -> dict:
    table = enforcement_table(rules, fail_on, languages)
    directives = extract_directives(text)
    rows = []
    for d in directives:
        matched = [table[r] for r in d.rules if r in table]
        rows.append(
            {
                "line": d.line,
                "text": d.text,
                "topics": d.topics,
                "rules": [{"rule_id": e.rule_id, "name": e.name, "tags": e.tags()} for e in matched],
                "enforced": "blocking" if any(e.blocking for e in matched) else "reported" if matched else "none",
            }
        )
    counts = {kind: sum(1 for r in rows if r["enforced"] == kind) for kind in ("blocking", "reported", "none")}
    return {"directives": len(rows), "counts": counts, "rows": rows}


def render_check(result: dict) -> str:
    counts = result["counts"]
    label = {"blocking": "차단", "reported": "보고", "none": "강제 수단 없음"}
    lines = [
        f"지시 문장 {result['directives']}개: 차단 {counts['blocking']}, 보고 {counts['reported']}, 강제 수단 없음 {counts['none']}",
        "강제 수단 없음은 모델이 읽고 따르기만 하는 문장입니다. 오철칙 규칙·사용자 명세, 에이전트 hook·권한 설정으로 확인할 수 있는지 보십시오.",
        "",
    ]
    for row in result["rows"]:
        target = ", ".join(f"{r['rule_id']}[{' · '.join(r['tags'])}]" for r in row["rules"]) or "대응 규칙 없음"
        lines.append(f"{row['line']:>4}  {label[row['enforced']]:<8} {row['text'][:80]}")
        lines.append(f"      → {target}")
    return "\n".join(lines) + "\n"
