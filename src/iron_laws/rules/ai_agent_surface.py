"""
AI 공격면 점검 계열(AIA) 2: LLM 응답과 MCP 도구 입력을 신뢰 경계 밖의 값으로 다룬다
- AIA-103: LLM 클라이언트 응답(소스 종류 ai_response)이 코드 실행·명령·SQL 싱크에 닿는다.
- AIA-104: 웹 요청의 값이 정제 없이 시스템 지시 자리(role=system, system=, SystemMessage)에 들어간다. 사용자 메시지 자리는 대상이 아니다.
- AIA-105: MCP 서버 구현의 도구 설명에 숨은 지시가 있거나, 도구 인자가 검증 없이 파일 경로·명령으로 쓰인다.
근거는 OWASP Top 10 for Agentic Applications 2026(ASI01·ASI02·ASI05)이며, 행안부 항목이 아닌 오철칙 자체 규칙이다.
작성자: 최진호
작성일: 2026-10-12
"""

import re

from tree_sitter import Node

from iron_laws.core.models import Confidence, Severity, Violation
from iron_laws.engine.ast_tools import iter_calls, iter_functions, string_value, walk
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import extra_sources, is_tainted, param_name
from iron_laws.rules.ai_attack import AgentRuleFileRule, AiAttackRule
from iron_laws.rules.injection_execution import (
    CodeInjectionRule,
    CommandInjectionRule,
    SqlInjectionRule,
)
from iron_laws.rules.injection_paths import PathTraversalRule
from iron_laws.rules.sinks import Flow, assess, sink_hits

LLM_IMPORT = re.compile(
    r"(?m)^\s*(?:from|import)\s+(openai|anthropic|langchain\w*|google\.generativeai|google\.genai|ollama|litellm|groq|mistralai|cohere)\b"
    r"|require\(\s*['\"](openai|@anthropic-ai/sdk|ai|@ai-sdk/[\w-]+|langchain|@langchain/[\w-]+|ollama)['\"]\s*\)"
    r"|from\s+['\"](openai|@anthropic-ai/sdk|ai|@ai-sdk/[\w-]+|langchain|@langchain/[\w-]+|ollama)['\"]"
)
AI_RESPONSE = re.compile(
    r"(?x)\b(?:chat\.)?completions\.create\s*\( | \bresponses\.create\s*\( | \bmessages\.create\s*\("
    r" | \.choices\s*\[\s*\d+\s*\]\s*\.\s*(?:message|text|delta)\b | \.output_text\b | \.content\s*\[\s*\d+\s*\]\s*\.\s*text\b"
    r" | \bgenerate_content\s*\( | \bgenerateText\s*\( | \bgenerateObject\s*\( | \bollama\.(?:chat|generate)\s*\("
    r" | \b(?:llm|chain|model|agent|chat|executor)\w*\.(?:invoke|ainvoke|predict|run|call)\s*\( | \bcompletion\s*\(\s*model\s*="
)
MCP_IMPORT = re.compile(
    r"(?m)^\s*(?:from|import)\s+(mcp\.server|fastmcp|mcp)\b|['\"]@modelcontextprotocol/sdk[\w/.-]*['\"]"
)
TOOL_DECORATOR = re.compile(r"@\s*\w+\.tool\b")


class LlmOutputExecutionRule(AiAttackRule):
    rule_id = "AIA-103"
    name = "LLM 응답을 검증 없이 실행·명령·SQL에 쓰는 코드 탐지"
    severity = Severity.HIGH
    plain = (
        "LLM 응답은 사용자가 넣은 글이나 모델이 읽은 웹 페이지에 숨은 지시로 얼마든지 바뀝니다. 그 응답을 eval·명령 실행·SQL에 그대로 넣으면 "
        "공격자가 프롬프트 한 줄로 서버에서 코드를 실행하거나 DB를 바꿀 수 있습니다. (참고: OWASP 에이전트 ASI05, LLM05 부적절한 출력 처리)"
    )
    how_to_fix = "LLM 응답은 외부 입력과 같게 다루십시오. 실행이 필요하면 허용 목록의 명령·함수 이름만 고르게 하고, SQL은 파라미터 바인딩으로, 코드는 격리된 환경에서만 실행하십시오."

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang is None or not LLM_IMPORT.search(src.code_text):
            return []
        found: list[Violation] = []
        seen: set[int] = set()
        with extra_sources(AI_RESPONSE, "ai_response"):
            for rule in (CodeInjectionRule(), CommandInjectionRule(), SqlInjectionRule()):
                if self.config is not None:
                    rule.configure(self.config)
                for call, arg, flow, via in sink_hits(src, rule.sinks, False, rule.select_args, rule.taint_ctx, rule.skip_hit):
                    if flow is not Flow.TAINTED or call.node.id in seen or (via is None and rule.skip_hit(src, call, arg, flow)):
                        continue
                    seen.add(call.node.id)
                    found.append((call, arg, rule, via))
        result = []
        for call, arg, rule, via in found:
            if assess(src, arg, False, ctx=rule.taint_ctx) is Flow.TAINTED:
                continue  # 웹 입력만으로도 닿는 흐름은 IL-50x가 이미 알린다
            where = f" (호출한 함수 안의 {via}에서 사용됩니다)" if via else ""
            result.append(self.at_node(src, call.node, f"LLM 응답(ai_response)이 검증 없이 {call.callee}에 전달됩니다{where}. 프롬프트 주입으로 실행 내용이 바뀔 수 있습니다."))
        return result


class SystemPromptInjectionRule(AiAttackRule):
    rule_id = "AIA-104"
    name = "외부 입력이 LLM 시스템 지시 자리에 들어가는 코드 탐지"
    severity = Severity.MEDIUM
    plain = (
        "시스템 지시(system prompt)는 모델이 가장 강하게 따르는 자리입니다. 요청 값이 그 자리에 그대로 들어가면 사용자가 '이전 지시를 무시하라' 같은 문장으로 "
        "앱의 규칙을 바꿀 수 있습니다. 사용자 입력은 user 메시지 자리에 두어야 합니다. (참고: OWASP 에이전트 ASI01, LLM01 프롬프트 주입)"
    )
    how_to_fix = "시스템 지시는 고정 문구로 두고, 사용자 입력은 role=user 메시지로 따로 넘기십시오. 꼭 넣어야 하면 허용 목록 값만 고르게 하십시오."

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang is None or not LLM_IMPORT.search(src.code_text):
            return []
        found = []
        for node, value in self._system_slots(src):
            if is_tainted(src, value):
                found.append(self.at_node(src, node, "웹 요청의 값이 LLM 시스템 지시 자리에 들어갑니다. 사용자가 앱의 지시를 바꿀 수 있습니다."))
        return found

    def _system_slots(self, src: SourceFile) -> list[tuple[Node, Node]]:
        slots: list[tuple[Node, Node]] = []
        for node in src.nodes:
            if node.type in ("dictionary", "object"):
                pairs = {self._key(src, p): p.child_by_field_name("value") for p in node.named_children if p.type == "pair"}
                role = pairs.get("role")
                if role is not None and role.type == "string" and string_value(src, role) == "system" and pairs.get("content") is not None:
                    slots.append((node, pairs["content"]))
            elif node.type in ("keyword_argument", "pair"):
                key = self._key(src, node) if node.type == "pair" else src.text_of(node.child_by_field_name("name") or node)
                value = node.child_by_field_name("value")
                if key in ("system", "system_prompt", "systemPrompt", "system_instruction", "instructions") and value is not None and self._inside_llm_call(src, node):
                    slots.append((node, value))
        for call in iter_calls(src):
            if re.search(r"(^|\.)(SystemMessage|SystemMessagePromptTemplate\.from_template)$", call.callee) and call.args:
                slots.append((call.node, call.args[0]))
        return slots

    @staticmethod
    def _key(src: SourceFile, pair: Node) -> str:
        key = pair.child_by_field_name("key")
        if key is None:
            return ""
        return string_value(src, key) if key.type == "string" else src.text_of(key)

    @staticmethod
    def _inside_llm_call(src: SourceFile, node: Node) -> bool:
        current = node.parent
        while current is not None:
            if current.type in ("call", "call_expression"):
                fn = current.child_by_field_name("function")
                return fn is not None and bool(AI_RESPONSE.search(src.text_of(fn) + "(") or re.search(r"(?i)(create|generate|chat|invoke|completion|stream)\w*$", src.text_of(fn)))
            current = current.parent
        return False


class McpServerToolRule(AiAttackRule):
    rule_id = "AIA-105"
    name = "MCP 서버 도구의 숨은 지시·무검증 경로·명령 인자 탐지"
    severity = Severity.HIGH
    plain = (
        "MCP 도구 설명은 에이전트가 그대로 읽는 문장이라, 숨은 지시가 있으면 에이전트를 조종할 수 있습니다(도구 독살). 도구 인자는 모델이 정하는 값이라 "
        "프롬프트 주입으로 바뀔 수 있으므로, 검증 없이 파일 경로나 셸 명령으로 쓰면 임의 파일 읽기·명령 실행이 됩니다. (참고: OWASP 에이전트 ASI02 도구 오용, ASI04)"
    )
    how_to_fix = "도구 설명은 기능만 짧게 쓰고 지시문·보이지 않는 글자를 넣지 마십시오. 경로 인자는 허용 폴더 안인지 정규화해 확인하고, 명령은 허용 목록에서만 고르며 셸을 거치지 않게 실행하십시오."

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang is None or not MCP_IMPORT.search(src.code_text):
            return []
        return self._descriptions(src) + self._unchecked_arguments(src)

    def _tool_functions(self, src: SourceFile) -> list:
        tools = []
        if src.lang is Lang.PYTHON:
            for fn in iter_functions(src):
                parent = fn.node.parent
                if parent is not None and parent.type == "decorated_definition" and any(TOOL_DECORATOR.search(src.text_of(d)) for d in parent.named_children if d.type == "decorator"):
                    tools.append(fn)
        elif src.lang in JS_FAMILY:
            for call in iter_calls(src):
                if re.search(r"\.(tool|registerTool)$", call.callee) and call.args:
                    handler = call.args[-1]
                    tools += [fn for fn in iter_functions(src) if fn.node.id == handler.id]
        return tools

    def _description_nodes(self, src: SourceFile) -> list[Node]:
        nodes: list[Node] = []
        for call in iter_calls(src):
            is_tool = re.search(r"\.(tool|registerTool|add_tool)$", call.callee) or TOOL_DECORATOR.search("@" + call.callee)
            if not is_tool:
                continue
            for arg in call.args:
                if arg.type == "string":
                    nodes.append(arg)
                for n in walk(arg):
                    if n.type in ("keyword_argument", "pair"):
                        key = n.child_by_field_name("name") or n.child_by_field_name("key")
                        value = n.child_by_field_name("value")
                        if key is not None and value is not None and value.type == "string" and src.text_of(key).strip("'\"") in ("description", "title"):
                            nodes.append(value)
        for fn in self._tool_functions(src):
            if src.lang is Lang.PYTHON and fn.body is not None and fn.body.named_children:
                first = fn.body.named_children[0]
                if first.type == "expression_statement" and first.named_children and first.named_children[0].type == "string":
                    nodes.append(first.named_children[0])
        return nodes

    def _descriptions(self, src: SourceFile) -> list[Violation]:
        probe = AgentRuleFileRule()
        found = []
        for node in self._description_nodes(src):
            start = src.line_of(node)
            for offset, line in enumerate(src.text_of(node).split("\n")):
                number = start + offset
                hits = probe._hidden_characters(src, number, line, False) + probe._instructions(src, number, line) + probe._encoded_blob(src, number, line)
                for hit in hits:
                    found.append(self.at_line(src, number, f"MCP 도구 설명에 숨은 지시가 있을 수 있습니다: {hit.message}", severity=hit.severity, confidence=hit.confidence))
        return found

    def _unchecked_arguments(self, src: SourceFile) -> list[Violation]:
        found = []
        rules = (PathTraversalRule(), CommandInjectionRule())
        for fn in self._tool_functions(src):
            seeds = frozenset(name for p in fn.params for name in ([param_name(src, p)] if src.lang is Lang.PYTHON else _js_param_names(src, p)) if name and name not in ("self", "ctx", "context"))
            if not seeds:
                continue
            for call in iter_calls(src):
                if not (fn.node.start_byte <= call.node.start_byte and call.node.end_byte <= fn.node.end_byte):
                    continue
                for rule in rules:
                    if self.config is not None:
                        rule.configure(self.config)
                    sink = next((s for s in rule.sinks if src.lang in s.langs and s.callee.search(call.callee)), None)
                    if sink is None:
                        continue
                    for arg in rule.select_args(src, call, sink):
                        flow = assess(src, arg, False, seeds, rule.taint_ctx)
                        if flow is Flow.TAINTED and not rule.skip_hit(src, call, arg, flow) and not rule._allowlisted(src, call, arg):
                            kind = "파일 경로" if isinstance(rule, PathTraversalRule) else "명령"
                            found.append(self.at_node(src, call.node, f"MCP 도구 인자가 검증 없이 {kind}로 {call.callee}에 전달됩니다. 모델이 정하는 값이라 프롬프트 주입으로 바뀔 수 있습니다."))
                            break
        return found


LLM_CALL = re.compile(r"(?:^|\.)(?:chat\.)?completions\.create$|(?:^|\.)responses\.create$|(?:^|\.)messages\.create$|(?:^|\.)generate_content$|^(?:generateText|streamText|generateObject)$|(?:^|\.)ChatCompletion\.create$")
OUTPUT_CAP = re.compile(r"\b(max_tokens|max_output_tokens|max_completion_tokens|maxTokens|maxOutputTokens|max_new_tokens)\b")
PII_NAME = re.compile(r"(?i)\b\w*(ssn|social_?security|resident_?(?:no|number|id)|jumin|rrn|주민|phone|mobile|tel_?no|e_?mail|address|birth_?(?:day|date)?|dob|card_?(?:no|number)|account_?(?:no|number)|passport|license_?no|patient|diagnosis|medical)\w*\b")
BROWSER_LLM = re.compile(r"dangerouslyAllowBrowser\s*:\s*true|fetch\(\s*['\"`]https://api\.(openai|anthropic)\.com|anthropic-dangerous-direct-browser-access")


class BrowserModelKeyRule(AiAttackRule):
    rule_id = "AIA-107"
    name = "브라우저에서 모델 키로 LLM을 직접 부르는 코드 탐지"
    severity = Severity.HIGH
    plain = "브라우저에서 LLM API를 직접 부르면 모델 키가 방문자 누구에게나 보입니다. 키를 가져간 사람이 비용을 무한정 쓰거나 다른 용도로 쓸 수 있습니다."
    how_to_fix = "LLM 호출은 서버(API 라우트)에서 하고, 브라우저는 그 서버 주소만 부르게 하십시오. dangerouslyAllowBrowser 옵션을 쓰지 마십시오."

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang not in JS_FAMILY:
            return []
        found = []
        for number, line in enumerate(src.code_text.split("\n"), start=1):
            if BROWSER_LLM.search(line):
                found.append(self.at_line(src, number, "브라우저에서 모델 키로 LLM API를 직접 부릅니다. 키가 방문자에게 노출됩니다."))
        return found


class UncappedLlmCallRule(AiAttackRule):
    rule_id = "AIA-108"
    name = "웹 입력을 받는 LLM 호출의 출력 상한 부재 탐지"
    severity = Severity.MEDIUM
    plain = "요청 값으로 LLM을 부르면서 출력 길이 상한이 없으면, 한 사람이 긴 입력·긴 답을 반복해 비용을 크게 늘리거나 서비스를 느리게 만들 수 있습니다. (참고: OWASP LLM10 무제한 소비)"
    how_to_fix = "max_tokens(또는 max_output_tokens) 같은 출력 상한을 지정하고, 입력 길이와 사용자별 호출 횟수도 제한하십시오."

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang is None or not LLM_IMPORT.search(src.code_text):
            return []
        found = []
        for call in iter_calls(src):
            if not LLM_CALL.search(call.callee) or call.callee.endswith("messages.create"):
                continue  # Anthropic messages.create는 max_tokens가 필수 인자다
            if OUTPUT_CAP.search(src.text_of(call.node)):
                continue
            if any(is_tainted(src, a) for a in call.args):
                found.append(self.at_node(src, call.node, f"웹 요청 값을 {call.callee}에 넘기면서 출력 길이 상한(max_tokens 등)이 없습니다.", confidence=Confidence.REVIEW))
        return found


class PiiToLlmRule(AiAttackRule):
    rule_id = "AIA-109"
    name = "개인정보 필드를 외부 LLM으로 보내는 코드 탐지"
    severity = Severity.MEDIUM
    plain = "주민등록번호·전화번호·주소·카드번호 같은 개인정보를 외부 LLM API로 보내면 국외 이전·제3자 제공에 해당할 수 있고, 제공자의 로그에 남을 수 있습니다."
    how_to_fix = "LLM에 보내기 전에 개인정보 필드를 빼거나 가명처리·마스킹하십시오. 꼭 필요하면 계약·동의·국외 이전 요건을 확인하십시오."

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang is None or not LLM_IMPORT.search(src.code_text):
            return []
        found = []
        for call in iter_calls(src):
            if not LLM_CALL.search(call.callee):
                continue
            payload = " ".join(src.text_of(a) for a in call.args)
            masked = re.search(r"(?i)mask|pseudonym|anonymi|redact|가명|비식별", payload)
            hits = sorted({m.group(0) for m in PII_NAME.finditer(_code_only(src, call.node))})
            if hits and not masked:
                found.append(self.at_node(src, call.node, f"개인정보로 보이는 필드({', '.join(hits[:4])})를 외부 LLM 호출({call.callee})에 넣습니다. 가명처리·마스킹을 확인하십시오.", confidence=Confidence.REVIEW))
        return found


def _code_only(src: SourceFile, node: Node) -> str:
    """문자열 리터럴 안의 글자를 뺀 식(프롬프트 문장 속 '전화번호' 같은 단어는 필드가 아니다)"""
    from iron_laws.engine.taint import _text_without_plain_strings

    return _text_without_plain_strings(src, node)


def _js_param_names(src: SourceFile, param: Node) -> list[str]:
    names = []
    for n in walk(param):
        if n.type in ("identifier", "shorthand_property_identifier_pattern"):
            names.append(src.text_of(n))
    return names


AGENT_SURFACE_RULES = [LlmOutputExecutionRule, SystemPromptInjectionRule, McpServerToolRule, BrowserModelKeyRule, UncappedLlmCallRule, PiiToLlmRule]
