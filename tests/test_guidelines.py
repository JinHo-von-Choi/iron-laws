"""
지침 강제 대응표: 내보낸 지침은 다시 대조하면 같은 규칙으로 돌아오고, 강제 수단 꼬리표는 규칙 메타데이터와 맞는다
작성자: 최진호
작성일: 2026-10-26
"""

import json

import pytest
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.guidelines import (
    check_guidelines,
    enforcement_table,
    export_guidelines,
    extract_directives,
)
from iron_laws.core.models import Severity
from iron_laws.rules.catalog import ALL_RULES

RULES = [cls() for cls in ALL_RULES]


def test_exported_lines_map_back_to_their_rules():
    text = export_guidelines(RULES)
    exported = [line for line in text.splitlines() if line.startswith("- ") and "[" in line and "(" in line and "차단:" not in line]
    result = check_guidelines(text, RULES)
    mapped = {r["rule_id"] for row in result["rows"] for r in row["rules"]}
    assert len(exported) == len(enforcement_table(RULES))
    assert mapped == set(enforcement_table(RULES))


def test_tags_follow_severity_threshold_and_executed_families():
    table = enforcement_table(RULES, Severity.HIGH)
    for rule in RULES:
        if rule.rule_id in table:
            assert table[rule.rule_id].blocking is (rule.severity in (Severity.HIGH, Severity.CRITICAL))
    assert {r for r, e in table.items() if e.executed} == {"IL-501", "IL-502", "IL-504"}
    assert not enforcement_table(RULES, Severity.CRITICAL)["IL-502"].blocking


def test_language_filter_drops_rules_that_do_not_apply():
    python = enforcement_table(RULES, languages={"python"})
    assert "IL-514" not in python and "TYP-301" not in python and "TYP-302" in python
    assert all(set(e.verified_languages) <= {"python"} for e in python.values())


def test_directive_extraction_skips_code_and_headings():
    text = "# Never do this heading\n```\nnever inside code\n```\n- Never log passwords.\n- 예외를 조용히 삼키지 않는다.\nplain note\n"
    found = extract_directives(text)
    assert [d.line for d in found] == [5, 6]
    assert "IL-301" in found[1].rules


@pytest.mark.parametrize("line, rule", [
    ("Always use parameterized SQL queries.", "IL-501"),
    ("Never build shell commands from user input.", "IL-504"),
    ("Do not use pickle for untrusted data.", "IL-515"),
    ("Never disable TLS certificate verification.", "IL-106"),
    ("Avoid `any` in TypeScript.", "TYP-301"),
    ("Must follow IL-503 even when tests pass.", "IL-503"),
    ("Do not push to main without review.", None),
])
def test_topic_mapping(line, rule):
    found = extract_directives(line)
    assert len(found) == 1
    assert (rule in found[0].rules) if rule else found[0].rules == []


def test_explicit_rule_ids_take_precedence_over_topics():
    found = extract_directives("Never use eval or SQL strings (IL-503).")
    assert found[0].rules == ["IL-503"] and found[0].topics == []


def test_check_cli_exit_codes(tmp_path):
    runner = CliRunner()
    guide = tmp_path / "CLAUDE.md"
    guide.write_text("- Never commit secrets.\n- Do not push to main without review.\n", encoding="utf-8")
    ok = runner.invoke(app, ["guidelines", "check", str(guide), "--format", "json"])
    assert ok.exit_code == 0
    assert json.loads(ok.stdout)["counts"] == {"blocking": 1, "reported": 0, "none": 1}
    assert runner.invoke(app, ["guidelines", "check", str(guide), "--fail-on-unenforced"]).exit_code == 1
    assert runner.invoke(app, ["guidelines", "check", str(guide), "--lang", "cobol"]).exit_code == 2
    assert runner.invoke(app, ["guidelines", "export", "--fail-on", "SEVERE"]).exit_code == 2


def test_topic_words_outside_the_directive_sentence_do_not_count():
    assert extract_directives("- `pkg/` holds servers, logger, jwt, postgres. Must not import internal.")[0].rules == []
    assert extract_directives("**Why:** we moved away from innerHTML for speed. Do not revert!")[0].rules == []
    private_key = extract_directives("The private key is stored on the maintainer machine. It is never committed.")[0]
    assert "AI-104" in private_key.rules  # 대명사로 시작하는 지시 문장은 앞 문장의 주제를 이어받는다


def test_narrower_topic_replaces_the_general_one():
    found = extract_directives("Passwords must be at least 8 characters long.")[0]
    assert found.topics == ["비밀번호 정책"] and found.rules == ["IL-110"]
