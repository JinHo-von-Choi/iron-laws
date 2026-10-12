"""
오철칙 JavaScript·TypeScript·Java 파일 간 해석 시험: 해석 범위의 각 형태마다 위험(지적 유지)과 정상(지적 없음)을 함께 둔다
작성자: 최진호
작성일: 2026-10-12
"""

from pathlib import Path

import pytest

from iron_laws.core.models import Confidence
from iron_laws.core.scanner import AuditScanner
from tests.helpers import lines_of as _all_lines


def lines_of(violations, rule_id, path):
    """외부 입력 도달이 확정된 지적만 센다(문자열 조합 자체를 의심하는 확인 필요 지적과 구분)."""
    return _all_lines([v for v in violations if v.confidence is Confidence.CONFIRMED], rule_id, path)

APP_HEAD = "const express = require('express');\nconst { exec } = require('child_process');\n"
ROUTE = "const app = express();\napp.get('/a', (req, res) => {{ exec({call}); }});\n"
PASS = "(v) => v"
SAFE = "(v) => 'uptime'"


def _scan(root: Path, files: dict[str, str]):
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    return AuditScanner(root).scan()


def _route_line(files: dict[str, str], entry: str) -> int:
    return files[entry].split("\n").index(next(line for line in files[entry].split("\n") if "exec(" in line)) + 1


def _cases():
    def esm(body):
        return {"lib/h.js": f"export const h = {body};\n", "app.js": "import { h } from './lib/h';\n" + APP_HEAD + ROUTE.format(call="h(req.query.a)")}

    def default(body):
        return {"lib/h.ts": f"export default {body.replace('(v)', 'function (v: string)').replace(' => ', ' { return ') + '; }'}\n", "app.ts": "import h from './lib/h';\n" + APP_HEAD + ROUTE.format(call="h(req.query.a)")}

    def namespace_alias(body):
        return {
            "tsconfig.json": '{\n  // 경로 별칭\n  "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["src/*"] } },\n}\n',
            "src/util/h.ts": f"export const h = {body};\n",
            "src/app.ts": "import * as U from '@/util/h';\n" + APP_HEAD + ROUTE.format(call="U.h(req.query.a)"),
        }

    def reexport(body):
        return {
            "lib/inner.js": f"export const h = {body};\n",
            "lib/index.js": "export { h as hh } from './inner';\n",
            "app.js": "import { hh } from './lib';\n" + APP_HEAD + ROUTE.format(call="hh(req.query.a)"),
        }

    def star(body):
        return {
            "lib/inner.js": f"export const h = {body};\n",
            "lib/index.js": "export * from './inner';\n",
            "app.js": "import { h } from './lib/index.js';\n" + APP_HEAD + ROUTE.format(call="h(req.query.a)"),
        }

    def cjs_destructure(body):
        return {"lib/h.js": f"const h = {body};\nmodule.exports = {{ h }};\n", "app.js": "const { h } = require('./lib/h');\n" + APP_HEAD + ROUTE.format(call="h(req.query.a)")}

    def cjs_member(body):
        return {"lib/h.js": f"exports.h = {body};\n", "app.js": "const lib = require('./lib/h');\n" + APP_HEAD + ROUTE.format(call="lib.h(req.query.a)")}

    def source_in_other_file(body):
        returned = "req.query[key]" if body == PASS else "'uptime'"
        return {"lib/h.js": f"export function read(req, key) {{\n  return {returned};\n}}\n", "app.js": "import { read } from './lib/h';\n" + APP_HEAD + ROUTE.format(call="read(req, 'a')")}

    return {
        "esm-named": esm,
        "esm-default": default,
        "tsconfig-alias-namespace": namespace_alias,
        "reexport-renamed": reexport,
        "reexport-star-js-suffix": star,
        "cjs-destructure": cjs_destructure,
        "cjs-member": cjs_member,
        "source-read-in-other-file": source_in_other_file,
    }


CASES = _cases()


@pytest.mark.parametrize("name", sorted(CASES))
def test_cross_file_forms_keep_risky_and_clear_sanitized(tmp_path: Path, name: str):
    risky = CASES[name](PASS)
    entry = next(k for k in risky if k.endswith(("app.js", "app.ts")))
    assert lines_of(_scan(tmp_path / "risky", risky).violations, "IL-504", entry) == [_route_line(risky, entry)], name
    safe = CASES[name](SAFE)
    assert lines_of(_scan(tmp_path / "safe", safe).violations, "IL-504", entry) == [], name


def test_ambiguous_candidate_files_are_a_gap_not_a_guess(tmp_path: Path):
    files = {
        "lib/h.js": "export const h = (v) => 'uptime';\n",
        "lib/h.ts": "export const h = (v: string) => 'uptime';\n",
        "app.js": "import { h } from './lib/h';\n" + APP_HEAD + ROUTE.format(call="h(req.query.a)"),
    }
    report = _scan(tmp_path, files)
    assert lines_of(report.violations, "IL-504", "app.js") == [_route_line(files, "app.js")]  # 어느 파일인지 정하지 않고, 인자의 오염이 그대로 전해진다고 본다
    assert report.metadata["cross_file"]["by_language"]["javascript"]["resolution_gaps"] == 1


def test_dynamic_import_and_computed_require_are_gaps(tmp_path: Path):
    files = {
        "lib/h.js": "export const h = (v) => 'uptime';\n",
        "app.js": "const name = './lib/h';\nconst { h } = require(name);\n" + APP_HEAD + ROUTE.format(call="h(req.query.a)"),
        "app2.mjs": "const { h } = await import('./lib/h.js');\n" + APP_HEAD + ROUTE.format(call="h(req.query.a)"),
    }
    report = _scan(tmp_path, files)
    assert lines_of(report.violations, "IL-504", "app.js") == [_route_line(files, "app.js")]
    assert lines_of(report.violations, "IL-504", "app2.mjs") == [_route_line(files, "app2.mjs")]
    assert report.metadata["cross_file"]["by_language"]["javascript"]["resolution_gaps"] == 2


def test_shadowed_import_name_is_not_resolved(tmp_path: Path):
    files = {
        "lib/h.js": "export const h = (v) => 'uptime';\n",
        "app.js": "import { h } from './lib/h';\n" + APP_HEAD + "function run(req, h) {\n  exec(h(req.query.a));\n}\n",
    }
    assert lines_of(_scan(tmp_path, files).violations, "IL-504", "app.js") == [5]


def test_import_cycle_terminates_and_keeps_the_finding(tmp_path: Path):
    files = {
        "lib/a.js": "import { b } from './b';\nexport function a(v) {\n  return b(v);\n}\n",
        "lib/b.js": "import { a } from './a';\nexport function b(v) {\n  return v ? a(v) : v;\n}\n",
        "app.js": "import { a } from './lib/a';\n" + APP_HEAD + ROUTE.format(call="a(req.query.a)"),
    }
    assert lines_of(_scan(tmp_path, files).violations, "IL-504", "app.js") == [5]


def test_package_import_is_not_a_gap(tmp_path: Path):
    files = {"app.js": "import { h } from 'some-package';\n" + APP_HEAD + ROUTE.format(call="h(req.query.a)")}
    report = _scan(tmp_path, files)
    assert report.metadata["cross_file"]["by_language"].get("javascript", {}).get("resolution_gaps", 0) == 0


JAVA_HELPER = "package com.app.util;\n\npublic class Text {{\n    public static String pass(String v) {{\n        return {ret};\n    }}\n}}\n"
JAVA_CALLER = (
    "package com.app.web;\n\n{imports}\nimport javax.servlet.http.HttpServletRequest;\n\npublic class Run {{\n"
    "    public void handle(HttpServletRequest request) throws Exception {{\n"
    "        String v = Text.pass(request.getParameter(\"c\"));\n"
    "        Runtime.getRuntime().exec(\"ls \" + v);\n    }}\n}}\n"
)


@pytest.mark.parametrize("ret,expected", [("v", [9]), ('"uptime"', [])])
def test_java_static_helper_in_another_file(tmp_path: Path, ret, expected):
    files = {
        "src/main/java/com/app/util/Text.java": JAVA_HELPER.format(ret=ret),
        "src/main/java/com/app/web/Run.java": JAVA_CALLER.format(imports="import com.app.util.Text;"),
    }
    assert lines_of(_scan(tmp_path, files).violations, "IL-504", "src/main/java/com/app/web/Run.java") == expected


def test_java_same_named_classes_are_a_gap(tmp_path: Path):
    files = {
        "src/main/java/com/a/Text.java": JAVA_HELPER.format(ret='"uptime"').replace("com.app.util", "com.a"),
        "src/main/java/com/b/Text.java": JAVA_HELPER.format(ret='"uptime"').replace("com.app.util", "com.b"),
        "src/main/java/com/app/web/Run.java": JAVA_CALLER.format(imports="import com.a.*;\nimport com.b.*;"),
    }
    report = _scan(tmp_path, files)
    assert lines_of(report.violations, "IL-504", "src/main/java/com/app/web/Run.java") == [10]
    assert report.metadata["cross_file"]["by_language"]["java"]["resolution_gaps"] == 1


def test_java_test_sources_are_not_candidates(tmp_path: Path):
    files = {
        "src/test/java/com/app/util/Text.java": JAVA_HELPER.format(ret='"uptime"'),
        "src/main/java/com/app/web/Run.java": JAVA_CALLER.format(imports="import com.app.util.Text;"),
    }
    assert lines_of(_scan(tmp_path, files).violations, "IL-504", "src/main/java/com/app/web/Run.java") == [9]


# ---- Java 주입 필드 ----
SERVICE = "package com.app.svc;\n\npublic interface NameService {\n    String name(String v);\n}\n"
IMPL = "package com.app.svc;\n\n{ann}public class {cls} implements NameService {{\n    public String name(String v) {{\n        return {ret};\n    }}\n}}\n"
CONTROLLER = (
    "package com.app.web;\n\nimport com.app.svc.NameService;\nimport javax.servlet.http.HttpServletRequest;\n\npublic class Ctl {\n"
    "    private final NameService names;\n\n    public Ctl(NameService names) {\n        this.names = names;\n    }\n\n"
    "    public void handle(HttpServletRequest request) throws Exception {\n"
    "        String v = names.name(request.getParameter(\"c\"));\n        Runtime.getRuntime().exec(\"ls \" + v);\n    }\n}\n"
)
CTL = "src/main/java/com/app/web/Ctl.java"
SINK_LINE = 15


def _java(files: dict[str, str]) -> dict[str, str]:
    return {"src/main/java/com/app/svc/NameService.java": SERVICE, CTL: CONTROLLER, **files}


@pytest.mark.parametrize("ret,expected", [("v", [SINK_LINE]), ('"uptime"', [])])
def test_java_injected_field_single_implementation(tmp_path: Path, ret, expected):
    files = _java({"src/main/java/com/app/svc/NameServiceImpl.java": IMPL.format(ann="", cls="NameServiceImpl", ret=ret)})
    assert lines_of(_scan(tmp_path, files).violations, "IL-504", CTL) == expected


def test_java_primary_implementation_is_chosen(tmp_path: Path):
    files = _java({
        "src/main/java/com/app/svc/SafeNames.java": IMPL.format(ann="@Primary\n", cls="SafeNames", ret='"uptime"'),
        "src/main/java/com/app/svc/RawNames.java": IMPL.format(ann="", cls="RawNames", ret="v"),
    })
    assert lines_of(_scan(tmp_path, files).violations, "IL-504", CTL) == []


@pytest.mark.parametrize("ann", ["", '@Profile("prod")\n'])
def test_java_ambiguous_or_profile_dependent_implementations_are_gaps(tmp_path: Path, ann):
    files = _java({
        "src/main/java/com/app/svc/SafeNames.java": IMPL.format(ann=ann, cls="SafeNames", ret='"uptime"'),
        "src/main/java/com/app/svc/OtherNames.java": IMPL.format(ann="", cls="OtherNames", ret='"date"'),
    })
    report = _scan(tmp_path, files)
    assert lines_of(report.violations, "IL-504", CTL) == [SINK_LINE]  # 정할 수 없으면 깨끗하다고 보지 않는다
    assert report.metadata["cross_file"]["by_language"]["java"]["resolution_gaps"] >= 1


def test_java_test_source_implementation_is_ignored(tmp_path: Path):
    files = _java({
        "src/main/java/com/app/svc/RawNames.java": IMPL.format(ann="", cls="RawNames", ret="v"),
        "src/test/java/com/app/svc/FakeNames.java": IMPL.format(ann="", cls="FakeNames", ret='"uptime"'),
    })
    assert lines_of(_scan(tmp_path, files).violations, "IL-504", CTL) == [SINK_LINE]
