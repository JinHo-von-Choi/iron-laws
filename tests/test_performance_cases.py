"""
오철칙 성능 위험 규칙(PERF) 사례 시험: 규칙마다 양성(지적해야 함)과 음성(지적하면 안 됨) 표본을 둔다.
표본은 개발팀이 직접 만들고 분류했다. 정적 점검이라 실제 느림을 측정하지 않으며 열거한 음성 표본의 오탐 0은 일반 오탐률 0을 뜻하지 않는다.
작성자: 최진호
작성일: 2026-10-05
"""

from pathlib import Path

import pytest

from iron_laws.core.scanner import AuditScanner
from tests.helpers import lines_of

QUERIES = "def handler(db, uid):\n" + "".join(f"    v{i} = db.query_x{i}(uid)\n" for i in range(5)) + "    return v0\n"
FOUR_QUERIES = "def handler(db, uid):\n" + "".join(f"    v{i} = db.query_x{i}(uid)\n" for i in range(4)) + "    return v0\n"

CASES: list[tuple[str, str, dict[str, str], dict[str, list[int]]]] = [
    # ---- PERF-101 한 함수 안의 DB 조회 과다
    ("many-queries-py", "PERF-101", {"a.py": QUERIES}, {"a.py": [2]}),
    ("four-queries-py", "PERF-101", {"a.py": FOUR_QUERIES}, {}),
    ("queries-split-over-functions", "PERF-101", {"a.py": FOUR_QUERIES + "\ndef other(db, uid):\n    return db.query_y(uid)\n"}, {}),
    ("queries-in-loop-left-to-arc212", "PERF-101", {"a.py": "def f(db, ids):\n    for i in ids:\n        db.query_a(i)\n        db.query_b(i)\n        db.query_c(i)\n        db.query_d(i)\n        db.query_e(i)\n"}, {}),
    ("many-queries-in-test-file", "PERF-101", {"test_a.py": QUERIES}, {}),
    ("many-queries-in-migration", "PERF-101", {"migrations/0001.py": QUERIES}, {}),
    # ---- PERF-102 중첩 반복과 리스트 찾기
    ("cross-product-loops", "PERF-102", {"a.py": "def f(A, B):\n    for a in A:\n        for b in B:\n            if a.id == b.id:\n                print(a)\n"}, {"a.py": [3]}),
    ("triple-loops", "PERF-102", {"a.py": "def f(A, B, C):\n    for a in A:\n        for b in B:\n            for c in C:\n                print(a, b, c)\n"}, {"a.py": [3, 4]}),
    ("comprehension-cross-product", "PERF-102", {"a.py": "def f(A, B):\n    return [(a, b) for a in A for b in B]\n"}, {"a.py": [2]}),
    ("rows-and-cells", "PERF-102", {"a.py": "def f(grid):\n    for row in grid:\n        for cell in row:\n            print(cell)\n"}, {}),
    ("constant-small-range", "PERF-102", {"a.py": "def f():\n    for i in range(3):\n        for j in range(3):\n            print(i, j)\n"}, {}),
    ("constant-small-tuple", "PERF-102", {"a.py": "def f(A):\n    for a in A:\n        for d in (1, 2, 3):\n            print(a, d)\n"}, {}),
    ("outer-loop-constant", "PERF-102", {"a.py": "def f(B):\n    for i in range(2):\n        for b in B:\n            print(i, b)\n"}, {}),
    ("grid-of-two-ranges", "PERF-102", {"a.py": "def f(rows, cols):\n    for r in range(rows):\n        for c in range(cols):\n            print(r, c)\n"}, {}),
    ("range-len-quadratic", "PERF-102", {"a.py": "def f(items):\n    for i in range(len(items)):\n        for j in range(len(items)):\n            print(i, j)\n"}, {"a.py": [3]}),
    ("inner-iterable-derived-from-outer-item", "PERF-102", {"a.py": "def f(files):\n    for f in files:\n        root = parse(f)\n        nodes = root.children\n        for n in nodes:\n            print(n)\n"}, {}),
    ("inner-loop-inside-while-menu", "PERF-102", {"a.py": "def f(demos):\n    while True:\n        for d in demos:\n            d()\n"}, {}),
    ("c-style-index-loops-with-constant-bound", "PERF-102", {"a.js": "function f(a, b) {\n  for (let i = 0; i < 9; i++) {\n    for (let j = 0; j < 9; j++) {\n      if (a[i][j] !== b[i][j]) return false;\n    }\n  }\n}\n"}, {}),
    ("c-style-loops-over-length-are-quadratic", "PERF-102", {"a.js": "function f(a) {\n  for (let i = 0; i < a.length; i++) {\n    for (let j = 0; j < a.length; j++) {\n      if (a[i] === a[j]) console.log(i);\n    }\n  }\n}\n"}, {"a.js": [3]}),
    ("membership-in-small-fixed-list", "PERF-102", {"a.py": "def f(items):\n    valid = ['a', 'b', 'c']\n    for x in items:\n        if x in valid:\n            print(x)\n"}, {}),
    ("c-style-inner-bound-derived-from-outer-item", "PERF-102", {"a.js": "function f(groups) {\n  for (let gi = 0; gi < groups.length; gi++) {\n    const group = groups[gi];\n    for (let hi = 0; hi < group.hooks.length; hi++) {\n      check(group.hooks[hi]);\n    }\n  }\n}\n"}, {}),
    ("tuple-assignment-derived-from-outer-item", "PERF-102", {"a.py": "def f(names, wb_f, wb_v):\n    for name in names:\n        ws_f, ws_v = wb_f[name], wb_v[name]\n        for row in ws_f.iter_rows():\n            print(row)\n"}, {}),
    ("container-filled-from-outer-item", "PERF-102", {"a.py": "def f(parents):\n    for parent in parents:\n        to_remove = []\n        for child in parent.children:\n            to_remove.append(child)\n        for elem in to_remove:\n            parent.remove(elem)\n"}, {}),
    ("constant-name-collections-are-enumerations", "PERF-102", {"a.js": "function f(buckets) {\n  for (const b of buckets) {\n    for (const o of OBSERVED_OUTCOMES) {\n      use(b, o);\n    }\n  }\n}\n"}, {}),
    ("list-membership-in-loop", "PERF-102", {"a.py": "def f(items):\n    seen = []\n    for x in items:\n        if x in seen:\n            continue\n        seen.append(x)\n"}, {"a.py": [4]}),
    ("set-membership-in-loop", "PERF-102", {"a.py": "def f(items):\n    seen = set()\n    for x in items:\n        if x in seen:\n            continue\n        seen.add(x)\n"}, {}),
    ("membership-outside-loop", "PERF-102", {"a.py": "def f(x):\n    seen = [1, 2]\n    return x in seen\n"}, {}),
    ("membership-on-unknown-type", "PERF-102", {"a.py": "def f(items, seen):\n    for x in items:\n        if x in seen:\n            print(x)\n"}, {}),
    ("js-includes-in-loop", "PERF-102", {"a.js": "function f(items) {\n  const seen = [];\n  for (const x of items) {\n    if (seen.includes(x)) continue;\n    seen.push(x);\n  }\n}\n"}, {"a.js": [4]}),
    ("js-set-has-in-loop", "PERF-102", {"a.js": "function f(items) {\n  const seen = new Set();\n  for (const x of items) {\n    if (seen.has(x)) continue;\n    seen.add(x);\n  }\n}\n"}, {}),
    ("js-cross-product", "PERF-102", {"a.js": "function f(A, B) {\n  for (const a of A) {\n    for (const b of B) {\n      if (a.id === b.id) console.log(a);\n    }\n  }\n}\n"}, {"a.js": [3]}),
    # ---- PERF-103 반복 안의 비싼 작업
    ("http-in-loop", "PERF-103", {"a.py": "import requests\ndef f(urls):\n    for u in urls:\n        requests.get(u)\n"}, {"a.py": [4]}),
    ("file-open-per-item-is-not-flagged", "PERF-103", {"a.py": "def f(names):\n    for n in names:\n        data = open(n).read()\n        print(data)\n"}, {}),
    ("subprocess-per-item-is-not-flagged", "PERF-103", {"a.py": "import subprocess\ndef f(cmds):\n    for c in cmds:\n        subprocess.run(c)\n"}, {}),
    ("await-http-in-loop", "PERF-103", {"a.py": "async def f(urls, client):\n    for u in urls:\n        r = await client.get(u)\n        print(r)\n"}, {"a.py": [3]}),
    ("await-http-in-retry-loop", "PERF-103", {"a.py": "async def f(client, n):\n    for attempt in range(n):\n        r = await client.get('x')\n        if r:\n            return r\n"}, {}),
    ("await-http-in-js-retry-loop", "PERF-103", {"a.js": "async function f(n) {\n  for (let attempt = 0; attempt < n; attempt++) {\n    const r = await fetch('x');\n    if (r.ok) return r;\n  }\n}\n"}, {}),
    ("await-sleep-in-retry-loop", "PERF-103", {"a.py": "import asyncio\nasync def f(n):\n    for i in range(n):\n        await asyncio.sleep(1)\n"}, {}),
    ("await-sequential-ui-step-is-not-flagged", "PERF-103", {"a.js": "async function f(page, vps) {\n  for (const vp of vps) {\n    await page.screenshot({ path: vp.name });\n  }\n}\n"}, {}),
    ("await-in-while-polling-loop", "PERF-103", {"a.py": "async def f(client):\n    while True:\n        r = await client.get('x')\n        if r:\n            break\n"}, {}),
    ("js-fetch-in-loop", "PERF-103", {"a.js": "async function f(urls) {\n  for (const u of urls) {\n    const r = await fetch(u);\n    console.log(r);\n  }\n}\n"}, {"a.js": [3]}),
    ("http-outside-loop", "PERF-103", {"a.py": "import requests\ndef f(u):\n    return requests.get(u)\n"}, {}),
    ("http-in-small-constant-loop", "PERF-103", {"a.py": "import requests\ndef f():\n    for u in ('a', 'b'):\n        requests.get(u)\n"}, {}),
    ("gather-instead-of-loop-await", "PERF-103", {"a.py": "import asyncio\nasync def f(urls, get):\n    return await asyncio.gather(*(get(u) for u in urls))\n"}, {}),
    # ---- PERF-104 한도 없는 조회
    ("select-star-no-where", "PERF-104", {"a.py": "def f(cur):\n    cur.execute('SELECT * FROM users')\n"}, {"a.py": [2]}),
    ("select-with-where", "PERF-104", {"a.py": "def f(cur):\n    cur.execute('SELECT * FROM users WHERE id = 1')\n"}, {}),
    ("select-with-limit", "PERF-104", {"a.py": "def f(cur):\n    cur.execute('SELECT * FROM users LIMIT 50')\n"}, {}),
    ("fetchall", "PERF-104", {"a.py": "def f(cur):\n    return cur.fetchall()\n"}, {"a.py": [2]}),
    ("fetchall-after-bounded-query", "PERF-104", {"a.py": "def f(cur):\n    cur.execute('SELECT id FROM t WHERE state = 1')\n    return cur.fetchall()\n"}, {}),
    ("fetchall-after-limited-query", "PERF-104", {"a.py": "def f(cur):\n    cur.execute('SELECT id FROM t LIMIT 100')\n    return cur.fetchall()\n"}, {}),
    ("aggregate-query-without-where", "PERF-104", {"a.py": "def f(cur):\n    cur.execute('SELECT host, COUNT(*) FROM cookies GROUP BY host')\n"}, {}),
    ("fetchmany", "PERF-104", {"a.py": "def f(cur):\n    return cur.fetchmany(100)\n"}, {}),
    ("orm-all", "PERF-104", {"a.py": "def f(User):\n    return User.objects.all()\n"}, {"a.py": [2]}),
    ("orm-all-sliced", "PERF-104", {"a.py": "def f(User):\n    return User.objects.all()[:50]\n"}, {}),
    ("java-findall-no-args", "PERF-104", {"A.java": "class A {\n  Object f(UserRepository userRepository) {\n    return userRepository.findAll();\n  }\n}\n"}, {"A.java": [3]}),
    ("java-findall-pageable", "PERF-104", {"A.java": "class A {\n  Object f(UserRepository userRepository, Pageable pageable) {\n    return userRepository.findAll(pageable);\n  }\n}\n"}, {}),
    ("js-findmany-no-args", "PERF-104", {"a.js": "async function f(prisma) {\n  return prisma.user.findMany();\n}\n"}, {"a.js": [2]}),
    ("js-findmany-take", "PERF-104", {"a.js": "async function f(prisma) {\n  return prisma.user.findMany({ take: 50 });\n}\n"}, {}),
    # ---- PERF-105 비동기 안의 막는 호출
    ("async-time-sleep", "PERF-105", {"a.py": "import time\nasync def f():\n    time.sleep(1)\n"}, {"a.py": [3]}),
    ("async-requests", "PERF-105", {"a.py": "import requests\nasync def f():\n    return requests.get('http://x')\n"}, {"a.py": [3]}),
    ("async-await-sleep", "PERF-105", {"a.py": "import asyncio\nasync def f():\n    await asyncio.sleep(1)\n"}, {}),
    ("sync-function-sleep", "PERF-105", {"a.py": "import time\ndef f():\n    time.sleep(1)\n"}, {}),
    ("nested-sync-in-async", "PERF-105", {"a.py": "import time\nasync def f():\n    def inner():\n        time.sleep(1)\n    return inner\n"}, {}),
    ("js-async-readfilesync-in-server-file", "PERF-105", {"a.js": "const express = require('express');\nconst fs = require('fs');\nasync function f() {\n  return fs.readFileSync('x');\n}\n"}, {"a.js": [4]}),
    ("js-async-readfilesync-in-cli-script", "PERF-105", {"a.js": "const fs = require('fs');\nasync function f() {\n  return fs.readFileSync('x');\n}\n"}, {}),
    ("js-sync-function-readfilesync", "PERF-105", {"a.js": "const fs = require('fs');\nfunction f() {\n  return fs.readFileSync('x');\n}\n"}, {}),
    # ---- 실제 프로젝트 표본 분류에서 나온 오탐 유형(반복 안 비교·순차 요청이 설계상 맞는 경우)
    ("string-containment-is-not-list-search", "PERF-102", {"a.py": "def f(path):\n    for line in open(path):\n        key = line.split('=')[1].strip()\n        if 'x' in key:\n            print(key)\n"}, {}),
    ("as-const-literal-is-small-enumeration", "PERF-102", {"a.ts": "function f(hosts: string[]) {\n  for (const h of hosts) {\n    for (const v of ['lite', 'full', 'plan'] as const) {\n      use(h, v);\n    }\n  }\n}\n"}, {}),
    ("slice-to-three-is-bounded", "PERF-102", {"a.py": "def f(files):\n    for f in files:\n        for e in list(f.errors)[:3]:\n            print(e)\n"}, {}),
    ("underscore-prefixed-constant-list", "PERF-102", {"a.py": "def f(blocks):\n    for b in blocks:\n        for p in _TITLE_PATTERNS:\n            p.search(b)\n"}, {}),
    ("small-literal-variable-is-enumeration", "PERF-102", {"a.py": "def f(elems):\n    attrs = ['id', 'embed', 'link']\n    for e in elems:\n        for a in attrs:\n            e.get(a)\n"}, {}),
    ("per-chunk-lines-are-not-independent", "PERF-102", {"a.js": "async function f(stream) {\n  let buffer = '';\n  for await (const chunk of stream) {\n    buffer += chunk;\n    const lines = buffer.split('\\n');\n    for (const line of lines) {\n      use(line);\n    }\n  }\n}\n"}, {}),
    ("polling-loop-await-is-sequential", "PERF-103", {"a.ts": "async function f(ref) {\n  for (;;) {\n    const r = await fetch(`/status/${ref}`);\n    if (r.ok) break;\n  }\n}\n"}, {}),
    ("deadline-loop-await-is-sequential", "PERF-103", {"a.ts": "async function f(url, start) {\n  while (Date.now() - start < 15000) {\n    const r = await fetch(url);\n    use(r);\n  }\n}\n"}, {}),
    ("first-success-wins-fallback-chain", "PERF-103", {"a.py": "import requests\ndef f(cands):\n    for c in cands:\n        r = requests.get(c)\n        if r.ok:\n            return r\n"}, {}),
    ("paged-requests-are-sequential", "PERF-103", {"a.py": "import requests\ndef f(chunks):\n    for chunk in chunks:\n        requests.post('u', json=chunk)\n"}, {}),
    ("await-with-api-word-only-in-arguments", "PERF-103", {"a.js": "async function f(items) {\n  for (const i of items) {\n    await verifyRewrite({ api: i });\n  }\n}\n"}, {}),
    ("independent-awaited-fetches-still-flagged", "PERF-103", {"a.js": "async function f(ids) {\n  for (const id of ids) {\n    await fetch(`/c/${id}`, { method: 'POST' });\n  }\n}\n"}, {"a.js": [3]}),
    ("dp-table-fill-reads-neighbor-cells", "PERF-102", {"a.ts": "function lcs(a: string[], b: string[]) {\n  const m: number[][] = [];\n  for (let i = 1; i <= a.length; i++) {\n    for (let j = 1; j <= b.length; j++) {\n      m[i][j] = a[i - 1] === b[j - 1] ? m[i - 1][j - 1] + 1 : 0;\n    }\n  }\n}\n"}, {}),
    ("constant-attribute-chain-is-enumeration", "PERF-102", {"a.js": "function f() {\n  for (const l of MATRIX.languages) {\n    for (const c of MATRIX.classes) {\n      use(l, c);\n    }\n  }\n}\n"}, {}),
    ("try-wrapped-assignment-is-derived-from-outer-item", "PERF-102", {"a.ts": "function f(order) {\n  for (const { root } of order) {\n    let entries;\n    try { entries = fs.readdirSync(root); } catch { continue; }\n    for (const e of entries) {\n      use(e);\n    }\n  }\n}\n"}, {}),
]


@pytest.mark.parametrize(("case_id", "rule_id", "files", "expected"), CASES, ids=[c[0] for c in CASES])
def test_case(tmp_path: Path, case_id: str, rule_id: str, files: dict[str, str], expected: dict[str, list[int]]):
    for rel, content in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    violations = AuditScanner(tmp_path).scan().violations
    actual = {path: lines_of(violations, rule_id, path) for path in files}
    actual = {p: sorted(set(ls)) for p, ls in actual.items() if ls}
    assert actual == expected, f"{case_id}: 기대 {expected}, 실제 {actual}"


def test_a_loop_query_flagged_by_arc212_is_not_flagged_again(tmp_path: Path):
    (tmp_path / "a.py").write_text("def f(db, ids):\n    for i in ids:\n        db.query_a(i)\n", encoding="utf-8")
    rules = {v.rule_id for v in AuditScanner(tmp_path).scan().violations}
    assert "ARC-212" in rules and "PERF-101" not in rules


def test_every_perf_finding_needs_review_and_has_plain_advice(tmp_path: Path):
    (tmp_path / "a.py").write_text("def f(A, B):\n    for a in A:\n        for b in B:\n            print(a, b)\n", encoding="utf-8")
    perf = [v for v in AuditScanner(tmp_path).scan().violations if v.rule_id.startswith("PERF")]
    assert perf and all(v.confidence.value == "REVIEW" and v.plain and v.how_to_fix for v in perf)
    assert all("1,000" in v.plain or "급격히" in v.plain or "느립니다" in v.plain or "멈" in v.plain or "메모리" in v.plain or "기다" in v.plain or "되풀이" in v.plain for v in perf)
