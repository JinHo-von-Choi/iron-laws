"""
오철칙 LSP 서버 시험: 실제 프로세스와 Content-Length 틀의 JSON-RPC로 주고받는다
작성자: 최진호
작성일: 2026-10-12
"""

import json
import subprocess
import sys


def _frame(payload: dict) -> bytes:
    body = json.dumps(payload).encode("utf-8")
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body


def _read_all(raw: bytes) -> list[dict]:
    messages = []
    while raw:
        header, _, rest = raw.partition(b"\r\n\r\n")
        length = int(header.split(b":")[1])
        messages.append(json.loads(rest[:length]))
        raw = rest[length:]
    return messages


def test_lsp_publishes_diagnostics_for_unsaved_text():
    code = "import os\nfrom flask import request\n\ndef run():\n    os.system('ls ' + request.args['d'])\n"
    uri = "file:///work/app.py"
    stdin = b"".join([
        _frame({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}}),
        _frame({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
        _frame({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {"textDocument": {"uri": uri, "languageId": "python", "version": 1, "text": code}}}),
        _frame({"jsonrpc": "2.0", "method": "textDocument/didChange", "params": {"textDocument": {"uri": uri, "version": 2}, "contentChanges": [{"text": "x = 1\n"}]}}),
        _frame({"jsonrpc": "2.0", "id": 2, "method": "shutdown"}),
        _frame({"jsonrpc": "2.0", "method": "exit"}),
    ])
    done = subprocess.run([sys.executable, "-c", "import sys; from iron_laws.cli import app; sys.exit(app())", "lsp"], input=stdin, capture_output=True, timeout=120)
    assert done.returncode == 0, done.stderr.decode()
    messages = _read_all(done.stdout)
    assert messages[0]["result"]["capabilities"]["textDocumentSync"]["change"] == 1
    published = [m["params"] for m in messages if m.get("method") == "textDocument/publishDiagnostics"]
    first = published[0]["diagnostics"]
    hit = next(d for d in first if d["code"] == "IL-504")
    assert hit["range"]["start"]["line"] == 4 and hit["severity"] == 1 and hit["source"] == "iron-laws"
    assert not any(d["code"] == "IL-504" for d in published[1]["diagnostics"])  # 고친 내용으로 다시 보낸다
