"""
오철칙 LSP 서버(표준 입출력): 편집기에서 파일을 열거나 고치거나 저장하면 그 내용을 점검해 진단(diagnostics)으로 보낸다

- 지원 메시지: initialize, initialized, textDocument/didOpen·didChange(전체 동기화)·didSave·didClose, shutdown, exit
- 저장하지 않은 내용도 점검한다(임시 폴더에 같은 파일 이름으로 써서 점검). 한 파일 단위 점검이라 파일 간 흐름은 저장 후 check·audit로 본다.
- 심각도: CRITICAL·HIGH → Error, MEDIUM → Warning, LOW → Information. 확인 필요 지적은 메시지 앞에 표시한다.
작성자: 최진호
작성일: 2026-10-12
"""

import json
import sys
import tempfile
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import unquote, urlparse

LSP_SEVERITY = {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _read_message(stream: BinaryIO) -> dict[str, Any] | None:
    length = None
    while True:
        line = stream.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            break
        name, _, value = line.decode("ascii", errors="replace").partition(":")
        if name.lower() == "content-length":
            length = int(value.strip())
    if length is None:
        return None
    return json.loads(stream.read(length).decode("utf-8"))


def _write_message(stream: BinaryIO, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    stream.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body)
    stream.flush()


def diagnostics_for(uri: str, text: str) -> list[dict[str, Any]]:
    from iron_laws.core.scanner import AuditScanner

    name = Path(unquote(urlparse(uri).path)).name or "untitled.txt"
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / name
        target.write_text(text, encoding="utf-8")
        report = AuditScanner(Path(tmp)).scan()
    lines = text.split("\n")
    found = []
    for v in report.violations:
        line = max(0, v.line_number - 1)
        width = len(lines[line]) if line < len(lines) else 0
        prefix = "[확인 필요] " if v.confidence.value == "REVIEW" else ""
        found.append({
            "range": {"start": {"line": line, "character": 0}, "end": {"line": line, "character": width}},
            "severity": LSP_SEVERITY.get(v.severity.value, 3),
            "code": v.rule_id,
            "source": "iron-laws",
            "message": f"{prefix}{v.message}" + (f"\n고치는 방법: {v.how_to_fix}" if v.how_to_fix else ""),
        })
    return found


def serve(stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> int:
    reader = stdin or sys.stdin.buffer
    writer = stdout or sys.stdout.buffer
    documents: dict[str, str] = {}
    shutting_down = False
    while True:
        message = _read_message(reader)
        if message is None:
            return 0 if shutting_down else 1
        method, params, msg_id = message.get("method"), message.get("params") or {}, message.get("id")
        if method == "initialize":
            _write_message(writer, {"jsonrpc": "2.0", "id": msg_id, "result": {
                "capabilities": {"textDocumentSync": {"openClose": True, "change": 1, "save": {"includeText": True}}},
                "serverInfo": {"name": "iron-laws"},
            }})
        elif method == "shutdown":
            shutting_down = True
            _write_message(writer, {"jsonrpc": "2.0", "id": msg_id, "result": None})
        elif method == "exit":
            return 0 if shutting_down else 1
        elif method in ("textDocument/didOpen", "textDocument/didChange", "textDocument/didSave"):
            doc = params.get("textDocument") or {}
            uri = doc.get("uri", "")
            if method == "textDocument/didOpen":
                documents[uri] = doc.get("text", "")
            elif method == "textDocument/didChange" and params.get("contentChanges"):
                documents[uri] = params["contentChanges"][-1].get("text", documents.get(uri, ""))
            elif method == "textDocument/didSave" and params.get("text") is not None:
                documents[uri] = params["text"]
            if uri in documents:
                _write_message(writer, {"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics", "params": {"uri": uri, "diagnostics": diagnostics_for(uri, documents[uri])}})
        elif method == "textDocument/didClose":
            uri = (params.get("textDocument") or {}).get("uri", "")
            documents.pop(uri, None)
            _write_message(writer, {"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics", "params": {"uri": uri, "diagnostics": []}})
        elif msg_id is not None:
            _write_message(writer, {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"지원하지 않는 요청: {method}"}})
