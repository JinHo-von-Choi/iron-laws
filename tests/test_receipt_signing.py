"""
오철칙 검증 기록 서명 시험: ssh-keygen -Y로 서명하고 허용 서명자 목록으로 확인한다. 기록이 바뀌면 서명 확인이 실패한다.
작성자: 최진호
작성일: 2026-10-12
"""

import difflib
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from iron_laws.cli import app

runner = CliRunner()
pytestmark = pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen이 필요하다")
ORIGINAL = "import os\nimport subprocess\nfrom flask import request\n\n\ndef run():\n    os.system('ls ' + request.args['d'])\n"


def _setup(tmp_path: Path) -> tuple[Path, Path, Path]:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text(ORIGINAL, encoding="utf-8")
    fixed = ORIGINAL.replace("os.system('ls ' + request.args['d'])", "subprocess.run(['ls', request.args['d']], check=False)")
    patch = tmp_path / "fix.diff"
    patch.write_text("".join(difflib.unified_diff(ORIGINAL.splitlines(True), fixed.splitlines(True), "a/app.py", "b/app.py")), encoding="utf-8")
    key = tmp_path / "id_ed25519"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "tester", "-f", str(key)], check=True)
    allowed = tmp_path / "allowed_signers"
    allowed.write_text(f'tester@example.com namespaces="iron-laws-receipt" {(tmp_path / "id_ed25519.pub").read_text().strip()}\n', encoding="utf-8")
    return project, patch, allowed


def test_sign_and_verify_receipt(tmp_path: Path):
    project, patch, allowed = _setup(tmp_path)
    out = tmp_path / "receipt.json"
    result = runner.invoke(app, ["verify-patch", str(project), "--patch", str(patch), "--finding", "IL-504@app.py:7", "--runner", "none", "--no-require-tests", "--out", str(out), "--sign", f"ssh:{tmp_path / 'id_ed25519'}"])
    assert out.is_file() and (tmp_path / "receipt.json.sig").is_file(), result.output
    ok = runner.invoke(app, ["evidence", "verify", str(out), "--allowed-signers", str(allowed), "--json"])
    payload = json.loads(ok.stdout)
    assert not [p for p in payload["problems"] if p["code"].startswith("signature")] and any("tester@example.com" in n for n in payload["notes"])
    data = json.loads(out.read_text(encoding="utf-8"))
    data["created"] = "2000-01-01T00:00:00Z"
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    bad = runner.invoke(app, ["evidence", "verify", str(out), "--allowed-signers", str(allowed), "--json"])
    assert bad.exit_code == 1 and any(p["code"] == "signature.invalid" for p in json.loads(bad.stdout)["problems"])


def test_missing_signature_and_sign_without_out(tmp_path: Path):
    project, patch, allowed = _setup(tmp_path)
    out = tmp_path / "receipt.json"
    runner.invoke(app, ["verify-patch", str(project), "--patch", str(patch), "--runner", "none", "--no-require-tests", "--out", str(out)])
    missing = runner.invoke(app, ["evidence", "verify", str(out), "--allowed-signers", str(allowed), "--json"])
    assert missing.exit_code == 1 and any(p["code"] == "signature.invalid" for p in json.loads(missing.stdout)["problems"])
    no_out = runner.invoke(app, ["verify-patch", str(project), "--patch", str(patch), "--runner", "none", "--no-require-tests", "--sign", f"ssh:{tmp_path / 'id_ed25519'}"])
    assert no_out.exit_code == 2
