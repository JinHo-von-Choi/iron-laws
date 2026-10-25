"""
승인 기록 서명과 체크포인트: 서명이 틀리거나(서명 필수면 없거나) 체크포인트 이전 기록이 줄거나 바뀐 승인은 쓰지 않는다
작성자: 최진호
작성일: 2026-10-26
"""

import json
import shutil
import subprocess
from datetime import date
from pathlib import Path

import pytest
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.approvals import ApprovalStore
from iron_laws.core.config import ConfigError
from tests.test_stage5_approvals import RULE, approve, make

pytestmark = pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen이 필요하다")
cli = CliRunner()


def keys(tmp_path: Path, name: str = "alice") -> tuple[Path, Path]:
    key = tmp_path / f"id_{name}"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key)], check=True)
    allowed = tmp_path / f"allowed_{name}"
    allowed.write_text(f'{name}@example.com namespaces="iron-laws-approval" {key.with_suffix(".pub").read_text().strip()}\n', encoding="utf-8")
    return key, allowed


def signed_store(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    project = make(tmp_path / "proj")
    store = tmp_path / "approvals.jsonl"
    key, allowed = keys(tmp_path)
    result = cli.invoke(app, ["approvals", "add", str(project), "--finding", RULE, "--reason", "내부 관리자 화면이며 입력이 사전 검증된다", "--store", str(store), "--sign-key", str(key)])
    assert result.exit_code == 0, result.output
    return project, store, key, allowed


def statuses(project: Path, store: Path, *args: str) -> list[str]:
    from iron_laws.core.scanner import AuditScanner

    scanner = AuditScanner(project, approvals=ApprovalStore(store, *args))
    scanner.scan()
    return [row.status for row in scanner.approval_rows]


def rewrite(store: Path, change) -> None:
    rows = [json.loads(line) for line in store.read_text(encoding="utf-8").splitlines()]
    change(rows)
    store.write_text("".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows), encoding="utf-8")


def test_signed_approval_is_used_and_signer_is_known(tmp_path: Path):
    project, store, _key, allowed = signed_store(tmp_path)
    assert statuses(project, store, allowed, True) == ["valid"]
    verified = ApprovalStore(store, allowed, True)
    assert verified.integrity().ok and list(verified.signers.values()) == ["alice@example.com"]
    assert cli.invoke(app, ["approvals", "verify", "--store", str(store), "--allowed-signers", str(allowed), "--require-signed"]).exit_code == 0


@pytest.mark.parametrize("tamper", ["reason", "fingerprint", "signature-removed", "other-signer"])
def test_tampered_or_foreign_signatures_are_rejected(tmp_path: Path, tamper: str):
    project, store, _key, allowed = signed_store(tmp_path)
    if tamper == "reason":
        rewrite(store, lambda rows: rows[0].update(reason="검토하지 않았지만 승인한다"))
    elif tamper == "fingerprint":
        rewrite(store, lambda rows: rows[0]["finding"].update(fingerprint="0" * 16))
    elif tamper == "signature-removed":
        rewrite(store, lambda rows: rows[0].pop("signature"))
    else:
        other_key, _other_allowed = keys(tmp_path, "mallory")
        from iron_laws.core.approvals import Record
        from iron_laws.evidence.signing import APPROVAL_NAMESPACE, sign_bytes

        rewrite(store, lambda rows: rows[0].update(signature=sign_bytes(Record(**rows[0]).signed_payload(), other_key, APPROVAL_NAMESPACE)))
    if tamper in ("reason", "fingerprint"):
        # 내용을 바꾸면 해시 사슬부터 깨진다. 공격자가 해시를 다시 계산해도 서명은 맞지 않는다
        from iron_laws.core.approvals import Record

        rewrite(store, lambda rows: rows[0].update(hash=Record(**rows[0]).compute_hash()))
    assert statuses(project, store, allowed, True) == ["invalid"]
    assert cli.invoke(app, ["approvals", "verify", "--store", str(store), "--allowed-signers", str(allowed), "--require-signed"]).exit_code == 1


def test_unsigned_approval_is_used_unless_signatures_are_required(tmp_path: Path):
    project = make(tmp_path / "proj")
    store = tmp_path / "approvals.jsonl"
    _key, allowed = keys(tmp_path)
    approve(project, store)
    assert statuses(project, store) == ["valid"]
    assert statuses(project, store, allowed) == ["valid"]
    assert statuses(project, store, allowed, True) == ["invalid"]
    assert "signature" not in store.read_text(encoding="utf-8")  # 서명 없는 기록의 줄 모양은 그대로다


def test_require_signed_needs_allowed_signers(tmp_path: Path):
    with pytest.raises(ConfigError):
        ApprovalStore(tmp_path / "a.jsonl", None, True)
    result = cli.invoke(app, ["check", str(make(tmp_path / "proj")), "--approvals", str(tmp_path / "a.jsonl"), "--require-signed-approvals"])
    assert result.exit_code == 2


def test_signature_survives_prune_rechaining(tmp_path: Path):
    project = make(tmp_path / "proj")
    store = tmp_path / "approvals.jsonl"
    key, allowed = keys(tmp_path)
    first = approve(project, store)
    assert cli.invoke(app, ["approvals", "revoke", first, "--store", str(store), "--reason", "다시 검토한다"]).exit_code == 0
    assert cli.invoke(app, ["approvals", "add", str(project), "--finding", RULE, "--reason", "다시 검토해 승인한다", "--store", str(store), "--sign-key", str(key)]).exit_code == 0
    assert ApprovalStore(store).prune(date(2999, 1, 1)) == 2
    remaining = ApprovalStore(store, allowed, True)
    assert remaining.records[0].seq == 1 and remaining.records[0].signature
    assert remaining.integrity().ok and statuses(project, store, allowed, True) == ["valid"]


def test_checkpoint_detects_truncation_rollback_and_rewrite(tmp_path: Path):
    project, store, key, allowed = signed_store(tmp_path)
    checkpoint = tmp_path / "outside" / "checkpoint.json"
    checkpoint.parent.mkdir()
    assert cli.invoke(app, ["approvals", "checkpoint", "--store", str(store), "-o", str(checkpoint), "--sign-key", str(key)]).exit_code == 0
    verify = ["approvals", "verify", "--store", str(store), "--allowed-signers", str(allowed), "--checkpoint", str(checkpoint)]
    assert cli.invoke(app, verify).exit_code == 0
    original = store.read_text(encoding="utf-8")

    store.write_text("", encoding="utf-8")  # 끝부분 삭제(전부)
    assert cli.invoke(app, verify).exit_code == 1

    store.write_text(original, encoding="utf-8")
    approve(project, store, reason="체크포인트 뒤에 더한 승인이다")  # 체크포인트 뒤 추가는 정상이다
    assert cli.invoke(app, verify).exit_code == 0

    rows = [json.loads(line) for line in store.read_text(encoding="utf-8").splitlines()]
    from iron_laws.core.approvals import GENESIS, Record

    rebuilt, previous = [], GENESIS
    for row in rows[1:]:  # 첫 승인을 지우고 사슬을 새로 이은 재작성
        record = Record(**row)
        record.seq, record.prev = len(rebuilt) + 1, previous
        record.hash = record.compute_hash()
        previous = record.hash
        rebuilt.append(record.line())
    store.write_text("".join(rebuilt), encoding="utf-8")
    assert ApprovalStore(store).integrity().ok  # 해시 사슬만으로는 알아채지 못한다
    assert cli.invoke(app, verify).exit_code == 1


def test_checkpoint_needs_allowed_signers_and_valid_signature(tmp_path: Path):
    _project, store, key, allowed = signed_store(tmp_path)
    checkpoint = tmp_path / "checkpoint.json"
    cli.invoke(app, ["approvals", "checkpoint", "--store", str(store), "-o", str(checkpoint), "--sign-key", str(key)])
    assert cli.invoke(app, ["approvals", "verify", "--store", str(store), "--checkpoint", str(checkpoint)]).exit_code == 2
    data = json.loads(checkpoint.read_text(encoding="utf-8"))
    checkpoint.write_text(json.dumps({**data, "count": 0}), encoding="utf-8")  # 서명 뒤 체크포인트를 고침
    assert cli.invoke(app, ["approvals", "verify", "--store", str(store), "--allowed-signers", str(allowed), "--checkpoint", str(checkpoint)]).exit_code == 1


def test_reapproval_in_the_same_second_gets_a_new_id(tmp_path: Path):
    project = make(tmp_path / "proj")
    store = tmp_path / "approvals.jsonl"
    first = approve(project, store)
    assert cli.invoke(app, ["approvals", "revoke", first, "--store", str(store), "--reason", "다시 검토한다"]).exit_code == 0
    second = approve(project, store)
    assert second != first
    rows = {a.id: a.revoked for a in ApprovalStore(store).approvals()}
    assert rows == {first: True, second: False}
    assert ApprovalStore(store).prune(date(2999, 1, 1)) == 2  # 철회한 첫 승인과 그 철회 기록만 지운다
