"""
오철칙 검증 기록(Receipt)·승인 기록 서명: OpenSSH 서명(ssh-keygen -Y)으로 파일 옆의 `<파일>.sig`나 기록 안의 서명 문자열을 남기고, 허용 서명자 목록으로 확인한다
서명 이름공간은 용도마다 고정한다(검증 기록 iron-laws-receipt, 승인 기록 iron-laws-approval). 다른 용도로 만든 서명을 받아들이지 않는다.
작성자: 최진호
작성일: 2026-10-12
"""

import shutil
import subprocess
import tempfile
from pathlib import Path

NAMESPACE = "iron-laws-receipt"
APPROVAL_NAMESPACE = "iron-laws-approval"


class SigningError(Exception):
    """서명하거나 확인할 수 없다"""


def _ssh_keygen() -> str:
    tool = shutil.which("ssh-keygen")
    if tool is None:
        raise SigningError("ssh-keygen을 찾을 수 없습니다(OpenSSH 8.2 이상 필요)")
    return tool


def signature_path(path: Path) -> Path:
    return path.with_name(path.name + ".sig")


def sign_file(path: Path, key: Path, namespace: str = NAMESPACE) -> Path:
    if not key.is_file():
        raise SigningError(f"서명 키가 없습니다: {key}")
    sig = signature_path(path)
    sig.unlink(missing_ok=True)
    done = subprocess.run([_ssh_keygen(), "-Y", "sign", "-f", str(key), "-n", namespace, str(path)], capture_output=True, text=True, timeout=60)
    if done.returncode != 0 or not sig.is_file():
        raise SigningError(f"서명하지 못했습니다: {done.stderr.strip()[:200]}")
    return sig


def sign_bytes(data: bytes, key: Path, namespace: str) -> str:
    """data에 대한 서명(ASCII armor 문자열)을 돌려준다."""
    if not key.is_file():
        raise SigningError(f"서명 키가 없습니다: {key}")
    done = subprocess.run([_ssh_keygen(), "-Y", "sign", "-f", str(key), "-n", namespace], input=data, capture_output=True, timeout=60)
    signature = done.stdout.decode("ascii", errors="replace")
    if done.returncode != 0 or "BEGIN SSH SIGNATURE" not in signature:
        raise SigningError(f"서명하지 못했습니다: {done.stderr.decode(errors='replace').strip()[:200]}")
    return signature


def verify_bytes(data: bytes, signature: str, allowed_signers: Path, namespace: str) -> str:
    """서명이 허용 서명자 목록의 키로 data에 대해 만들어졌으면 서명자 이름을 돌려준다. 아니면 SigningError"""
    tool = _ssh_keygen()
    with tempfile.TemporaryDirectory(prefix="iron-laws-sig-") as work:
        sig = Path(work) / "data.sig"
        sig.write_text(signature, encoding="ascii")
        found = subprocess.run([tool, "-Y", "find-principals", "-s", str(sig), "-f", str(allowed_signers)], capture_output=True, text=True, timeout=60)
        principals = [p for p in found.stdout.split() if p]
        if found.returncode != 0 or not principals:
            raise SigningError("허용 서명자 목록에 이 서명의 키가 없습니다")
        checked = subprocess.run([tool, "-Y", "verify", "-f", str(allowed_signers), "-I", principals[0], "-n", namespace, "-s", str(sig)], input=data, capture_output=True, timeout=60)
    if checked.returncode != 0:
        raise SigningError("서명이 이 내용과 맞지 않습니다(서명 뒤 내용이 바뀌었거나 다른 이름공간의 서명)")
    return principals[0]


def verify_file(path: Path, allowed_signers: Path, namespace: str = NAMESPACE) -> str:
    """서명이 허용 서명자 목록의 키로 이 파일 내용에 대해 만들어졌으면 서명자 이름을 돌려준다. 아니면 SigningError"""
    sig = signature_path(path)
    if not sig.is_file():
        raise SigningError(f"서명 파일이 없습니다: {sig.name}")
    return verify_bytes(path.read_bytes(), sig.read_text(encoding="ascii", errors="replace"), allowed_signers, namespace)
