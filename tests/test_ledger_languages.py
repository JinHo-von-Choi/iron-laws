"""
근거 장부의 Java·JavaScript·TypeScript 확장: 위험 호출마다 지점을 만들고, 확신이 없으면 '확인 못 함'으로 남긴다
작성자: 최진호
작성일: 2026-10-26
"""

from pathlib import Path

from iron_laws.core.scanner import AuditScanner

JAVA = """import java.sql.*;
import javax.servlet.http.*;
public class Svc {
  public void a(HttpServletRequest request, Connection conn) throws Exception {
    conn.createStatement().executeQuery("SELECT * FROM t WHERE id = '" + request.getParameter("id") + "'");
  }
  public void b(Connection conn) throws Exception {
    conn.createStatement().executeQuery("SELECT * FROM t");
  }
  public void c(Connection conn, String name) throws Exception {
    conn.createStatement().executeQuery("SELECT * FROM t WHERE n = '" + name + "'");
  }
  public void d(Connection conn) throws Exception {
    int n = 3;
    String v = (n > 5) ? System.getenv("X") : "fixed";
    conn.createStatement().executeQuery("SELECT * FROM t WHERE n = '" + v + "'");
  }
}
"""

JS = """const express = require('express')
const fs = require('fs')
const app = express()
app.get('/a', (req, res) => {
  db.query('SELECT * FROM t WHERE id = ' + req.query.id)
  fs.readFile('/srv/data/' + req.query.f, () => {})
  config.get('server.port')
})
"""


def points(tmp_path: Path, name: str, code: str) -> dict[int, tuple[str, str, str]]:
    (tmp_path / name).write_text(code, encoding="utf-8")
    ledger = AuditScanner(tmp_path).scan().coverage_ledger
    return {p.line: (p.family, p.state, p.evidence_kind) for p in ledger.points}


def test_java_points_are_classified(tmp_path):
    found = points(tmp_path, "Svc.java", JAVA)
    assert found[5] == ("sql", "evidence_met", "finding")
    assert found[8] == ("sql", "evidence_met", "closed_value")
    assert found[11][:2] == ("sql", "unresolved")  # 매개변수 값은 출처를 확정하지 못한다
    assert found[16] == ("sql", "evidence_met", "closed_value")  # 상수 조건이라 환경변수 갈래는 실행되지 않는다


def test_javascript_points_skip_non_database_calls(tmp_path):
    found = points(tmp_path, "app.js", JS)
    assert found[5][:2] == ("sql", "evidence_met") and found[6][0] == "path"
    assert 4 not in found and 7 not in found  # 라우터 app.get, 설정 config.get은 SQL 지점이 아니다
