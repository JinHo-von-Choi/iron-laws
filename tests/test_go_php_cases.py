"""
오철칙 Go·PHP 보안 규칙 양성·음성 사례 시험(깊은 지원: 외부 입력 흐름과 정제를 언어마다 확인한다)
작성자: 최진호
작성일: 2026-10-12
"""

from pathlib import Path

import pytest

from tests.helpers import lines_of

GO = 'package main\n\nimport (\n\t"database/sql"\n\t"net/http"\n\t"os"\n\t"os/exec"\n)\n\n'
PHP = "<?php\n"


def go(body: str) -> str:
    return GO + "func handle(w http.ResponseWriter, r *http.Request, db *sql.DB) {\n" + body + "}\n"


# (사례 이름, 규칙 ID, {파일: 내용}, 기대 위치 {파일: [줄 번호]})
CASES: list[tuple[str, str, dict[str, str], dict[str, list[int]]]] = [
    # ---- Go (net/http)
    ("go-sqli-concat", "IL-501", {"a.go": go('\tdb.Query("SELECT * FROM t WHERE id = " + r.URL.Query().Get("id"))\n')}, {"a.go": [11]}),
    ("go-sqli-bound", "IL-501", {"a.go": go('\tdb.Query("SELECT * FROM t WHERE id = ?", r.URL.Query().Get("id"))\n')}, {}),
    ("go-cmd-shell", "IL-504", {"a.go": go('\texec.Command("sh", "-c", "ls "+r.FormValue("d")).Run()\n')}, {"a.go": [11]}),
    ("go-cmd-argv", "IL-504", {"a.go": go('\texec.Command("ls", "--", "/srv/static").Run()\n')}, {}),
    ("go-path-concat", "IL-502", {"a.go": go('\tos.ReadFile("/srv/" + r.FormValue("f"))\n')}, {"a.go": [11]}),
    ("go-path-constant", "IL-502", {"a.go": go('\tos.ReadFile("/srv/static/index.html")\n')}, {}),
    ("go-ssrf", "IL-506", {"a.go": go('\thttp.Get(r.FormValue("url"))\n')}, {"a.go": [11]}),
    ("go-ssrf-constant", "IL-506", {"a.go": go('\thttp.Get("https://api.example.com/v1/items")\n')}, {}),
    ("go-redirect", "IL-507", {"a.go": go('\thttp.Redirect(w, r, r.FormValue("next"), http.StatusFound)\n')}, {"a.go": [11]}),
    ("go-redirect-constant", "IL-507", {"a.go": go('\thttp.Redirect(w, r, "/home", http.StatusFound)\n')}, {}),
    ("go-helper-flow", "IL-504", {"a.go": GO + 'func run(c string) {\n\texec.Command("sh", "-c", c).Run()\n}\n\nfunc handle(w http.ResponseWriter, r *http.Request) {\n\trun("ls " + r.FormValue("d"))\n}\n'}, {"a.go": [11]}),
    ("go-helper-constant", "IL-504", {"a.go": GO + 'func run(c string) {\n\texec.Command("sh", "-c", c).Run()\n}\n\nfunc handle(w http.ResponseWriter, r *http.Request) {\n\trun("ls /srv")\n}\n'}, {}),
    # ---- PHP
    ("php-sqli-concat", "IL-501", {"a.php": PHP + "$r = mysqli_query($conn, \"SELECT * FROM t WHERE id = \" . $_GET['id']);\n"}, {"a.php": [2]}),
    ("php-sqli-prepared", "IL-501", {"a.php": PHP + "$stmt = $conn->prepare(\"SELECT * FROM t WHERE id = ?\");\n$stmt->bind_param(\"s\", $_GET['id']);\n$stmt->execute();\n"}, {}),
    ("php-cmd-system", "IL-504", {"a.php": PHP + "system(\"ls \" . $_GET['d']);\n"}, {"a.php": [2]}),
    ("php-cmd-escaped", "IL-504", {"a.php": PHP + "system(\"ls \" . escapeshellarg($_GET['d']));\n"}, {}),
    ("php-path-include", "IL-502", {"a.php": PHP + "echo file_get_contents(\"/srv/\" . $_GET['f']);\n"}, {"a.php": [2]}),
    ("php-path-basename", "IL-502", {"a.php": PHP + "echo file_get_contents(\"/srv/\" . basename($_GET['f']));\n"}, {}),
    ("php-eval", "IL-503", {"a.php": PHP + "eval($_POST['code']);\n"}, {"a.php": [2]}),
    ("php-eval-constant", "IL-503", {"a.php": PHP + "eval('return 1;');\n"}, {}),
    ("php-xss-echo", "IL-505", {"a.php": PHP + "echo $_GET['q'];\n"}, {"a.php": [2]}),
    ("php-xss-escaped", "IL-505", {"a.php": PHP + "echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');\n"}, {}),
    ("php-redirect", "IL-507", {"a.php": PHP + "header(\"Location: \" . $_GET['next']);\n"}, {"a.php": [2]}),
    ("php-redirect-constant", "IL-507", {"a.php": PHP + "header(\"Location: /home\");\n"}, {}),
    ("php-unserialize", "IL-515", {"a.php": PHP + "$data = unserialize($_COOKIE['data']);\n"}, {"a.php": [2]}),
    ("php-json-decode", "IL-515", {"a.php": PHP + "$data = json_decode($_COOKIE['data'], true);\n"}, {}),
    ("php-helper-flow", "IL-504", {"a.php": PHP + "function run($c) {\n    system($c);\n}\nrun(\"ls \" . $_GET['d']);\n"}, {"a.php": [3]}),
    ("php-helper-constant", "IL-504", {"a.php": PHP + "function run($c) {\n    system($c);\n}\nrun(\"ls /srv\");\n"}, {}),
]


@pytest.mark.parametrize(("case_id", "rule_id", "files", "expected"), CASES, ids=[c[0] for c in CASES])
def test_go_php_case(tmp_path: Path, case_id, rule_id, files, expected):
    from iron_laws.core.models import Confidence
    from tests.helpers import scan_files

    confirmed = [v for v in scan_files(tmp_path, files) if v.confidence is Confidence.CONFIRMED]
    for path in files:
        assert lines_of(confirmed, rule_id, path) == expected.get(path, []), case_id


def test_go_cross_file_same_package_and_imported_package(tmp_path: Path):
    from iron_laws.core.models import Confidence
    from tests.helpers import scan_files

    files = {
        "cmd/server/main.go": 'package main\n\nimport (\n\t"net/http"\n\t"example.com/app/internal/shell"\n)\n\nfunc handle(w http.ResponseWriter, r *http.Request) {\n\tshell.Run("ls " + r.FormValue("d"))\n\tlocal(r.FormValue("e"))\n}\n',
        "cmd/server/util.go": 'package main\n\nimport "os/exec"\n\nfunc local(c string) {\n\texec.Command("sh", "-c", c).Run()\n}\n',
        "internal/shell/shell.go": 'package shell\n\nimport "os/exec"\n\nfunc Run(c string) {\n\texec.Command("sh", "-c", c).Run()\n}\n',
    }
    found = [v for v in scan_files(tmp_path, files) if v.rule_id == "IL-504" and v.confidence is Confidence.CONFIRMED]
    assert sorted((v.file_path.as_posix(), v.line_number) for v in found) == [("cmd/server/main.go", 9), ("cmd/server/main.go", 10)]


def test_go_imports_follow_go_mod_and_skip_stdlib_and_other_modules(tmp_path: Path):
    from iron_laws.core.models import Confidence
    from tests.helpers import scan_files

    files = {
        "go.mod": "module example.com/app\n\ngo 1.22\n",
        "main.go": 'package main\n\nimport (\n\t"net/http"\n\t"os/exec"\n\t"strings"\n\tother "github.com/other/shell"\n\t"example.com/app/internal/shell"\n)\n\n'
        'func handle(w http.ResponseWriter, r *http.Request) {\n\texec.Command("sh", "-c", strings.TrimSpace(r.FormValue("a"))).Run()\n'
        '\texec.Command("sh", "-c", other.Clean(r.FormValue("b"))).Run()\n\texec.Command("sh", "-c", shell.Clean(r.FormValue("c"))).Run()\n}\n',
        "strings/util.go": 'package strings\n\nfunc TrimSpace(s string) string {\n\treturn "ls"\n}\n',
        "shell/clean.go": 'package shell\n\nfunc Clean(s string) string {\n\treturn "ls"\n}\n',
        "internal/shell/clean.go": 'package shell\n\nfunc Clean(s string) string {\n\treturn "ls"\n}\n',
    }
    found = [v for v in scan_files(tmp_path, files) if v.rule_id == "IL-504" and v.confidence is Confidence.CONFIRMED and v.file_path.as_posix() == "main.go"]
    # 표준 라이브러리 strings와 다른 모듈의 shell은 프로젝트 함수로 보지 않는다. go.mod 경로가 맞는 internal/shell은 상수를 돌려준다
    assert sorted(v.line_number for v in found) == [12, 13]


def test_php_cross_file_include_and_static(tmp_path: Path):
    from iron_laws.core.models import Confidence
    from tests.helpers import scan_files

    files = {
        "index.php": "<?php\nrequire_once __DIR__ . '/lib/run.php';\nuse App\\Util\\Shell;\nrun_cmd(\"ls \" . $_GET['d']);\nShell::exec(\"ls \" . $_GET['e']);\n",
        "lib/run.php": "<?php\nfunction run_cmd($c) {\n    system($c);\n}\n",
        "src/Util/Shell.php": "<?php\nnamespace App\\Util;\nclass Shell {\n    public static function exec($c) {\n        passthru($c);\n    }\n}\n",
    }
    found = [v for v in scan_files(tmp_path, files) if v.rule_id == "IL-504" and v.confidence is Confidence.CONFIRMED]
    assert sorted((v.file_path.as_posix(), v.line_number) for v in found) == [("index.php", 4), ("index.php", 5)]


KT = "package app\n\nimport org.springframework.web.bind.annotation.*\n\n@RestController\nclass C(private val jdbc: JdbcTemplate) {\n"

KOTLIN_CASES = [
    ("kt-cmd-requestparam", "IL-504", {"C.kt": KT + '    @GetMapping("/run")\n    fun run(@RequestParam cmd: String): String {\n        Runtime.getRuntime().exec("sh -c " + cmd)\n        return "ok"\n    }\n}\n'}, {"C.kt": [9]}),
    ("kt-cmd-processbuilder-list", "IL-504", {"C.kt": KT + '    @GetMapping("/run")\n    fun run(@RequestParam name: String): String {\n        ProcessBuilder(listOf("ls", "--", "/srv/static")).start()\n        return "ok"\n    }\n}\n'}, {}),
    ("kt-sql-template", "IL-501", {"C.kt": KT + '    @GetMapping("/q")\n    fun q(@RequestParam name: String): Any {\n        val sql = "SELECT * FROM t WHERE n = \'$name\'"\n        return jdbc.queryForList(sql)\n    }\n}\n'}, {"C.kt": [10]}),
    ("kt-sql-bound", "IL-501", {"C.kt": KT + '    @GetMapping("/q")\n    fun q(@RequestParam name: String): Any {\n        return jdbc.queryForList("SELECT * FROM t WHERE n = ?", name)\n    }\n}\n'}, {}),
    ("kt-ktor-cmd", "IL-504", {"App.kt": 'import io.ktor.server.application.*\n\nfun Application.module() {\n    routing {\n        get("/run") {\n            val c = call.parameters["c"]\n            Runtime.getRuntime().exec("sh -c " + c)\n        }\n    }\n}\n'}, {"App.kt": [7]}),
]


@pytest.mark.parametrize(("case_id", "rule_id", "files", "expected"), KOTLIN_CASES, ids=[c[0] for c in KOTLIN_CASES])
def test_kotlin_case(tmp_path: Path, case_id, rule_id, files, expected):
    from iron_laws.core.models import Confidence
    from tests.helpers import scan_files

    confirmed = [v for v in scan_files(tmp_path, files) if v.confidence is Confidence.CONFIRMED]
    for path in files:
        assert lines_of(confirmed, rule_id, path) == expected.get(path, []), case_id
