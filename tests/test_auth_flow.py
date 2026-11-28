"""
오철칙 인증 흐름·소속 경계·공격 표면·지원 종료 판정 시험: 라우트 종류와 인증 근거, 설정이 필요한 규칙, 기준선 비교, 명령 출력, 보고서 증빙 표
작성자: 최진호
작성일: 2026-11-23
"""

import json
import shutil
from pathlib import Path

from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.config import IronLawsConfig
from iron_laws.core.scanner import AuditScanner
from iron_laws.engine.routes import discover_routes, route_kind
from tests.helpers import lines_of

runner = CliRunner()
FIXTURE = Path(__file__).parent / "fixtures" / "auth_flow"
EOL_DATA = Path(__file__).parent / "fixtures" / "eol"
CONTROLLER = "src/main/java/demo/LegacyController.java"


def _project(tmp_path: Path, config: str | None = None) -> Path:
    root = tmp_path / "app"
    shutil.copytree(FIXTURE, root)
    if config is not None:
        (root / ".iron-laws.yml").write_text(config, encoding="utf-8")
    return root


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    return root


def _routes(root: Path, config: IronLawsConfig | None = None):
    cfg = config or IronLawsConfig()
    return {(r.method, r.path): r for r in discover_routes(AuditScanner(root)._read_sources(), cfg.auth, cfg.tenancy.keys)}


def test_route_kind_words():
    assert route_kind("/user/changePwLater") == "auth_flow"
    assert route_kind("/sso/sendSms") == "auth_flow"
    assert route_kind("/actuator/env") == "admin"
    assert route_kind("/admin/login") == "auth_flow"
    assert route_kind("/admin/users") == "admin"
    assert route_kind("/payout/list") == "normal"


def test_fixture_routes_are_classified(tmp_path: Path):
    routes = _routes(_project(tmp_path))
    for key in (("POST", "/user/changePwLater"), ("GET", "/otp/service"), ("POST", "/otp/verify"), ("POST", "/sso/sendSms"), ("GET", "/v2/switch")):
        assert routes[key].kind == "auth_flow", key
    assert routes[("GET", "/payout/list")].kind == "normal"


INTERCEPTOR_CONFIG = (
    "import org.springframework.web.servlet.config.annotation.*;\n"
    "class WebConfig implements WebMvcConfigurer {\n"
    "  public void addInterceptors(InterceptorRegistry r) {\n"
    '    r.addInterceptor(new LoginInterceptor()).addPathPatterns("/**").excludePathPatterns("/login");\n'
    "  }\n}\n"
)
INTERCEPTOR_CONTROLLER = (
    "@RestController\nclass C {\n"
    '  @SessionExclude\n  @PostMapping("/later")\n  public String later() { return "x"; }\n'
    '  @PostMapping("/orders/cancel")\n  public String cancel() { return "x"; }\n'
    '  @PostMapping("/login")\n  public String login() { return "x"; }\n'
    "}\n"
)


def test_interceptor_and_exempt_marker(tmp_path: Path):
    root = _write(tmp_path, {"WebConfig.java": INTERCEPTOR_CONFIG, "C.java": INTERCEPTOR_CONTROLLER})
    cfg = IronLawsConfig(auth={"interceptor_protects": True, "exempt_markers": ["@SessionExclude"]})
    routes = _routes(root, cfg)
    assert routes[("POST", "/later")].auth == "no"
    assert routes[("POST", "/orders/cancel")].auth == "yes"
    assert routes[("POST", "/login")].auth == "no"  # excludePathPatterns
    default = _routes(root)
    assert default[("POST", "/orders/cancel")].auth == "no"  # 설정이 없으면 인터셉터를 보호 근거로 쓰지 않는다


def test_request_mapping_methods(tmp_path: Path):
    root = _write(tmp_path, {"C.java": '@RestController\nclass C {\n  @RequestMapping(value = "/a", method = {RequestMethod.GET, RequestMethod.POST})\n  public String a() { return "x"; }\n  @RequestMapping("/b")\n  public String b() { return "x"; }\n}\n'})
    routes = _routes(root)
    assert ("GET", "/a") in routes and ("POST", "/a") in routes
    assert ("GET", "/b") in routes and ("POST", "/b") not in routes


def test_routes_command_csv_and_filter(tmp_path: Path):
    root = _project(tmp_path)
    result = runner.invoke(app, ["routes", str(root), "--format", "csv", "--auth", "no"])
    assert result.exit_code == 0, result.output
    lines = result.output.strip().splitlines()
    assert lines[0] == "framework,method,path,file,line,handler,kind,sensitive,auth,auth_reason,authz,authz_reason"
    assert all(",no," in line for line in lines[1:])
    assert runner.invoke(app, ["routes", str(root), "--format", "xml"]).exit_code == 2


def test_fixture_auth_flow_findings(tmp_path: Path):
    violations = AuditScanner(_project(tmp_path)).scan().violations
    assert lines_of(violations, "IL-534", CONTROLLER) == [25, 55, 69]
    assert [v.confidence.value for v in violations if v.rule_id == "IL-534" and v.line_number == 25] == ["CONFIRMED"]
    assert lines_of(violations, "IL-535", CONTROLLER) == [24]
    assert lines_of(violations, "IL-532", CONTROLLER) == [38]
    assert lines_of(violations, "IL-512", CONTROLLER) == [47]
    assert lines_of(violations, "IL-526", CONTROLLER) == []  # 같은 줄을 IL-534가 지적한다
    assert lines_of(violations, "AI-123", CONTROLLER) == [34]
    assert lines_of(violations, "AI-123", "src/main/java/demo/MerchantPageController.java") == [18]
    assert lines_of(violations, "AI-124", CONTROLLER) == [55, 69]
    assert lines_of(violations, "AI-125", CONTROLLER) == [63]


def test_il526_alone_keeps_session_findings(tmp_path: Path):
    root = _project(tmp_path, "enabled_rules: [IL-526]\n")
    violations = AuditScanner(root).scan().violations
    assert lines_of(violations, "IL-526", CONTROLLER) == [25, 55, 69]


TENANCY = "tenancy:\n  keys: [mid]\n  principal: ['getLoginUser().getMid()']\n  tables: [payout]\n"


def test_tenant_boundary_request_value(tmp_path: Path):
    violations = AuditScanner(_project(tmp_path, TENANCY)).scan().violations
    assert lines_of(violations, "AI-129", CONTROLLER) == [63]
    assert lines_of(AuditScanner(_project(tmp_path / "plain")).scan().violations, "AI-129") == []


def test_tenant_boundary_principal_value(tmp_path: Path):
    root = _project(tmp_path, TENANCY)
    path = root / CONTROLLER
    path.write_text(path.read_text(encoding="utf-8").replace("return payoutMapper.selectPayoutList(mid, size);", "String own = getLoginUser().getMid();\n        return payoutMapper.selectPayoutList(own, Math.min(size, 100));"), encoding="utf-8")
    violations = AuditScanner(root).scan().violations
    assert lines_of(violations, "AI-129") == []
    assert lines_of(violations, "AI-125") == []


SERVICE_LOGIN = {
    "src/main/java/app/LoginController.java": """package app;
import javax.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.*;
@RestController
public class LoginController {
    private final MemberService memberService;
    public LoginController(MemberService s) { this.memberService = s; }
    @PostMapping("/login")
    public String login(@RequestParam String id, @RequestParam String pw, HttpSession session) {
        Member m = memberService.login(id, pw);
        if (m == null) { return "fail"; }
        session.setAttribute("loginUser", m);
        return "ok";
    }
}
""",
    "src/main/java/app/MemberService.java": """package app;
import org.springframework.security.crypto.password.PasswordEncoder;
public class MemberService {
    private final MemberMapper mapper; private final PasswordEncoder encoder;
    public MemberService(MemberMapper m, PasswordEncoder e) { mapper = m; encoder = e; }
    public Member login(String id, String pw) {
        Member m = mapper.findById(id);
        if (m == null || !encoder.matches(pw, m.getPassword())) { return null; }
        return m;
    }
}
""",
    "src/main/java/app/Member.java": "package app;\npublic class Member { private String password; public String getPassword() { return password; } }\n",
    "src/main/java/app/MemberMapper.java": "package app;\npublic interface MemberMapper { Member findById(String id); }\n",
}


def test_service_layer_password_check(tmp_path: Path):
    root = _write(tmp_path / "svc", SERVICE_LOGIN)
    violations = AuditScanner(root).scan().violations
    assert lines_of(violations, "IL-534") == []
    assert lines_of(violations, "IL-526") == []  # 비밀번호를 확인한 뒤 넣는 로그인 사용자는 검증 없는 입력이 아니다
    root_alone = _write(tmp_path / "svc_alone", {**SERVICE_LOGIN, ".iron-laws.yml": "enabled_rules: [IL-526]\n"})
    assert lines_of(AuditScanner(root_alone).scan().violations, "IL-526") == [12]  # IL-534를 끄면 IL-526은 예전처럼 낸다
    service = root / "src/main/java/app/MemberService.java"
    service.write_text(service.read_text(encoding="utf-8").replace(" || !encoder.matches(pw, m.getPassword())", ""), encoding="utf-8")
    violations = [v for v in AuditScanner(root).scan().violations if v.rule_id == "IL-534"]
    assert [(v.line_number, v.confidence.value) for v in violations] == [(12, "CONFIRMED")]
    service.write_text(service.read_text(encoding="utf-8").replace("if (m == null)", "if (m == null || encoder.matches(pw, m.getPassword()))"), encoding="utf-8")
    assert lines_of(AuditScanner(root).scan().violations, "IL-534") == [12]  # 비밀번호가 맞을 때 거부하는 메서드는 검증이 아니다


OWNER_CHECK = {
    ".iron-laws.yml": "tenancy:\n  keys: [mid]\n  principal: ['getLoginUser().getMid()']\n",
    "src/main/java/app/TxController.java": """package app;
import java.util.List;
import org.springframework.web.bind.annotation.*;
@RestController
public class TxController {
    private final TxMapper txMapper; private final AuthHelper auth;
    public TxController(TxMapper m, AuthHelper a) { txMapper = m; auth = a; }
    @GetMapping("/tx")
    public List<Tx> list(@RequestParam String mid) {
        if (!auth.isOwnedMerchant(mid)) { throw new IllegalStateException("forbidden"); }
        return txMapper.selectTx(mid);
    }
    @GetMapping("/tx2")
    public List<Tx> list2(@RequestParam String mid) {
        if (!mid.equals(auth.getLoginUser().getMid())) { throw new IllegalStateException("forbidden"); }
        return txMapper.selectTx(mid);
    }
    @GetMapping("/tx3")
    public List<Tx> list3(@RequestParam String mid) {
        if (!mid.equals(auth.getLoginUser().getMid())) { System.out.println("other merchant"); }
        return txMapper.selectTx(mid);
    }
}
""",
    "src/main/java/app/TxMapper.java": "package app;\nimport java.util.List;\nimport org.apache.ibatis.annotations.Param;\npublic interface TxMapper { List<Tx> selectTx(@Param(\"mid\") String mid); }\n",
    "src/main/java/app/Tx.java": "package app;\npublic class Tx { }\n",
    "src/main/java/app/AuthHelper.java": """package app;
public class AuthHelper {
    public User getLoginUser() { return null; }
    public boolean isOwnedMerchant(String mid) { return mid != null && mid.equals(getLoginUser().getMid()); }
    public static class User { public String getMid() { return ""; } }
}
""",
    "src/main/resources/mapper/TxMapper.xml": """<?xml version="1.0" encoding="UTF-8"?>
<mapper namespace="app.TxMapper">
  <select id="selectTx" resultType="app.Tx">SELECT * FROM tx WHERE mid = #{mid}</select>
</mapper>
""",
}


def test_tenant_boundary_owner_check(tmp_path: Path):
    root = _write(tmp_path / "owner", OWNER_CHECK)
    assert lines_of(AuditScanner(root).scan().violations, "AI-129") == [21]  # 다르다고 기록만 하고 계속 실행하는 분기는 확인이 아니다
    rows = json.loads(runner.invoke(app, ["tenancy", str(root), "--format", "json"]).output)
    assert [(r["source"], r["verdict"]) for r in rows if r["statement"] == "selectTx"] == [("checked", "ok"), ("checked", "ok"), ("request", "violation")]
    controller = root / "src/main/java/app/TxController.java"
    controller.write_text(controller.read_text(encoding="utf-8").replace("if (!mid.equals(auth.getLoginUser().getMid())) { throw", "if (!mid.equals(auth.getLoginUser().getMid()) && !force) { throw").replace("list2(@RequestParam String mid)", "list2(@RequestParam String mid, @RequestParam boolean force)"), encoding="utf-8")
    helper = root / "src/main/java/app/AuthHelper.java"
    helper.write_text(helper.read_text(encoding="utf-8").replace("return mid != null && mid.equals(getLoginUser().getMid());", "boolean ok = mid.equals(getLoginUser().getMid()); return true;"), encoding="utf-8")
    assert lines_of(AuditScanner(root).scan().violations, "AI-129") == [11, 16, 21]  # and로 묶인 우회 조건, 비교 결과를 쓰지 않는 함수


def test_tenancy_command(tmp_path: Path):
    root = _project(tmp_path, TENANCY)
    result = runner.invoke(app, ["tenancy", str(root), "--format", "json"])
    assert result.exit_code == 0, result.output
    rows = json.loads(result.output)
    payout = [r for r in rows if r["statement"] == "selectPayoutList"]
    assert payout and payout[0]["key_column"] == "where" and payout[0]["source"] == "request" and payout[0]["verdict"] == "violation"
    assert runner.invoke(app, ["tenancy", str(_project(tmp_path / "plain"))]).exit_code == 2


def test_session_timeout_policy(tmp_path: Path):
    with_policy = AuditScanner(_project(tmp_path, "policies:\n  session_timeout_max: 10m\n")).scan().violations
    assert lines_of(with_policy, "AI-126", "src/main/resources/application.properties") == [1]
    without = AuditScanner(_project(tmp_path / "plain")).scan().violations
    assert lines_of(without, "AI-126") == []


def test_eol_data_judgment(tmp_path: Path):
    report = AuditScanner(_project(tmp_path, f"policies:\n  eol_db: {EOL_DATA.as_posix()}\n")).scan()
    eol = {(v.file_path.as_posix(), v.line_number) for v in report.violations if v.rule_id == "AI-121"}
    assert ("Dockerfile", 1) in eol and ("pom.xml", 2) in eol and ("pom.xml", 3) in eol
    assert all("오래된 주 버전" not in v.message for v in report.violations if v.rule_id == "AI-121")
    assert report.metadata["eol"]["data"]["fetched_at"] == "2026-11-20"
    assert report.execution.reference_data["eol"].startswith("2026-11-20:")
    again = AuditScanner(_project(tmp_path / "again", f"policies:\n  eol_db: {EOL_DATA.as_posix()}\n")).scan()
    assert again.execution.reference_data == report.execution.reference_data


def test_eol_data_unreadable_does_not_fall_back(tmp_path: Path):
    broken = tmp_path / "eol"
    shutil.copytree(EOL_DATA, broken)
    manifest = json.loads((broken / "manifest.json").read_text(encoding="utf-8"))
    manifest["sha256"] = "0" * 64
    (broken / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    report = AuditScanner(_project(tmp_path, f"policies:\n  eol_db: {broken.as_posix()}\n")).scan()
    assert [d for d in report.diagnostics if d.kind == "eol_data" and d.severity == "error"]
    assert not [v for v in report.violations if v.rule_id == "AI-121" and "지원이 끝났습니다" in v.message]
    builtin = AuditScanner(_project(tmp_path / "plain")).scan()
    assert [v for v in builtin.violations if v.rule_id == "AI-121" and "오래된 주 버전" in v.message]


def test_fetch_eol_data_writes_loadable_folder(tmp_path: Path):
    from iron_laws.deps.eol import EOL_PRODUCTS, fetch_eol_data, judge, load_eol_data

    def opener(url: str, timeout: float) -> bytes:
        return b'[{"cycle": "7", "eol": "2024-06-30"}]' if url.endswith("/centos.json") else b"[]"

    fetch_eol_data(tmp_path / "eol", "2026-11-23T00:00:00Z", opener=opener)
    data = load_eol_data(tmp_path / "eol")
    assert set(data.products) == set(EOL_PRODUCTS)
    assert judge(data, "centos", "7").eol == "2024-06-30"


def test_attack_surface_baseline(tmp_path: Path):
    root = _write(tmp_path / "app", {"C.java": '@RestController\nclass C {\n  @PreAuthorize("isAuthenticated()")\n  @PostMapping("/orders")\n  public String o() { return "x"; }\n}\n'})
    baseline = tmp_path / "baseline.json"
    created = runner.invoke(app, ["baseline", "create", str(root), "--output", str(baseline)])
    assert created.exit_code == 0, created.output
    assert json.loads(baseline.read_text(encoding="utf-8"))["routes"][0]["path"] == "/orders"
    _write(root, {"D.java": '@RestController\nclass D {\n  @PostMapping("/legacy/export")\n  public String e() { return "x"; }\n  @PreAuthorize("isAuthenticated()")\n  @PostMapping("/reports")\n  public String r() { return "x"; }\n  @PreAuthorize("hasRole(\'ADMIN\')")\n  @GetMapping("/admin/stats")\n  public String a() { return "x"; }\n}\n'})
    from iron_laws.core.baseline import load_baseline

    report = AuditScanner(root, baseline=load_baseline(baseline)).scan()
    found = {(v.line_number, v.severity.value) for v in report.violations if v.rule_id == "AI-127"}
    assert found == {(3, "MEDIUM"), (8, "LOW")}


def test_old_baseline_without_routes(tmp_path: Path):
    from iron_laws.core.baseline import Baseline, load_baseline, migrate_baseline, save_baseline

    root = _write(tmp_path / "app", {"C.java": '@RestController\nclass C {\n  @PostMapping("/x")\n  public String x() { return "x"; }\n}\n'})
    old = tmp_path / "old.json"
    save_baseline(Baseline(tool_version="1.12.1"), old)
    report = AuditScanner(root, baseline=load_baseline(old)).scan()
    assert not [v for v in report.violations if v.rule_id == "AI-127"]
    assert [d for d in report.diagnostics if d.kind == "baseline" and "라우트 목록" in d.message]
    with_routes = Baseline(tool_version="1.12.1", routes=[{"method": "POST", "path": "/x", "kind": "normal", "auth": "no", "file": "C.java"}])
    assert migrate_baseline(with_routes, report.violations, "1.13.0").baseline.routes == with_routes.routes


def test_fin_selfcheck_markdown_section(tmp_path: Path):
    root = _project(tmp_path, TENANCY + f"policies:\n  eol_db: {EOL_DATA.as_posix()}\n")
    out = tmp_path / "report.md"
    result = runner.invoke(app, ["audit", str(root), "--format", "markdown", "--standard", "fin-selfcheck-2026", "-o", str(out)])
    assert result.exit_code == 1, result.output
    text = out.read_text(encoding="utf-8")
    assert "침해사고 대비 금융권 IT보안 자체점검(2026) 항목별 점검 현황" in text
    assert "| 1 | 공격자 IP 차단 | 코드 밖 확인 | - | - | 코드 밖 확인 필요 |" in text
    assert "### 조회문별 소속 확인" in text and "### 지원 종료 제품" in text
    assert runner.invoke(app, ["audit", str(root), "--standard", "no-such-pack"]).exit_code == 2


def test_triage_prompt_includes_handler(tmp_path: Path):
    from iron_laws.core.triage import build_prompt

    root = _project(tmp_path)
    report = AuditScanner(root).scan()
    report.violations = [v for v in report.violations if v.rule_id == "IL-534" and v.line_number == 55]
    prompt, picks = build_prompt(report, root, set())
    assert len(picks) == 1
    assert "public String switchIn" in prompt and "물음:" in prompt


HELPER_LOGIN = {
    "src/main/java/app/SwitchController.java": """package app;
import javax.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.*;
@RestController
public class SwitchController {
    private final SessionHelper sessionHelper;
    public SwitchController(SessionHelper h) { this.sessionHelper = h; }
    @PostMapping("/switch")
    public String switchUser(@RequestParam String id, HttpSession session) {
        sessionHelper.loginAs(id, session);
        return "ok";
    }
}
""",
    "src/main/java/app/SessionHelper.java": """package app;
import javax.servlet.http.HttpSession;
public class SessionHelper {
    private final MemberMapper mapper;
    public SessionHelper(MemberMapper m) { mapper = m; }
    public void loginAs(String id, HttpSession session) {
        session.setAttribute("loginUser", mapper.findById(id));
    }
}
""",
    "src/main/java/app/MemberMapper.java": "package app;\npublic interface MemberMapper { Object findById(String id); }\n",
}


def test_triage_prompt_includes_call_chain(tmp_path: Path):
    from iron_laws.core.triage import build_prompt

    root = _write(tmp_path / "chain", HELPER_LOGIN)
    report = AuditScanner(root).scan()
    report.violations = [v for v in report.violations if v.rule_id == "IL-534"]
    assert [(v.file_path.as_posix(), v.line_number, v.confidence.value) for v in report.violations] == [("src/main/java/app/SessionHelper.java", 7, "REVIEW")]
    assert [(e.role, e.file_path, e.line) for e in report.violations[0].evidence] == [
        ("source", "src/main/java/app/SwitchController.java", 8),  # 메서드 선언은 애너테이션 줄에서 시작한다
        ("propagation", "src/main/java/app/SwitchController.java", 10),
        ("sink", "src/main/java/app/SessionHelper.java", 7),
    ]
    prompt, _picks = build_prompt(report, root, set())
    assert "public String switchUser" in prompt and "public void loginAs" in prompt  # 라우트 핸들러와 도우미를 함께 보낸다


def test_spec_draft_config_hints(tmp_path: Path):
    from iron_laws.core.spec_draft import build_draft

    root = _write(tmp_path, {
        "LoginInterceptor.java": "class LoginInterceptor implements HandlerInterceptor {\n  public boolean preHandle(Object h) {\n    return ((HandlerMethod) h).getMethodAnnotation(SessionExclude.class) != null;\n  }\n}\n",
        "S.java": "class S {\n  void a() { repo.find(getLoginUser().getMid()); }\n}\n",
    })
    hints = build_draft(AuditScanner(root)._read_sources())["config_hints"]
    assert [h["value"] for h in hints["auth.exempt_markers"]] == ["@SessionExclude"]
    assert [h["value"] for h in hints["tenancy.principal"]] == ["getLoginUser().getMid()"]


def test_maven_manifest_versions(tmp_path: Path):
    from iron_laws.deps.lockfiles import parse_lock
    from iron_laws.deps.sbom import purl
    from iron_laws.deps.versions import parse_version

    lock = parse_lock(_project(tmp_path) / "pom.xml")
    assert {(p.name, p.version) for p in lock.packages} == {("org.springframework.boot:spring-boot-starter-parent", "2.7.4"), ("log4j:log4j", "1.2.12")}
    assert lock.capabilities["direct_transitive"] is False and lock.notes
    order = ["1.0-alpha", "1.0-rc1", "1.0", "1.0-sp1", "1.0.1", "1.2.12", "1.10"]
    parsed = [parse_version("Maven", v) for v in order]
    assert all(a < b for a, b in zip(parsed, parsed[1:], strict=False))
    assert parse_version("Maven", "1.0") == parse_version("Maven", "1.0.0")
    assert purl("Maven", "log4j:log4j", "1.2.12") == "pkg:maven/log4j/log4j@1.2.12"
