"""
오철칙 인증 흐름·소속 경계·설정 정책 규칙의 양성·음성 사례 시험
작성자: 최진호
작성일: 2026-11-23
"""

from pathlib import Path

import pytest

from tests.helpers import lines_of

CTRL = "import org.springframework.web.bind.annotation.*;\nimport javax.servlet.http.HttpSession;\n@RestController\nclass C {\n"
PAGE = "import org.springframework.stereotype.Controller;\n@Controller\nclass P {\n"
OTP_INFO_ROUTE = CTRL + '  @GetMapping("/otp/info")\n  public OtpInfo info(@RequestParam String id) {\n    OtpInfo i = service.find(id);\n    return i;\n  }\n}\n'

# (사례 이름, 규칙 ID, {파일: 내용}, 기대 위치 {파일: [줄 번호]}) - 빈 dict는 지적 없음을 뜻한다
CASES: list[tuple[str, str, dict[str, str], dict[str, list[int]]]] = [
    # ---- IL-534 검증 없이 로그인 상태 생성
    (
        "il534-java-id-only-session",
        "IL-534",
        {"C.java": CTRL + '  @PostMapping("/user/later")\n  public String later(@RequestParam String id, HttpSession session) {\n    Member m = mapper.selectMember(id);\n    session.setAttribute("LOGIN_USER", m);\n    return "ok";\n  }\n}\n'},
        {"C.java": [8]},
    ),
    (
        "il534-java-password-checked",
        "IL-534",
        {"C.java": CTRL + '  @PostMapping("/login")\n  public String login(@RequestParam String id, @RequestParam String pw, HttpSession session) {\n    Member m = mapper.selectMember(id);\n    if (passwordEncoder.matches(pw, m.getPassword())) {\n      session.setAttribute("LOGIN_USER", m);\n    }\n    return "ok";\n  }\n}\n'},
        {},
    ),
    (
        "il534-java-guard-return",
        "IL-534",
        {"C.java": CTRL + '  @PostMapping("/login")\n  public String login(@RequestParam String id, @RequestParam String pw, HttpSession session) {\n    Member m = mapper.selectMember(id);\n    if (!passwordEncoder.matches(pw, m.getPassword())) {\n      return "fail";\n    }\n    session.setAttribute("LOGIN_USER", m);\n    return "ok";\n  }\n}\n'},
        {},
    ),
    (
        "il534-java-admin-switch-preauthorize",
        "IL-534",
        {"C.java": CTRL + '  @PreAuthorize("hasRole(\'ADMIN\')")\n  @PostMapping("/account/switch")\n  public String sw(@RequestParam String target, HttpSession session) {\n    session.setAttribute("LOGIN_USER", mapper.selectMember(target));\n    return "ok";\n  }\n}\n'},
        {"C.java": [8]},
    ),
    (
        "il534-java-token-equals",
        "IL-534",
        {"C.java": CTRL + '  @GetMapping("/v2/switch")\n  public String sw(@RequestParam String id, @RequestParam String token, HttpSession session) {\n    Member m = mapper.selectMember(id);\n    if (token.equals(m.getSwitchToken())) {\n      session.setAttribute("LOGIN_USER", m);\n    }\n    return "ok";\n  }\n}\n'},
        {"C.java": [9]},
    ),
    (
        "il534-py-flask-session",
        "IL-534",
        {"a.py": 'from flask import Flask, request, session\napp = Flask(__name__)\n@app.route("/later", methods=["POST"])\ndef later():\n    user = User.query.get(request.form["id"])\n    session["user_id"] = user.id\n    return "ok"\n'},
        {"a.py": [6]},
    ),
    (
        "il534-py-flask-checked",
        "IL-534",
        {"a.py": 'from flask import Flask, request, session\napp = Flask(__name__)\n@app.route("/login", methods=["POST"])\ndef login():\n    user = User.query.filter_by(name=request.form["id"]).first()\n    if user and check_password_hash(user.pw, request.form["pw"]):\n        session["user_id"] = user.id\n    return "ok"\n'},
        {},
    ),
    # ---- IL-535 실패 기록 초기화 위치
    (
        "il535-java-reset-outside",
        "IL-535",
        {"C.java": CTRL + '  @PostMapping("/user/later")\n  public String later(@RequestParam String id) {\n    mapper.resetLoginFailCount(id);\n    return "ok";\n  }\n}\n'},
        {"C.java": [7]},
    ),
    (
        "il535-java-reset-in-success",
        "IL-535",
        {"C.java": CTRL + '  @PostMapping("/login")\n  public String login(@RequestParam String id, @RequestParam String pw) {\n    Member m = mapper.selectMember(id);\n    if (passwordEncoder.matches(pw, m.getPassword())) {\n      mapper.resetLoginFailCount(id);\n    }\n    return "ok";\n  }\n}\n'},
        {},
    ),
    (
        "il535-java-setter-zero",
        "IL-535",
        {"S.java": "class S {\n  void touch(Member m) {\n    m.setLoginFailCnt(0);\n  }\n}\n"},
        {"S.java": [3]},
    ),
    # ---- IL-532 라우트 단위 시도 제한
    (
        "il532-java-otp-verify-no-limit",
        "IL-532",
        {"C.java": CTRL + '  @PostMapping("/otp/verify")\n  public boolean verify(@RequestParam String id, @RequestParam String code) {\n    return otpService.verifyOtpCode(id, code);\n  }\n}\n'},
        {"C.java": [5]},
    ),
    (
        "il532-java-otp-verify-with-count",
        "IL-532",
        {"C.java": CTRL + '  @PostMapping("/otp/verify")\n  public boolean verify(@RequestParam String id, @RequestParam String code) {\n    if (attempts.failCount(id) > 5) { return false; }\n    return otpService.verifyOtpCode(id, code);\n  }\n}\n'},
        {},
    ),
    (
        "il532-java-login-locked-but-otp-not",
        "IL-532",
        {"C.java": CTRL + '  @PostMapping("/login")\n  public String login(@RequestParam String id) {\n    lockout.check(id);\n    return "ok";\n  }\n  @PostMapping("/otp/verify")\n  public boolean verify(@RequestParam String id, @RequestParam String code) {\n    return otpService.verifyOtpCode(id, code);\n  }\n}\n'},
        {"C.java": [10]},
    ),
    # ---- IL-512 2단계 인증 대상
    (
        "il512-java-sms-target-from-request",
        "IL-512",
        {"C.java": CTRL + '  @PostMapping("/sso/sendSms")\n  public void send(@RequestParam String userId, HttpSession session) {\n    smsService.sendSmsCode(userId);\n  }\n}\n'},
        {"C.java": [7]},
    ),
    (
        "il512-java-sms-target-from-session",
        "IL-512",
        {"C.java": CTRL + '  @PostMapping("/sso/sendSms")\n  public void send(HttpSession session) {\n    String userId = (String) session.getAttribute("PENDING_USER");\n    smsService.sendSmsCode(userId);\n  }\n}\n'},
        {},
    ),
    # ---- IL-305 사용자 열거
    (
        "il305-java-distinct-login-messages",
        "IL-305",
        {"L.java": 'class L {\n  String fail(boolean exists) {\n    if (!exists) {\n      return "존재하지 않는 아이디입니다";\n    }\n    return "비밀번호가 일치하지 않습니다";\n  }\n}\n'},
        {"L.java": [4]},
    ),
    (
        "il305-java-same-login-message",
        "IL-305",
        {"L.java": 'class L {\n  String fail(boolean exists) {\n    return "아이디 또는 비밀번호가 올바르지 않습니다";\n  }\n}\n'},
        {},
    ),
    (
        "il305-java-hide-user-not-found-false",
        "IL-305",
        {"S.java": "class S {\n  void p(DaoAuthenticationProvider p) {\n    p.setHideUserNotFoundExceptions(false);\n  }\n}\n"},
        {"S.java": [3]},
    ),
    (
        "il305-java-hide-user-not-found-true",
        "IL-305",
        {"S.java": "class S {\n  void p(DaoAuthenticationProvider p) {\n    p.setHideUserNotFoundExceptions(true);\n  }\n}\n"},
        {},
    ),
    # ---- AI-123 비밀값을 응답·화면으로 보냄
    ("ai123-java-rest-dto-secret", "AI-123", {"C.java": OTP_INFO_ROUTE, "OtpInfo.java": "class OtpInfo {\n  private String userId;\n  private String otpSecret;\n}\n"}, {"C.java": [8]}),
    ("ai123-java-rest-dto-jsonignore", "AI-123", {"C.java": OTP_INFO_ROUTE, "OtpInfo.java": "class OtpInfo {\n  private String userId;\n  @JsonIgnore\n  private String otpSecret;\n}\n"}, {}),
    ("ai123-java-model-api-key", "AI-123", {"P.java": PAGE + '  @GetMapping("/merchant/detail")\n  public String d(@RequestParam String mid, Model model) {\n    Merchant m = mapper.find(mid);\n    model.addAttribute("apiKey", m.getApiKey());\n    return "v";\n  }\n}\n'}, {"P.java": [7]}),
    ("ai123-java-model-api-key-masked", "AI-123", {"P.java": PAGE + '  @GetMapping("/merchant/detail")\n  public String d(@RequestParam String mid, Model model) {\n    Merchant m = mapper.find(mid);\n    model.addAttribute("apiKey", mask(m.getApiKey()));\n    return "v";\n  }\n}\n'}, {}),
    # ---- AI-124 상태 변경을 GET으로 처리
    ("ai124-java-get-delete", "AI-124", {"C.java": CTRL + '  @GetMapping("/user/delete")\n  public String del(@RequestParam String id) {\n    userService.deleteUser(id);\n    return "ok";\n  }\n}\n'}, {"C.java": [7]}),
    ("ai124-java-post-delete", "AI-124", {"C.java": CTRL + '  @PostMapping("/user/delete")\n  public String del(@RequestParam String id) {\n    userService.deleteUser(id);\n    return "ok";\n  }\n}\n'}, {}),
    ("ai124-java-request-mapping-post", "AI-124", {"C.java": CTRL + '  @RequestMapping(value = "/user/delete", method = RequestMethod.POST)\n  public String del(@RequestParam String id) {\n    userService.deleteUser(id);\n    return "ok";\n  }\n}\n'}, {}),
    # ---- AI-125 조회 건수 상한
    ("ai125-java-page-size-unbounded", "AI-125", {"C.java": CTRL + '  @GetMapping("/items")\n  public Object list(@RequestParam int page, @RequestParam int size) {\n    return repo.findAll(PageRequest.of(page, size));\n  }\n}\n'}, {"C.java": [7]}),
    ("ai125-java-page-size-min", "AI-125", {"C.java": CTRL + '  @GetMapping("/items")\n  public Object list(@RequestParam int page, @RequestParam int size) {\n    int s = Math.min(size, 100);\n    return repo.findAll(PageRequest.of(page, s));\n  }\n}\n'}, {}),
    # ---- AI-126 세션 고정 방어 해제
    ("ai126-java-session-fixation-none", "AI-126", {"S.java": "class S {\n  void c(HttpSecurity h) throws Exception {\n    h.sessionManagement().sessionFixation().none();\n  }\n}\n"}, {"S.java": [3]}),
    ("ai126-java-session-fixation-migrate", "AI-126", {"S.java": "class S {\n  void c(HttpSecurity h) throws Exception {\n    h.sessionManagement().sessionFixation().migrateSession();\n  }\n}\n"}, {}),
    # ---- AI-106 API 문서 화면
    ("ai106-springdoc-prod", "AI-106", {"application-prod.properties": "springdoc.api-docs.enabled=true\n"}, {"application-prod.properties": [1]}),
    ("ai106-springdoc-dev", "AI-106", {"application-dev.properties": "springdoc.api-docs.enabled=true\n"}, {}),
    ("ai106-springdoc-yaml-base", "AI-106", {"application.yml": "springdoc:\n  swagger-ui:\n    enabled: true\n"}, {"application.yml": [3]}),
    # ---- AI-128 중요 기능의 감사 기록
    ("ai128-java-password-change-no-audit", "AI-128", {"C.java": CTRL + '  @PostMapping("/password/change")\n  public String change(@RequestParam String pw) {\n    userService.changePassword(pw);\n    return "ok";\n  }\n}\n'}, {"C.java": [5]}),
    ("ai128-java-password-change-audited", "AI-128", {"C.java": CTRL + '  @PostMapping("/password/change")\n  public String change(@RequestParam String pw) {\n    userService.changePassword(pw);\n    auditService.record("PASSWORD_CHANGE");\n    return "ok";\n  }\n}\n'}, {}),
    ("ai128-java-failure-handler", "AI-128", {"H.java": "class H implements AuthenticationFailureHandler {\n  public void onAuthenticationFailure(HttpServletRequest r, HttpServletResponse s, AuthenticationException e) {\n    s.sendRedirect(\"/login?error\");\n  }\n}\n"}, {"H.java": [1]}),
    ("ai124-java-get-binding-reject", "AI-124", {"C.java": CTRL + '  @GetMapping("/owners")\n  public String find(@RequestParam String name, BindingResult result) {\n    result.rejectValue("lastName", "notFound", "not found");\n    return "owners";\n  }\n}\n'}, {}),
    ("il534-java-servlet-login-with-password", "IL-534", {"C.java": CTRL + '  @PostMapping("/register")\n  public String reg(@RequestParam String id, @RequestParam String pw, HttpServletRequest request) throws Exception {\n    userService.addUser(id, pw);\n    request.login(id, pw);\n    return "ok";\n  }\n}\n'}, {}),
]


@pytest.mark.parametrize(("case_id", "rule_id", "files", "expected"), CASES, ids=[c[0] for c in CASES])
def test_auth_flow_case(tmp_path: Path, case_id: str, rule_id: str, files: dict[str, str], expected: dict[str, list[int]]):
    from iron_laws.core.scanner import AuditScanner

    for rel, content in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    violations = AuditScanner(tmp_path).scan().violations
    actual = {path: lines_of(violations, rule_id, path) for path in files}
    actual = {p: ls for p, ls in actual.items() if ls}
    assert actual == expected, f"{case_id}: 기대 {expected}, 실제 {actual}"
