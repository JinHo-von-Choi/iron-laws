"""
오철칙 라우트 접근통제 행렬 시험: 프레임워크별 라우트 발견, 인증·인가 yes/no/unknown, 중요 GET 유지, 보고서·명령 출력
작성자: 최진호
작성일: 2026-10-12
"""

import json
from pathlib import Path

from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.scanner import AuditScanner
from iron_laws.engine.routes import discover_routes

runner = CliRunner()


def _routes(tmp_path: Path, files: dict[str, str]):
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, encoding="utf-8")
    return {(r.framework, r.method, r.path): r for r in discover_routes(AuditScanner(tmp_path)._read_sources())}


def test_flask_fastapi_auth_and_object_authz(tmp_path: Path):
    files = {
        "app.py": (
            "from flask import Flask\napp = Flask(__name__)\n"
            "@app.route('/admin/users', methods=['GET'])\ndef users():\n    return db.query('SELECT * FROM users')\n\n"
            "@app.route('/orders/<int:order_id>', methods=['GET'])\n@login_required\ndef order(order_id):\n    o = Order.query.get(order_id)\n    return o\n\n"
            "@app.route('/notes/<int:note_id>', methods=['DELETE'])\n@login_required\ndef note(note_id):\n    n = Note.query.get(note_id)\n    if n.owner_id != current_user.id:\n        abort(403)\n    db.delete(n)\n"
        ),
    }
    r = _routes(tmp_path, files)
    admin = r[("flask", "GET", "/admin/users")]
    assert admin.sensitive and admin.auth == "no"  # 중요 기능 GET도 대상이다
    order = r[("flask", "GET", "/orders/<int:order_id>")]
    assert order.auth == "yes" and order.authz == "no"
    note = r[("flask", "DELETE", "/notes/<int:note_id>")]
    assert note.auth == "yes"


def test_owner_check_before_access_is_authz_yes(tmp_path: Path):
    files = {"api.py": "from fastapi import FastAPI, Depends\napp = FastAPI()\n@app.get('/files/{file_id}')\ndef get_file(file_id: int, user=Depends(current_user)):\n    if user.id != owner_of(file_id):\n        raise HTTPException(403)\n    return repo.find(file_id)\n"}
    route = _routes(tmp_path, files)[("fastapi", "GET", "/files/{file_id}")]
    assert route.auth == "yes"


def test_express_global_middleware_order(tmp_path: Path):
    files = {
        "a.js": "app.use(authenticate);\napp.post('/users/delete', (req, res) => { res.send('x'); });\n",
        "b.js": "app.post('/users/delete', (req, res) => { res.send('x'); });\napp.use(authenticate);\n",
    }
    r = discover_routes(AuditScanner(_write(tmp_path, files))._read_sources())
    by_file = {x.file: x for x in r}
    assert by_file["a.js"].auth == "yes" and by_file["b.js"].auth == "unknown"


def test_express_path_scoped_middleware_applies_only_under_its_prefix(tmp_path: Path):
    files = {"a.js": "app.use('/public', authenticate);\napp.post('/admin/delete', (req, res) => { res.send('x'); });\napp.post('/public/items', (req, res) => { res.send('x'); });\n"}
    r = {x.path: x for x in discover_routes(AuditScanner(_write(tmp_path, files))._read_sources())}
    assert r["/admin/delete"].auth == "no" and r["/public/items"].auth == "yes"


def test_express_router_middleware_does_not_cover_app_routes(tmp_path: Path):
    files = {"a.js": "const router = express.Router();\nrouter.use('/admin', requireAuth);\napp.get('/admin/export', (req, res) => res.send('secret'));\nrouter.get('/admin/list', (req, res) => res.send('x'));\n"}
    r = {x.path: x for x in discover_routes(AuditScanner(_write(tmp_path, files))._read_sources())}
    assert r["/admin/export"].auth == "no" and r["/admin/list"].auth == "yes"


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    return root


def test_django_urls_resolve_views(tmp_path: Path):
    files = {
        "shop/urls.py": "from django.urls import path\nfrom . import views\nurlpatterns = [\n    path('account/delete/', views.delete_account),\n    path('account/profile/', views.ProfileView.as_view()),\n]\n",
        "shop/views.py": "from django.contrib.auth.decorators import login_required\n\ndef delete_account(request):\n    request.user.delete()\n\nclass ProfileView(LoginRequiredMixin, View):\n    def get(self, request):\n        return render(request, 'p.html')\n",
    }
    r = _routes(tmp_path, files)
    assert r[("django", "POST", "/account/delete/")].auth == "no"
    assert r[("django", "GET", "/account/profile/")].auth == "yes"


def test_nextjs_route_handlers_and_middleware_matcher(tmp_path: Path):
    files = {
        "app/api/admin/users/route.ts": "export async function DELETE(req: Request) {\n  return Response.json({});\n}\nexport async function GET(req: Request) {\n  const session = await getServerSession();\n  return Response.json({});\n}\n",
    }
    r = _routes(tmp_path / "a", files)
    assert r[("nextjs", "DELETE", "/api/admin/users")].auth == "no"
    assert r[("nextjs", "GET", "/api/admin/users")].auth == "yes"
    files["middleware.ts"] = "export function middleware(req) { return auth(req); }\nexport const config = { matcher: ['/dashboard/:path*'] };\n"
    r = _routes(tmp_path / "b", files)
    assert r[("nextjs", "DELETE", "/api/admin/users")].auth == "unknown"


def test_spring_security_chain_rules(tmp_path: Path):
    controller = "@RestController\n@RequestMapping(\"/api\")\nclass A {\n  @DeleteMapping(\"/users/{id}\")\n  void d() {}\n  @PostMapping(\"/public/upload\")\n  void u() {}\n  @PostMapping(\"/orders\")\n  void o() {}\n}\n"
    security = ("@EnableWebSecurity\nclass S {\n  SecurityFilterChain chain(HttpSecurity http) {\n"
                "    http.authorizeHttpRequests(a -> a.requestMatchers(\"/api/public/**\").permitAll().requestMatchers(\"/api/users/**\").hasRole(\"ADMIN\"));\n    return http.build();\n  }\n}\n")
    r = _routes(tmp_path, {"A.java": controller, "S.java": security})
    assert r[("spring", "DELETE", "/api/users/{id}")].auth == "yes"
    assert r[("spring", "POST", "/api/public/upload")].auth == "no"
    assert r[("spring", "POST", "/api/orders")].auth == "unknown"


def test_aspnet_allow_anonymous(tmp_path: Path):
    files = {"A.cs": "[Authorize]\nclass A : ControllerBase {\n  [HttpDelete(\"users\")]\n  public void D() {}\n  [AllowAnonymous]\n  [HttpPost(\"payments\")]\n  public void P() {}\n}\n"}
    r = _routes(tmp_path, files)
    assert r[("aspnet", "DELETE", "users")].auth == "yes"
    assert r[("aspnet", "POST", "payments")].auth == "no"


def test_report_and_command_carry_the_matrix(tmp_path: Path):
    _write(tmp_path, {"a.js": "app.post('/users/delete', (req, res) => { res.send('x'); });\napp.get('/about', (req, res) => { res.send('x'); });\napp.use(authenticate);\n"})
    report = AuditScanner(tmp_path).scan()
    routes = report.metadata["routes"]
    assert routes["total"] == 2 and routes["sensitive"] == 1 and routes["auth"]["unknown"] == 1
    finding = next(v for v in report.violations if v.rule_id == "IL-525")
    assert finding.severity.value == "LOW" and "정할 수 없습니다" in finding.message
    out = runner.invoke(app, ["routes", str(tmp_path), "--format", "json"])
    assert out.exit_code == 0 and len(json.loads(out.stdout)) == 2
