import http.server
import json
import os
import socket
import struct
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from blade_monitor.models import Finding, HTTPInfo, Service, Snapshot
from blade_monitor.platform import auth, engine, partners, scoring, verification, worker
from blade_monitor.platform.db import Database, now
from blade_monitor.platform.web import App, Settings, serve


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"<html><head><title>Index of /backup</title></head></html>"
        self.send_response(200)
        self.send_header("Server", "nginx/1.18.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Client:
    """Cliente HTTP mínimo com cookie de sessão e token CSRF."""

    def __init__(self, base: str):
        self.base, self.cookie, self.csrf, self.bearer = base, "", "", ""

    def call(self, method, path, body=None, csrf=True):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if data:
            req.add_header("Content-Type", "application/json")
        if self.cookie:
            req.add_header("Cookie", self.cookie)
        if self.bearer:
            req.add_header("Authorization", f"Bearer {self.bearer}")
        if csrf and self.csrf:
            req.add_header("X-CSRF-Token", self.csrf)
        try:
            with urllib.request.urlopen(req) as resp:
                status, raw, headers = resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as exc:
            status, raw, headers = exc.code, exc.read(), exc.headers
        if headers.get("Set-Cookie"):
            self.cookie = headers["Set-Cookie"].split(";")[0]
        ctype = headers.get("Content-Type", "")
        return status, (json.loads(raw) if ctype.startswith("application/json") else raw.decode())

    def login(self, email, password="senha-super-secreta"):
        status, body = self.call("POST", "/api/v1/auth/login", {"email": email, "password": password})
        assert status == 200, body
        self.csrf = body["csrf"]
        return body


class ScoringTests(unittest.TestCase):
    def test_clean_surface_is_A(self):
        r = scoring.compute([], 5)
        self.assertEqual((r["score"], r["grade"]), (100, "A"))

    def test_critical_caps_grade(self):
        r = scoring.compute([Finding("risky-port", "critical", "db:6379", "Redis")], 50)
        self.assertLessEqual(r["score"], 59)
        self.assertEqual(r["grade"], "F")
        self.assertEqual(r["categories"]["network"]["findings"], 1)
        self.assertEqual(r["categories"]["tls"]["grade"], "A")

    def test_larger_surface_dilutes_minor_findings(self):
        f = [Finding("cert-expiring", "medium", "a:443", "x")]
        self.assertLess(scoring.compute(f, 1)["score"], scoring.compute(f, 64)["score"])

    def test_grades(self):
        self.assertEqual([scoring.grade(s) for s in (95, 85, 75, 65, 10)], list("ABCDF"))


class VerificationTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(verification.normalize_asset("domain", " Example.COM. "), "example.com")
        for bad in ("http://x.com", "localhost", "-a.com", "a..com"):
            with self.assertRaises(ValueError):
                verification.normalize_asset("domain", bad)
        self.assertEqual(verification.normalize_asset("cidr", "8.8.8.7/30"), "8.8.8.4/30")
        with self.assertRaises(ValueError):
            verification.normalize_asset("cidr", "10.0.0.0/24")
        with self.assertRaises(ValueError):
            verification.normalize_asset("ip", "127.0.0.1")
        self.assertEqual(verification.normalize_asset("ip", "127.0.0.1", allow_private=True), "127.0.0.1")
        with self.assertRaises(ValueError):
            verification.normalize_asset("cidr", "8.8.0.0/16")

    def test_dns_txt_wire_format(self):
        query = verification.build_txt_query("_blade-monitor.example.com", 0x1234)
        txt = b"blade-monitor-verification=abc"
        answer = (b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 60, len(txt) + 1)
                  + bytes([len(txt)]) + txt)
        response = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + query[12:] + answer
        self.assertEqual(verification.parse_txt_response(response, 0x1234),
                         ["blade-monitor-verification=abc"])
        with self.assertRaises(OSError):
            verification.parse_txt_response(response, 0x9999)

    def test_verify_domain(self):
        tok = "t0k"
        ok_dns = lambda name: ([f"blade-monitor-verification={tok}"]  # noqa: E731
                               if name == "_blade-monitor.ex.com" else [])
        self.assertEqual(verification.verify_domain("ex.com", tok, ok_dns, lambda d: ""), "dns")
        self.assertEqual(verification.verify_domain("ex.com", tok, lambda n: [], lambda d: tok), "http")
        self.assertIsNone(verification.verify_domain("ex.com", tok, lambda n: ["x"], lambda d: "y"))


class EngineSafetyTests(unittest.TestCase):
    def test_internal_ips_are_dropped(self):
        hosts = {"www.ex.com": ["8.8.8.8", "10.0.0.5"], "intranet.ex.com": ["192.168.1.1"],
                 "meta.ex.com": ["169.254.169.254"], "lo.ex.com": ["127.0.0.1", "::1"]}
        self.assertEqual(engine.public_hosts(hosts), {"www.ex.com": ["8.8.8.8"]})


class BootstrapTests(unittest.TestCase):
    def test_env_bootstrap_is_idempotent(self):
        from unittest import mock
        from blade_monitor.platform import cli
        with tempfile.TemporaryDirectory() as d:
            db = Database(os.path.join(d, "b.db"))
            env = {"BLADE_ADMIN_EMAIL": "ops@x.example", "BLADE_ADMIN_PASSWORD": "senha-super-secreta",
                   "BLADE_DEMO": "1"}
            with mock.patch.dict(os.environ, env):
                cli.bootstrap(db)
                cli.bootstrap(db)  # segundo boot não duplica nada
            self.assertEqual(db.one("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'")["n"], 2)
            self.assertEqual(db.one("SELECT COUNT(*) AS n FROM organizations")["n"], 4)
            self.assertEqual(auth.authenticate(db, "ops@x.example", "senha-super-secreta")["role"], "admin")


class PartnerProgramTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(os.path.join(self.tmp.name, "p.db"))
        self.pid = self.db.execute(
            "INSERT INTO partners (name, status, referral_code, created_at) VALUES ('P', 'active', 'BM-1', ?)",
            (now(),))

    def tearDown(self):
        self.tmp.cleanup()

    def _org(self, plan="professional", **kw):
        cols = {"name": "o", "plan": plan, "created_at": now(), **kw}
        return self.db.execute(
            f"INSERT INTO organizations ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
            tuple(cols.values()))

    def test_tier_progression_and_override(self):
        partner = self.db.one("SELECT * FROM partners WHERE id = ?", (self.pid,))
        self.assertEqual(partners.tier_for(self.db, partner)["tier"], "registered")
        for _ in range(5):
            self._org(partner_id=self.pid)
        t = partners.tier_for(self.db, partner)
        self.assertEqual(t["tier"], "silver")
        self.assertTrue(t["white_label"])
        self.assertEqual(t["next_tier"], {"tier": "gold", "label": "Gold", "clients_needed": 10})
        partner["tier_override"] = "platinum"
        self.assertEqual(partners.tier_for(self.db, partner)["discount"], 0.40)

    def test_statement(self):
        self._org(partner_id=self.pid, plan="enterprise")
        self._org(referred_by=self.pid, plan="professional")
        self._org(partner_id=self.pid, plan="essentials", status="suspended")
        partner = self.db.one("SELECT * FROM partners WHERE id = ?", (self.pid,))
        s = partners.statement(self.db, partner, now()[:7])
        self.assertEqual(len(s["managed"]), 1)
        self.assertEqual(s["totals"]["wholesale_due"], round(1499 * 0.9, 2))
        self.assertEqual(s["totals"]["referral_commission"], round(499 * 0.2, 2))
        self.assertEqual(s["totals"]["net_payable"], round(1499 * 0.9 - 499 * 0.2, 2))
        self.assertEqual(partners.statement(self.db, partner, "2000-01")["managed"], [])


class EngineLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(os.path.join(self.tmp.name, "e.db"))
        self.org = self.db.execute("INSERT INTO organizations (name, created_at) VALUES ('o', ?)", (now(),))

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, services):
        sid = self.db.execute("INSERT INTO scans (org_id, mode, status, queued_at) VALUES (?, 'active',"
                              " 'running', ?)", (self.org, now()))
        snap = Snapshot(started_at=now(), finished_at=now(), hosts={"h": ["198.51.100.1"]},
                        services=services, findings=[])
        from blade_monitor.rules import evaluate
        snap.findings = evaluate(services)
        return engine.finalize(self.db, self.db.one("SELECT * FROM scans WHERE id = ?", (sid,)),
                               snap, engine.EngineSettings(send_alerts=False))

    def _issues(self):
        return {i["rule"]: i["status"] for i in self.db.all("SELECT * FROM issues")}

    def test_open_resolve_reopen_and_accept(self):
        redis = Service("h", "198.51.100.1", 6379)
        web = Service("h", "198.51.100.1", 80, http=HTTPInfo(status=200, redirect_to_https=False))
        r1 = self._run([redis, web])
        self.assertEqual(self._issues(), {"risky-port": "open", "http-no-redirect": "open"})
        self.assertEqual(r1["grade"], "F")

        self._run([web])
        self.assertEqual(self._issues()["risky-port"], "resolved")
        self._run([redis, web])
        self.assertEqual(self._issues()["risky-port"], "open")

        self.db.execute("UPDATE issues SET status = 'accepted' WHERE rule = 'risky-port'")
        r4 = self._run([redis, web])
        self.assertEqual(self._issues()["risky-port"], "accepted")
        self.assertGreater(r4["score"], r1["score"])  # risco aceito sai da nota


class PlatformAPITests(unittest.TestCase):
    """Fluxo completo via HTTP: parceiro → cliente → ativo → varredura real."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Database(os.path.join(cls.tmp.name, "api.db"))
        cls.target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.target.serve_forever, daemon=True).start()
        cls.engine = engine.EngineSettings(ports=[cls.target.server_address[1]], timeout=2,
                                           workers=4, ct_discovery=False, send_alerts=False,
                                           allow_private=True)
        cls.app = App(cls.db, Settings(allow_private_targets=True, engine=cls.engine))
        cls.app.verify_domain = lambda domain, token: "dns" if domain == "owned.example" else None
        port = _free_port()
        cls.server = serve(cls.app, "127.0.0.1", port)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{port}"
        auth.create_user(cls.db, "root@plat.example", "senha-super-secreta", "admin")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.target.shutdown()
        cls.tmp.cleanup()

    def _partner(self, company, email):
        c = Client(self.base)
        st, body = c.call("POST", "/api/v1/partners/apply", {
            "company": company, "name": "Ana", "email": email, "password": "senha-super-secreta"})
        self.assertEqual(st, 201, body)
        admin = Client(self.base)
        admin.login("root@plat.example")
        st, _ = admin.call("POST", f"/api/v1/admin/partners/{body['partner_id']}", {"status": "active"})
        self.assertEqual(st, 200)
        c.login(email)
        return c, body["partner_id"]

    def test_full_partner_flow(self):
        p, pid = self._partner("Consultoria Um", "um@consult.example")
        st, org = p.call("POST", "/api/v1/orgs", {
            "name": "Cliente A", "plan": "professional",
            "admin_email": "ciso@cliente-a.example", "admin_password": "senha-super-secreta"})
        self.assertEqual(st, 201, org)
        oid = org["id"]

        # sem ativo verificado não há varredura
        self.assertEqual(p.call("POST", f"/api/v1/orgs/{oid}/scans")[0], 400)

        st, dom = p.call("POST", f"/api/v1/orgs/{oid}/assets", {"kind": "domain", "value": "Owned.Example"})
        self.assertEqual(st, 201)
        self.assertIn("_blade-monitor.owned.example", dom["instructions"]["dns"]["name"])
        self.assertTrue(p.call("POST", f"/api/v1/assets/{dom['id']}/verify")[1]["verified"])
        _, other = p.call("POST", f"/api/v1/orgs/{oid}/assets", {"kind": "domain", "value": "notmine.example"})
        self.assertFalse(p.call("POST", f"/api/v1/assets/{other['id']}/verify")[1]["verified"])
        p.call("DELETE", f"/api/v1/assets/{dom['id']}")  # domínio fictício não resolve; usa IP local

        st, ip = p.call("POST", f"/api/v1/orgs/{oid}/assets", {"kind": "ip", "value": "127.0.0.1"})
        self.assertEqual(st, 201)
        self.assertEqual(p.call("POST", f"/api/v1/assets/{ip['id']}/attest", {})[0], 400)
        self.assertEqual(p.call("POST", f"/api/v1/assets/{ip['id']}/attest",
                                {"note": "Contrato 42/2026"})[0], 200)

        st, body = p.call("POST", f"/api/v1/orgs/{oid}/scans")
        self.assertEqual(st, 202)
        w = worker.Worker(self.db, self.engine, schedule=False)
        self.assertEqual(w.run_once(), body["scan_id"])

        _, scan = p.call("GET", f"/api/v1/scans/{body['scan_id']}")
        self.assertEqual(scan["status"], "done", scan["error"])
        self.assertEqual(scan["services"], 1)
        _, issues = p.call("GET", f"/api/v1/orgs/{oid}/issues")
        rules = {i["rule"] for i in issues}
        self.assertIn("sensitive-panel", rules)
        self.assertIn("server-version-disclosure", rules)

        # aceitar risco exige justificativa
        iid = next(i["id"] for i in issues if i["rule"] == "sensitive-panel")
        self.assertEqual(p.call("PATCH", f"/api/v1/issues/{iid}", {"status": "accepted"})[0], 400)
        st, upd = p.call("PATCH", f"/api/v1/issues/{iid}", {"status": "accepted", "note": "honeypot"})
        self.assertEqual((st, upd["status"]), (200, "accepted"))
        self.assertEqual(p.call("PATCH", f"/api/v1/issues/{iid}", {"status": "resolved"})[0], 400)

        # relatório white-label com a marca do parceiro
        p.call("PATCH", "/api/v1/partner", {"brand_name": "Marca Um", "brand_color": "#123456"})
        st, html = p.call("GET", f"/reports/scan/{body['scan_id']}")
        self.assertEqual(st, 200)
        self.assertIn("Marca Um", html)
        self.assertIn("#123456", html)
        self.assertIn("Blade Monitor", html)  # nível Registered não remove a marca
        self.assertEqual(p.call("PATCH", "/api/v1/partner", {"white_label": True})[0], 403)

        # portfólio
        _, orgs = p.call("GET", "/api/v1/orgs")
        self.assertEqual([o["name"] for o in orgs], ["Cliente A"])
        self.assertEqual(orgs[0]["last_scan"]["id"], body["scan_id"])

        # usuário do cliente vê só a própria org, com a marca do parceiro
        c = Client(self.base)
        c.login("ciso@cliente-a.example")
        _, me = c.call("GET", "/api/v1/me")
        self.assertEqual(me["brand"]["name"], "Marca Um")
        self.assertEqual(c.call("GET", "/api/v1/partner/statement")[0], 403)
        self.assertEqual(c.call("PATCH", f"/api/v1/orgs/{oid}", {"plan": "enterprise"})[0], 403)

        # leitor não escreve
        st, _ = c.call("POST", "/api/v1/users", {"email": "leitor@cliente-a.example",
                                                "password": "senha-super-secreta", "role": "org_viewer"})
        self.assertEqual(st, 201)
        v = Client(self.base)
        v.login("leitor@cliente-a.example")
        self.assertEqual(v.call("GET", f"/api/v1/orgs/{oid}")[0], 200)
        self.assertEqual(v.call("POST", f"/api/v1/orgs/{oid}/scans")[0], 403)

        # extrato do parceiro
        _, stmt = p.call("GET", "/api/v1/partner/statement")
        self.assertEqual(stmt["totals"]["wholesale_due"], round(499 * 0.9, 2))

    def test_tenant_isolation_and_csrf(self):
        a, _ = self._partner("Consultoria A", "a@iso.example")
        b, _ = self._partner("Consultoria B", "b@iso.example")
        _, org = a.call("POST", "/api/v1/orgs", {"name": "Segredo"})
        for method, path in (("GET", f"/api/v1/orgs/{org['id']}"),
                             ("GET", f"/api/v1/orgs/{org['id']}/issues"),
                             ("POST", f"/api/v1/orgs/{org['id']}/scans")):
            self.assertEqual(b.call(method, path)[0], 404, path)
        self.assertNotIn("Segredo", json.dumps(b.call("GET", "/api/v1/orgs")[1]))

        # mutação via cookie sem token CSRF é recusada
        self.assertEqual(a.call("POST", "/api/v1/orgs", {"name": "x"}, csrf=False)[0], 403)
        self.assertEqual(Client(self.base).call("GET", "/api/v1/orgs")[0], 401)

        # chave de API autentica sem CSRF e herda permissões
        _, key = a.call("POST", "/api/v1/api-keys", {"name": "ci"})
        k = Client(self.base)
        k.bearer = key["key"]
        self.assertEqual(k.call("GET", f"/api/v1/orgs/{org['id']}")[0], 200)
        self.assertEqual(k.call("POST", "/api/v1/api-keys", {"name": "x"})[0], 403)

    def test_pending_partner_and_referral_signup(self):
        c = Client(self.base)
        _, body = c.call("POST", "/api/v1/partners/apply", {
            "company": "Pendente", "name": "P", "email": "p@pend.example", "password": "senha-super-secreta"})
        c.login("p@pend.example")
        self.assertEqual(c.call("POST", "/api/v1/orgs", {"name": "x"})[0], 403)
        self.assertEqual(c.call("POST", "/api/v1/partner/prospects",
                                {"name": "x", "domain": "x.example"})[0], 403)

        p, pid = self._partner("Indicadora", "ind@ref.example")
        _, partner = p.call("GET", "/api/v1/partner")
        anon = Client(self.base)
        self.assertEqual(anon.call("POST", "/api/v1/signup", {
            "company": "Direta", "name": "D", "email": "d@direta.example",
            "password": "senha-super-secreta", "referral_code": "BM-NOPE"})[0], 400)
        st, _ = anon.call("POST", "/api/v1/signup", {
            "company": "Direta", "name": "D", "email": "d@direta.example",
            "password": "senha-super-secreta", "referral_code": partner["referral_code"].lower()})
        self.assertEqual(st, 201)
        _, stmt = p.call("GET", "/api/v1/partner/statement")
        self.assertEqual([r["org"] for r in stmt["referrals"]], ["Direta"])
        self.assertEqual(p.call("GET", "/api/v1/orgs")[1], [])  # indicado não é gerenciado

        admin = Client(self.base)
        admin.login("root@plat.example")
        admin.call("POST", f"/api/v1/admin/partners/{pid}", {"status": "suspended"})
        self.assertEqual(p.call("GET", "/api/v1/orgs")[0], 403)

    def test_prospect_quota_and_login_errors(self):
        p, pid = self._partner("Prospectora", "pro@q.example")
        for i in range(5):
            self.assertEqual(p.call("POST", "/api/v1/partner/prospects",
                                    {"name": f"p{i}", "domain": f"p{i}.example"})[0], 201)
        st, body = p.call("POST", "/api/v1/partner/prospects", {"name": "x", "domain": "x.example"})
        self.assertEqual(st, 403)
        self.assertIn("cota", body["error"])
        self.assertEqual(len(p.call("GET", "/api/v1/partner/prospects")[1]), 5)
        self.assertEqual(Client(self.base).call(
            "POST", "/api/v1/auth/login", {"email": "pro@q.example", "password": "errada-errada"})[0], 401)

    def test_login_rate_limit_counts_failures_only(self):
        limiter = self.app.login_limiter.__class__(limit=2)
        self.assertFalse(limiter.blocked("ip"))
        limiter.fail("ip")
        limiter.fail("ip")
        self.assertTrue(limiter.blocked("ip"))
        self.assertFalse(limiter.blocked("outro"))

    def test_static_and_security_headers(self):
        req = urllib.request.Request(self.base + "/")
        with urllib.request.urlopen(req) as resp:
            self.assertIn("default-src 'self'", resp.headers["Content-Security-Policy"])
            self.assertEqual(resp.headers["X-Frame-Options"], "DENY")
            self.assertIn(b"app.js", resp.read())
        with urllib.request.urlopen(self.base + "/static/../../web.py") as resp:
            self.assertIn(b"<!doctype html>", resp.read())  # sem path traversal


if __name__ == "__main__":
    unittest.main()
