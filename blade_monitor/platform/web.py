"""API REST (/api/v1) e painel web da plataforma — apenas biblioteca padrão."""
from __future__ import annotations

import json
import logging
import mimetypes
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

from ..models import SEVERITY_ORDER
from . import auth, partners, report_html, verification, worker
from .db import Database, now
from .engine import EngineSettings

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).with_name("static")
MAX_BODY = 1_000_000
COOKIE = "bm_session"
ISSUE_STATUSES = ("open", "resolved", "accepted", "false_positive")
USER_SETTABLE_ISSUE_STATUSES = ("open", "accepted", "false_positive")


class HTTPError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class Settings:
    allow_private_targets: bool = False   # só para laboratório/testes
    secure_cookies: bool = False          # ative atrás de HTTPS
    engine: EngineSettings = field(default_factory=EngineSettings)


@dataclass
class Request:
    method: str
    path: str
    query: dict[str, str]
    body: dict
    headers: dict[str, str]
    client_ip: str
    params: dict[str, str] = field(default_factory=dict)
    user: dict | None = None
    csrf: str | None = None
    via_session: bool = False
    set_cookie: str | None = None

    def need(self, *keys: str) -> list:
        missing = [k for k in keys if not str(self.body.get(k, "")).strip()]
        if missing:
            raise HTTPError(400, "campos obrigatórios: " + ", ".join(missing))
        return [self.body[k] for k in keys]


@dataclass
class Response:
    status: int
    body: bytes
    content_type: str
    headers: dict[str, str] = field(default_factory=dict)


class RateLimiter:
    """Limita falhas de login por IP (janela deslizante simples)."""

    def __init__(self, limit: int = 10, window: float = 900):
        self.limit, self.window = limit, window
        self.failures: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    def _recent(self, key: str) -> list[float]:
        t = time.monotonic()
        recent = [x for x in self.failures.get(key, []) if t - x < self.window]
        self.failures[key] = recent
        return recent

    def blocked(self, key: str) -> bool:
        with self.lock:
            return len(self._recent(key)) >= self.limit

    def fail(self, key: str) -> None:
        with self.lock:
            self._recent(key).append(time.monotonic())


Route = tuple[str, re.Pattern, Callable, str]


class App:
    def __init__(self, db: Database, settings: Settings | None = None):
        self.db = db
        self.settings = settings or Settings()
        self.login_limiter = RateLimiter()
        self.verify_domain = verification.verify_domain  # substituível em testes
        self.routes: list[Route] = []
        r = self.route
        # públicas
        r("GET", "/api/v1/program", self.program, "public")
        r("POST", "/api/v1/auth/login", self.login, "public")
        r("POST", "/api/v1/auth/logout", self.logout, "public")
        r("POST", "/api/v1/partners/apply", self.partner_apply, "public")
        r("POST", "/api/v1/signup", self.signup, "public")
        # sessão
        r("GET", "/api/v1/me", self.me)
        # administração da plataforma
        r("GET", "/api/v1/admin/partners", self.admin_partners)
        r("POST", "/api/v1/admin/partners/(?P<id>\\d+)", self.admin_partner_update)
        r("GET", "/api/v1/admin/audit", self.admin_audit)
        # parceiro
        r("GET", "/api/v1/partner", self.partner_get)
        r("PATCH", "/api/v1/partner", self.partner_update)
        r("GET", "/api/v1/partner/statement", self.partner_statement)
        r("GET", "/api/v1/partner/prospects", self.prospects_list)
        r("POST", "/api/v1/partner/prospects", self.prospects_create)
        # organizações (clientes)
        r("GET", "/api/v1/orgs", self.orgs_list)
        r("POST", "/api/v1/orgs", self.orgs_create)
        r("GET", "/api/v1/orgs/(?P<id>\\d+)", self.org_get)
        r("PATCH", "/api/v1/orgs/(?P<id>\\d+)", self.org_update)
        r("GET", "/api/v1/orgs/(?P<id>\\d+)/history", self.org_history)
        r("GET", "/api/v1/orgs/(?P<id>\\d+)/assets", self.assets_list)
        r("POST", "/api/v1/orgs/(?P<id>\\d+)/assets", self.assets_create)
        r("POST", "/api/v1/assets/(?P<id>\\d+)/verify", self.asset_verify)
        r("POST", "/api/v1/assets/(?P<id>\\d+)/attest", self.asset_attest)
        r("DELETE", "/api/v1/assets/(?P<id>\\d+)", self.asset_delete)
        r("GET", "/api/v1/orgs/(?P<id>\\d+)/scans", self.scans_list)
        r("POST", "/api/v1/orgs/(?P<id>\\d+)/scans", self.scans_create)
        r("GET", "/api/v1/scans/(?P<id>\\d+)", self.scan_get)
        r("GET", "/api/v1/orgs/(?P<id>\\d+)/issues", self.issues_list)
        r("PATCH", "/api/v1/issues/(?P<id>\\d+)", self.issue_update)
        r("GET", "/api/v1/orgs/(?P<id>\\d+)/vendors", self.vendors_list)
        r("POST", "/api/v1/orgs/(?P<id>\\d+)/vendors", self.vendors_create)
        r("POST", "/api/v1/watch/(?P<id>\\d+)/scan", self.watch_scan)
        r("DELETE", "/api/v1/watch/(?P<id>\\d+)", self.watch_delete)
        # usuários e chaves
        r("GET", "/api/v1/users", self.users_list)
        r("POST", "/api/v1/users", self.users_create)
        r("DELETE", "/api/v1/users/(?P<id>\\d+)", self.user_deactivate)
        r("GET", "/api/v1/api-keys", self.keys_list)
        r("POST", "/api/v1/api-keys", self.keys_create)
        r("DELETE", "/api/v1/api-keys/(?P<id>\\d+)", self.key_delete)
        # relatórios HTML
        r("GET", "/reports/scan/(?P<id>\\d+)", self.report_scan)

    def route(self, method: str, pattern: str, fn: Callable, access: str = "user") -> None:
        self.routes.append((method, re.compile(f"^{pattern}$"), fn, access))

    # ----------------------------------------------------------- despacho
    def dispatch(self, req: Request) -> Response:
        try:
            if not req.path.startswith(("/api/", "/reports/")):
                return self.static(req.path)
            allowed = False
            for method, pattern, fn, access in self.routes:
                m = pattern.match(req.path)
                if not m:
                    continue
                allowed = True
                if method != req.method:
                    continue
                req.params = m.groupdict()
                if access != "public":
                    self._authenticate(req)
                result = fn(req)
                if isinstance(result, Response):
                    return result
                status, payload = result if isinstance(result, tuple) else (200, result)
                resp = _json(status, payload)
                if req.set_cookie:
                    resp.headers["Set-Cookie"] = req.set_cookie
                return resp
            raise HTTPError(405 if allowed else 404,
                            "método não permitido" if allowed else "não encontrado")
        except HTTPError as exc:
            return _json(exc.status, {"error": exc.message})
        except (auth.AuthError, ValueError) as exc:
            return _json(400, {"error": str(exc)})
        except Exception:  # noqa: BLE001
            log.exception("Erro interno em %s %s", req.method, req.path)
            return _json(500, {"error": "erro interno"})

    def _authenticate(self, req: Request) -> None:
        header = req.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            req.user = auth.api_key_user(self.db, header[7:].strip())
        else:
            token = _cookie(req.headers.get("cookie", ""))
            found = auth.session_user(self.db, token) if token else None
            if found:
                req.user, req.csrf = found
                req.via_session = True
        if not req.user:
            raise HTTPError(401, "autenticação necessária")
        if req.user["partner_id"]:
            p = self.db.one("SELECT status FROM partners WHERE id = ?", (req.user["partner_id"],))
            if p and p["status"] == "suspended":
                raise HTTPError(403, "conta de parceiro suspensa")
        if req.via_session and req.method not in ("GET", "HEAD"):
            sent = req.headers.get("x-csrf-token", "")
            if not secrets.compare_digest(sent, req.csrf or ""):
                raise HTTPError(403, "token CSRF inválido")

    def static(self, path: str) -> Response:
        name = "index.html" if path in ("/", "") else path.lstrip("/").removeprefix("static/")
        target = (STATIC_DIR / name).resolve()
        if STATIC_DIR.resolve() not in target.parents or not target.is_file():
            target = STATIC_DIR / "index.html"
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        return Response(200, target.read_bytes(), ctype, {"Cache-Control": "no-cache"})

    # ------------------------------------------------------ carregadores
    def _org(self, req: Request, org_id, write: bool = False) -> dict:
        org = self.db.one("SELECT * FROM organizations WHERE id = ?", (int(org_id),))
        if not org or not auth.can_view_org(req.user, org):
            raise HTTPError(404, "organização não encontrada")
        if write and not auth.can_edit_org(req.user, org):
            raise HTTPError(403, "sem permissão de escrita")
        return org

    def _partner_of(self, req: Request) -> dict:
        if req.user["role"] not in auth.PARTNER_ROLES:
            raise HTTPError(403, "apenas usuários de parceiros")
        return self.db.one("SELECT * FROM partners WHERE id = ?", (req.user["partner_id"],))

    def _watch(self, req: Request, watch_id, write: bool = False) -> dict:
        w = self.db.one("SELECT * FROM watchlist WHERE id = ?", (int(watch_id),))
        if not w:
            raise HTTPError(404, "alvo não encontrado")
        if w["org_id"]:
            self._org(req, w["org_id"], write)
        elif not (req.user["role"] == "admin" or (
                req.user["role"] in auth.PARTNER_ROLES and req.user["partner_id"] == w["partner_id"])):
            raise HTTPError(404, "alvo não encontrado")
        return w

    def _require_role(self, req: Request, *roles: str) -> None:
        if req.user["role"] not in roles:
            raise HTTPError(403, "permissão insuficiente")

    # ----------------------------------------------------------- públicas
    def program(self, req: Request):
        return partners.program_overview()

    def login(self, req: Request):
        email, password = req.need("email", "password")
        if self.login_limiter.blocked(req.client_ip):
            raise HTTPError(429, "muitas tentativas; aguarde alguns minutos")
        try:
            user = auth.authenticate(self.db, email, password)
        except auth.AuthError:
            self.login_limiter.fail(req.client_ip)
            raise HTTPError(401, "e-mail ou senha inválidos") from None
        token, csrf = auth.create_session(self.db, user["id"])
        req.set_cookie = self._session_cookie(token, auth.SESSION_HOURS * 3600)
        self.db.audit("login", user=user)
        return {"user": auth.public_user(user), "csrf": csrf}

    def logout(self, req: Request):
        token = _cookie(req.headers.get("cookie", ""))
        if token:
            auth.end_session(self.db, token)
        req.set_cookie = self._session_cookie("", 0)
        return {"ok": True}

    def _session_cookie(self, token: str, max_age: int) -> str:
        secure = "; Secure" if self.settings.secure_cookies else ""
        return f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"

    def partner_apply(self, req: Request):
        company, name, email, password = req.need("company", "name", "email", "password")
        if "@" not in email:
            raise HTTPError(400, "e-mail inválido")
        if len(password) < auth.MIN_PASSWORD:
            raise HTTPError(400, f"a senha precisa ter ao menos {auth.MIN_PASSWORD} caracteres")
        if self.db.one("SELECT 1 FROM users WHERE email = ?", (email.strip().lower(),)):
            raise HTTPError(409, "e-mail já cadastrado")
        pid = self.db.execute(
            "INSERT INTO partners (name, website, referral_code, brand_name, support_email,"
            " created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (company.strip()[:120], str(req.body.get("website", ""))[:200],
             partners.new_referral_code(), company.strip()[:120], email.strip().lower(), now()))
        uid = auth.create_user(self.db, email, password, "partner_admin", name=name, partner_id=pid)
        self.db.audit("partner.apply", company, partner_id=pid, user={"id": uid, "partner_id": pid})
        return 201, {"partner_id": pid, "status": "pending",
                     "message": "Cadastro recebido. Avaliaremos e ativaremos sua conta de parceiro."}

    def signup(self, req: Request):
        """Cadastro de cliente direto (opcionalmente indicado por um parceiro)."""
        company, name, email, password = req.need("company", "name", "email", "password")
        plan = req.body.get("plan", "essentials")
        if plan not in partners.PLANS:
            raise HTTPError(400, "plano inválido")
        if "@" not in email:
            raise HTTPError(400, "e-mail inválido")
        if len(password) < auth.MIN_PASSWORD:
            raise HTTPError(400, f"a senha precisa ter ao menos {auth.MIN_PASSWORD} caracteres")
        if self.db.one("SELECT 1 FROM users WHERE email = ?", (email.strip().lower(),)):
            raise HTTPError(409, "e-mail já cadastrado")
        referrer = None
        code = str(req.body.get("referral_code", "")).strip().upper()
        if code:
            referrer = self.db.one("SELECT id FROM partners WHERE referral_code = ? AND status = 'active'",
                                   (code,))
            if not referrer:
                raise HTTPError(400, "código de indicação inválido")
        oid = self.db.execute(
            "INSERT INTO organizations (name, referred_by, plan, created_at) VALUES (?, ?, ?, ?)",
            (company.strip()[:120], referrer["id"] if referrer else None, plan, now()))
        auth.create_user(self.db, email, password, "org_admin", name=name, org_id=oid)
        self.db.audit("org.signup", company, org_id=oid,
                      partner_id=referrer["id"] if referrer else None)
        return 201, {"org_id": oid}

    # ------------------------------------------------------------- sessão
    def me(self, req: Request):
        u = req.user
        out = {"user": auth.public_user(u), "csrf": req.csrf}
        if u["partner_id"]:
            p = self.db.one("SELECT * FROM partners WHERE id = ?", (u["partner_id"],))
            out["partner"] = {**p, "tier": partners.tier_for(self.db, p)}
        if u["org_id"]:
            org = self.db.one("SELECT * FROM organizations WHERE id = ?", (u["org_id"],))
            out["org"] = org
            if org["partner_id"]:
                p = self.db.one("SELECT * FROM partners WHERE id = ?", (org["partner_id"],))
                out["brand"] = report_html.branding(p, partners.tier_for(self.db, p)["white_label"])
        return out

    # ------------------------------------------------------------- admin
    def admin_partners(self, req: Request):
        self._require_role(req, "admin")
        rows = self.db.all("SELECT * FROM partners ORDER BY status = 'pending' DESC, name")
        return [{**p, "tier": partners.tier_for(self.db, p)} for p in rows]

    def admin_partner_update(self, req: Request):
        self._require_role(req, "admin")
        p = self.db.one("SELECT * FROM partners WHERE id = ?", (int(req.params["id"]),))
        if not p:
            raise HTTPError(404, "parceiro não encontrado")
        status = req.body.get("status", p["status"])
        if status not in ("pending", "active", "suspended"):
            raise HTTPError(400, "status inválido")
        tier = req.body.get("tier_override", p["tier_override"]) or None
        if tier and tier not in {t[0] for t in partners.TIERS}:
            raise HTTPError(400, "nível inválido")
        approved = p["approved_at"] or (now() if status == "active" else None)
        self.db.execute("UPDATE partners SET status = ?, tier_override = ?, approved_at = ? WHERE id = ?",
                        (status, tier, approved, p["id"]))
        self.db.audit("partner.update", f"status={status} tier={tier}", user=req.user,
                      partner_id=p["id"])
        return self.db.one("SELECT * FROM partners WHERE id = ?", (p["id"],))

    def admin_audit(self, req: Request):
        self._require_role(req, "admin")
        limit = min(int(req.query.get("limit", 100)), 1000)
        return self.db.all("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))

    # ----------------------------------------------------------- parceiro
    def partner_get(self, req: Request):
        p = self._partner_of(req)
        return {**p, "tier": partners.tier_for(self.db, p), "program": partners.program_overview()}

    def partner_update(self, req: Request):
        self._require_role(req, "partner_admin")
        p = self._partner_of(req)
        b = req.body
        color = b.get("brand_color", p["brand_color"])
        if not re.fullmatch(r"#[0-9a-fA-F]{6}", color):
            raise HTTPError(400, "cor inválida (use #RRGGBB)")
        logo = b.get("logo_url", p["logo_url"]).strip()
        if logo and not logo.startswith("https://"):
            raise HTTPError(400, "o logo precisa ser uma URL https://")
        white = bool(b.get("white_label", p["white_label"]))
        if white and not partners.tier_for(self.db, p)["white_label"]:
            raise HTTPError(403, "white-label disponível a partir do nível Silver")
        self.db.execute(
            "UPDATE partners SET brand_name = ?, brand_color = ?, logo_url = ?, support_email = ?,"
            " white_label = ? WHERE id = ?",
            (str(b.get("brand_name", p["brand_name"]))[:120], color, logo,
             str(b.get("support_email", p["support_email"]))[:200], int(white), p["id"]))
        self.db.audit("partner.branding", user=req.user)
        return self.partner_get(req)

    def partner_statement(self, req: Request):
        self._require_role(req, "partner_admin")
        month = req.query.get("month") or datetime.now(timezone.utc).strftime("%Y-%m")
        if not re.fullmatch(r"\d{4}-\d{2}", month):
            raise HTTPError(400, "mês no formato AAAA-MM")
        return partners.statement(self.db, self._partner_of(req), month)

    def prospects_list(self, req: Request):
        p = self._partner_of(req)
        return self._watch_rows("w.partner_id = ? AND w.kind = 'prospect'", (p["id"],))

    def prospects_create(self, req: Request):
        p = self._partner_of(req)
        if p["status"] != "active":
            raise HTTPError(403, "conta de parceiro ainda não aprovada")
        name, domain = req.need("name", "domain")
        domain = verification.normalize_asset("domain", domain)
        quota = partners.tier_for(self.db, p)["prospects_per_month"]
        month = datetime.now(timezone.utc).strftime("%Y-%m")
        used = self.db.one("SELECT COUNT(*) AS n FROM watchlist WHERE partner_id = ?"
                           " AND kind = 'prospect' AND substr(created_at, 1, 7) = ?",
                           (p["id"], month))["n"]
        if quota is not None and used >= quota:
            raise HTTPError(403, f"cota mensal de avaliações de prospects atingida ({quota})")
        wid = self.db.execute(
            "INSERT INTO watchlist (partner_id, kind, name, domain, created_at)"
            " VALUES (?, 'prospect', ?, ?, ?)", (p["id"], name.strip()[:120], domain, now()))
        sid = worker.enqueue(self.db, mode="passive", watch_id=wid, user_id=req.user["id"])
        self.db.audit("prospect.create", domain, user=req.user)
        return 201, {"id": wid, "scan_id": sid}

    # -------------------------------------------------------- organizações
    def _org_summary(self, org: dict) -> dict:
        last = self.db.one(
            "SELECT id, score, grade, finished_at, hosts, services FROM scans WHERE org_id = ?"
            " AND mode = 'active' AND status = 'done' ORDER BY id DESC LIMIT 1", (org["id"],))
        sev = {r["severity"]: r["n"] for r in self.db.all(
            "SELECT severity, COUNT(*) AS n FROM issues WHERE org_id = ? AND status = 'open'"
            " GROUP BY severity", (org["id"],))}
        assets = self.db.one(
            "SELECT COUNT(*) AS total, SUM(verified_at IS NOT NULL) AS verified FROM assets"
            " WHERE org_id = ?", (org["id"],))
        return {**org, "last_scan": last,
                "open_issues": {s: sev.get(s, 0) for s in SEVERITY_ORDER},
                "assets": {"total": assets["total"], "verified": assets["verified"] or 0},
                "plan_info": partners.PLANS[org["plan"]]}

    def orgs_list(self, req: Request):
        u = req.user
        if u["role"] == "admin":
            rows = self.db.all("SELECT * FROM organizations ORDER BY name")
        elif u["role"] in auth.PARTNER_ROLES:
            rows = self.db.all("SELECT * FROM organizations WHERE partner_id = ? ORDER BY name",
                               (u["partner_id"],))
        else:
            rows = self.db.all("SELECT * FROM organizations WHERE id = ?", (u["org_id"],))
        return [self._org_summary(o) for o in rows]

    def orgs_create(self, req: Request):
        u = req.user
        self._require_role(req, "admin", "partner_admin", "partner_analyst")
        (name,) = req.need("name")
        plan = req.body.get("plan", "essentials")
        if plan not in partners.PLANS:
            raise HTTPError(400, "plano inválido")
        partner_id = None
        if u["role"] in auth.PARTNER_ROLES:
            p = self._partner_of(req)
            if p["status"] != "active":
                raise HTTPError(403, "conta de parceiro ainda não aprovada")
            partner_id = p["id"]
        elif req.body.get("partner_id"):
            partner_id = int(req.body["partner_id"])
        oid = self.db.execute(
            "INSERT INTO organizations (name, partner_id, plan, created_at) VALUES (?, ?, ?, ?)",
            (name.strip()[:120], partner_id, plan, now()))
        if req.body.get("admin_email"):
            auth.create_user(self.db, req.body["admin_email"], req.body.get("admin_password", ""),
                             "org_admin", name=req.body.get("admin_name", ""), org_id=oid)
        self.db.audit("org.create", name, user=u, org_id=oid, partner_id=partner_id)
        return 201, self._org_summary(self.db.one("SELECT * FROM organizations WHERE id = ?", (oid,)))

    def org_get(self, req: Request):
        return self._org_summary(self._org(req, req.params["id"]))

    def org_update(self, req: Request):
        org = self._org(req, req.params["id"], write=True)
        b = req.body
        if "plan" in b and b["plan"] != org["plan"]:
            if req.user["role"] not in ("admin", "partner_admin"):
                raise HTTPError(403, "apenas o parceiro ou a administração alteram o plano")
            if b["plan"] not in partners.PLANS:
                raise HTTPError(400, "plano inválido")
        if "status" in b and req.user["role"] not in ("admin", "partner_admin"):
            raise HTTPError(403, "sem permissão para alterar o status")
        sev = b.get("alert_min_severity", org["alert_min_severity"])
        if sev not in SEVERITY_ORDER:
            raise HTTPError(400, "severidade inválida")
        hook = str(b.get("webhook_url", org["webhook_url"])).strip()
        if hook and not hook.startswith("https://"):
            raise HTTPError(400, "o webhook precisa ser https://")
        status = b.get("status", org["status"])
        if status not in ("active", "suspended"):
            raise HTTPError(400, "status inválido")
        self.db.execute(
            "UPDATE organizations SET name = ?, plan = ?, status = ?, exclude = ?, webhook_url = ?,"
            " alert_min_severity = ? WHERE id = ?",
            (str(b.get("name", org["name"]))[:120], b.get("plan", org["plan"]), status,
             str(b.get("exclude", org["exclude"]))[:5000], hook, sev, org["id"]))
        self.db.audit("org.update", json.dumps(b, ensure_ascii=False)[:500], user=req.user,
                      org_id=org["id"])
        return self.org_get(req)

    def org_history(self, req: Request):
        org = self._org(req, req.params["id"])
        return self.db.all(
            "SELECT id, finished_at, score, grade, categories, hosts, services, findings FROM scans"
            " WHERE org_id = ? AND mode = 'active' AND status = 'done' ORDER BY id DESC LIMIT 90",
            (org["id"],))[::-1]

    # -------------------------------------------------------------- ativos
    def assets_list(self, req: Request):
        org = self._org(req, req.params["id"])
        rows = self.db.all("SELECT * FROM assets WHERE org_id = ? ORDER BY kind, value", (org["id"],))
        for a in rows:
            if a["kind"] == "domain" and not a["verified_at"]:
                a["instructions"] = verification.instructions(a["value"], a["verification_token"])
        return rows

    def assets_create(self, req: Request):
        org = self._org(req, req.params["id"], write=True)
        kind, value = req.need("kind", "value")
        value = verification.normalize_asset(kind, value, self.settings.allow_private_targets)
        count = self.db.one("SELECT COUNT(*) AS n FROM assets WHERE org_id = ?", (org["id"],))["n"]
        limit = partners.PLANS[org["plan"]]["max_assets"]
        if count >= limit:
            raise HTTPError(403, f"limite do plano atingido ({limit} ativos)")
        if self.db.one("SELECT 1 FROM assets WHERE org_id = ? AND kind = ? AND value = ?",
                       (org["id"], kind, value)):
            raise HTTPError(409, "ativo já cadastrado")
        token = secrets.token_hex(16)
        aid = self.db.execute(
            "INSERT INTO assets (org_id, kind, value, verification_token, created_at)"
            " VALUES (?, ?, ?, ?, ?)", (org["id"], kind, value, token, now()))
        self.db.audit("asset.create", f"{kind}:{value}", user=req.user, org_id=org["id"])
        out = self.db.one("SELECT * FROM assets WHERE id = ?", (aid,))
        if kind == "domain":
            out["instructions"] = verification.instructions(value, token)
        return 201, out

    def _asset(self, req: Request, write: bool = True) -> tuple[dict, dict]:
        a = self.db.one("SELECT * FROM assets WHERE id = ?", (int(req.params["id"]),))
        if not a:
            raise HTTPError(404, "ativo não encontrado")
        return a, self._org(req, a["org_id"], write)

    def asset_verify(self, req: Request):
        a, org = self._asset(req)
        if a["kind"] != "domain":
            raise HTTPError(400, "IPs e redes são verificados por atestado (/attest)")
        method = self.verify_domain(a["value"], a["verification_token"])
        if not method:
            return {"verified": False, "instructions":
                    verification.instructions(a["value"], a["verification_token"])}
        self.db.execute("UPDATE assets SET verified_at = ?, verified_method = ?, verified_by = ?"
                        " WHERE id = ?", (now(), method, req.user["id"], a["id"]))
        self.db.audit("asset.verify", f"{a['value']} via {method}", user=req.user, org_id=org["id"])
        return {"verified": True, "method": method}

    def asset_attest(self, req: Request):
        a, org = self._asset(req)
        self._require_role(req, "admin", "partner_admin", "org_admin")
        if a["kind"] == "domain":
            raise HTTPError(400, "domínios exigem verificação técnica (DNS ou HTTP)")
        (note,) = req.need("note")
        self.db.execute(
            "UPDATE assets SET verified_at = ?, verified_method = 'attestation', verified_by = ?,"
            " attestation_note = ? WHERE id = ?", (now(), req.user["id"], note[:500], a["id"]))
        self.db.audit("asset.attest", f"{a['value']}: {note}", user=req.user, org_id=org["id"])
        return {"verified": True, "method": "attestation"}

    def asset_delete(self, req: Request):
        a, org = self._asset(req)
        self.db.execute("DELETE FROM assets WHERE id = ?", (a["id"],))
        self.db.audit("asset.delete", a["value"], user=req.user, org_id=org["id"])
        return {"ok": True}

    # ----------------------------------------------------------- varreduras
    def scans_list(self, req: Request):
        org = self._org(req, req.params["id"])
        return self.db.all(
            "SELECT id, mode, status, trigger, queued_at, started_at, finished_at, error, score,"
            " grade, hosts, services, findings FROM scans WHERE org_id = ? AND watch_id IS NULL"
            " ORDER BY id DESC LIMIT 50", (org["id"],))

    def scans_create(self, req: Request):
        org = self._org(req, req.params["id"], write=True)
        if org["status"] != "active":
            raise HTTPError(403, "organização suspensa")
        if not self.db.one("SELECT 1 FROM assets WHERE org_id = ? AND verified_at IS NOT NULL",
                           (org["id"],)):
            raise HTTPError(400, "nenhum ativo verificado — verifique a posse antes de varrer")
        sid = worker.enqueue(self.db, mode="active", org_id=org["id"],
                             trigger="api" if not req.via_session else "manual",
                             user_id=req.user["id"])
        self.db.audit("scan.request", str(sid), user=req.user, org_id=org["id"])
        return 202, {"scan_id": sid}

    def _scan(self, req: Request, scan_id) -> dict:
        s = self.db.one("SELECT * FROM scans WHERE id = ?", (int(scan_id),))
        if not s:
            raise HTTPError(404, "varredura não encontrada")
        if s["watch_id"]:
            self._watch(req, s["watch_id"])
        else:
            self._org(req, s["org_id"])
        return s

    def scan_get(self, req: Request):
        s = self._scan(req, req.params["id"])
        for k in ("categories", "changes", "data"):
            s[k] = json.loads(s[k]) if s[k] else None
        return s

    # -------------------------------------------------------------- achados
    def issues_list(self, req: Request):
        org = self._org(req, req.params["id"])
        status = req.query.get("status", "open")
        where, args = "org_id = ?", [org["id"]]
        if status != "all":
            if status not in ISSUE_STATUSES:
                raise HTTPError(400, "status inválido")
            where += " AND status = ?"
            args.append(status)
        if req.query.get("severity") in SEVERITY_ORDER:
            where += " AND severity = ?"
            args.append(req.query["severity"])
        rows = self.db.all(f"SELECT * FROM issues WHERE {where}", tuple(args))
        return sorted(rows, key=lambda i: (-SEVERITY_ORDER[i["severity"]], i["asset"], i["rule"]))

    def issue_update(self, req: Request):
        issue = self.db.one("SELECT * FROM issues WHERE id = ?", (int(req.params["id"]),))
        if not issue:
            raise HTTPError(404, "achado não encontrado")
        org = self._org(req, issue["org_id"], write=True)
        status = req.body.get("status", issue["status"])
        if status != issue["status"] and status not in USER_SETTABLE_ISSUE_STATUSES:
            raise HTTPError(400, "status deve ser open, accepted ou false_positive")
        note = str(req.body.get("note", issue["note"]))[:1000]
        if status in ("accepted", "false_positive") and not note.strip():
            raise HTTPError(400, "justificativa obrigatória para aceitar risco/falso positivo")
        self.db.execute("UPDATE issues SET status = ?, note = ? WHERE id = ?",
                        (status, note, issue["id"]))
        self.db.audit("issue.update", f"#{issue['id']} {issue['rule']} -> {status}",
                      user=req.user, org_id=org["id"])
        return self.db.one("SELECT * FROM issues WHERE id = ?", (issue["id"],))

    # ------------------------------------------- fornecedores (terceiros)
    def _watch_rows(self, where: str, args: tuple) -> list[dict]:
        return self.db.all(
            "SELECT w.*, s.id AS scan_id, s.status AS scan_status, s.score, s.grade,"
            " s.finished_at FROM watchlist w LEFT JOIN scans s ON s.id = ("
            "  SELECT id FROM scans WHERE watch_id = w.id ORDER BY id DESC LIMIT 1)"
            f" WHERE {where} ORDER BY w.name", args)

    def vendors_list(self, req: Request):
        org = self._org(req, req.params["id"])
        return self._watch_rows("w.org_id = ? AND w.kind = 'vendor'", (org["id"],))

    def vendors_create(self, req: Request):
        org = self._org(req, req.params["id"], write=True)
        name, domain = req.need("name", "domain")
        domain = verification.normalize_asset("domain", domain)
        crit = req.body.get("criticality", "medium")
        if crit not in ("low", "medium", "high", "critical"):
            raise HTTPError(400, "criticidade inválida")
        used = self.db.one("SELECT COUNT(*) AS n FROM watchlist WHERE org_id = ?", (org["id"],))["n"]
        limit = partners.PLANS[org["plan"]]["vendors"]
        if used >= limit:
            raise HTTPError(403, f"limite do plano atingido ({limit} fornecedores)")
        wid = self.db.execute(
            "INSERT INTO watchlist (org_id, kind, name, domain, criticality, created_at)"
            " VALUES (?, 'vendor', ?, ?, ?, ?)", (org["id"], name.strip()[:120], domain, crit, now()))
        sid = worker.enqueue(self.db, mode="passive", watch_id=wid, user_id=req.user["id"])
        self.db.audit("vendor.create", domain, user=req.user, org_id=org["id"])
        return 201, {"id": wid, "scan_id": sid}

    def watch_scan(self, req: Request):
        w = self._watch(req, req.params["id"], write=True)
        return 202, {"scan_id": worker.enqueue(self.db, mode="passive", watch_id=w["id"],
                                               user_id=req.user["id"])}

    def watch_delete(self, req: Request):
        w = self._watch(req, req.params["id"], write=True)
        self.db.execute("DELETE FROM watchlist WHERE id = ?", (w["id"],))
        self.db.audit("watch.delete", w["domain"], user=req.user, org_id=w["org_id"])
        return {"ok": True}

    # ------------------------------------------------------------ usuários
    def users_list(self, req: Request):
        u = req.user
        if u["role"] == "admin":
            rows = self.db.all("SELECT * FROM users ORDER BY email")
        elif u["role"] == "partner_admin":
            rows = self.db.all(
                "SELECT * FROM users WHERE partner_id = ? OR org_id IN"
                " (SELECT id FROM organizations WHERE partner_id = ?) ORDER BY email",
                (u["partner_id"], u["partner_id"]))
        elif u["role"] == "org_admin":
            rows = self.db.all("SELECT * FROM users WHERE org_id = ? ORDER BY email", (u["org_id"],))
        else:
            raise HTTPError(403, "permissão insuficiente")
        return [auth.public_user(r) for r in rows]

    def _can_manage_user(self, actor: dict, role: str, partner_id, org_id) -> bool:
        if actor["role"] == "admin":
            return True
        if actor["role"] == "partner_admin":
            if role in auth.PARTNER_ROLES:
                return partner_id == actor["partner_id"]
            if role in auth.ORG_ROLES and org_id:
                org = self.db.one("SELECT partner_id FROM organizations WHERE id = ?", (org_id,))
                return bool(org) and org["partner_id"] == actor["partner_id"]
        if actor["role"] == "org_admin":
            return role in auth.ORG_ROLES and org_id == actor["org_id"]
        return False

    def users_create(self, req: Request):
        email, password, role = req.need("email", "password", "role")
        partner_id = req.body.get("partner_id")
        org_id = req.body.get("org_id")
        if req.user["role"] == "partner_admin" and role in auth.PARTNER_ROLES:
            partner_id = req.user["partner_id"]
        if req.user["role"] == "org_admin":
            org_id = req.user["org_id"]
        partner_id = int(partner_id) if partner_id else None
        org_id = int(org_id) if org_id else None
        if not self._can_manage_user(req.user, role, partner_id, org_id):
            raise HTTPError(403, "sem permissão para criar este usuário")
        uid = auth.create_user(self.db, email, password, role, name=req.body.get("name", ""),
                               partner_id=partner_id, org_id=org_id)
        self.db.audit("user.create", f"{email} ({role})", user=req.user, org_id=org_id)
        return 201, auth.public_user(self.db.one("SELECT * FROM users WHERE id = ?", (uid,)))

    def user_deactivate(self, req: Request):
        target = self.db.one("SELECT * FROM users WHERE id = ?", (int(req.params["id"]),))
        if not target or target["id"] == req.user["id"] or not self._can_manage_user(
                req.user, target["role"], target["partner_id"], target["org_id"]):
            raise HTTPError(404, "usuário não encontrado")
        self.db.execute("UPDATE users SET active = 0 WHERE id = ?", (target["id"],))
        self.db.execute("DELETE FROM sessions WHERE user_id = ?", (target["id"],))
        self.db.execute("DELETE FROM api_keys WHERE user_id = ?", (target["id"],))
        self.db.audit("user.deactivate", target["email"], user=req.user)
        return {"ok": True}

    # -------------------------------------------------------- chaves de API
    def keys_list(self, req: Request):
        return self.db.all("SELECT id, name, prefix, created_at, last_used FROM api_keys"
                           " WHERE user_id = ? ORDER BY id", (req.user["id"],))

    def keys_create(self, req: Request):
        if not req.via_session:
            raise HTTPError(403, "crie chaves pelo painel")
        key_id, key = auth.create_api_key(self.db, req.user["id"], req.body.get("name", "api"))
        self.db.audit("apikey.create", str(key_id), user=req.user)
        return 201, {"id": key_id, "key": key, "warning": "Guarde a chave: ela não será exibida novamente."}

    def key_delete(self, req: Request):
        n = self.db.execute("DELETE FROM api_keys WHERE id = ? AND user_id = ?",
                            (int(req.params["id"]), req.user["id"]))
        if not n:
            raise HTTPError(404, "chave não encontrada")
        return {"ok": True}

    # ----------------------------------------------------------- relatórios
    def report_scan(self, req: Request) -> Response:
        s = self._scan(req, req.params["id"])
        if s["status"] != "done":
            raise HTTPError(409, "varredura ainda não concluída")
        partner = None
        if s["org_id"]:
            org = self.db.one("SELECT * FROM organizations WHERE id = ?", (s["org_id"],))
            subject = org["name"]
            if org["partner_id"]:
                partner = self.db.one("SELECT * FROM partners WHERE id = ?", (org["partner_id"],))
            issues = [i for i in self.db.all(
                "SELECT * FROM issues WHERE org_id = ? AND status = 'open'", (org["id"],))]
            history = self.db.all("SELECT score, grade FROM scans WHERE org_id = ? AND mode = 'active'"
                                  " AND status = 'done' AND id <= ? ORDER BY id", (org["id"], s["id"]))
        else:
            w = self.db.one("SELECT * FROM watchlist WHERE id = ?", (s["watch_id"],))
            subject = f"{w['name']} ({w['domain']}) — avaliação passiva"
            if w["partner_id"]:
                partner = self.db.one("SELECT * FROM partners WHERE id = ?", (w["partner_id"],))
            elif w["org_id"]:
                org = self.db.one("SELECT * FROM organizations WHERE id = ?", (w["org_id"],))
                if org["partner_id"]:
                    partner = self.db.one("SELECT * FROM partners WHERE id = ?", (org["partner_id"],))
            issues = json.loads(s["data"])["findings"]
            history = None
        brand = report_html.branding(
            partner, partners.tier_for(self.db, partner)["white_label"] if partner else False)
        html = report_html.render(subject, s, issues, brand, history)
        return Response(200, html.encode(), "text/html; charset=utf-8", {
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src https:"})


# ----------------------------------------------------------------- HTTP

def _json(status: int, payload) -> Response:
    return Response(status, json.dumps(payload, ensure_ascii=False, default=str).encode(),
                    "application/json; charset=utf-8")


def _cookie(header: str) -> str | None:
    jar = SimpleCookie()
    try:
        jar.load(header)
    except Exception:  # noqa: BLE001
        return None
    return jar[COOKIE].value if COOKIE in jar and jar[COOKIE].value else None


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' https: data:; "
                               "style-src 'self'; script-src 'self'; frame-ancestors 'none'",
}


def make_handler(app: App) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "BladeMonitor"
        sys_version = ""

        def _handle(self):
            parts = urlsplit(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._send(_json(413, {"error": "corpo muito grande"}))
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw) if raw else {}
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._send(_json(400, {"error": "JSON inválido"}))
            req = Request(
                method=self.command, path=parts.path.rstrip("/") or "/",
                query={k: v[0] for k, v in parse_qs(parts.query).items()}, body=body,
                headers={k.lower(): v for k, v in self.headers.items()},
                client_ip=self.client_address[0])
            self._send(app.dispatch(req))

        def _send(self, resp: Response):
            self.send_response(resp.status)
            headers = {**SECURITY_HEADERS, **resp.headers}
            headers["Content-Type"] = resp.content_type
            headers["Content-Length"] = str(len(resp.body))
            if resp.content_type.startswith("application/json"):
                headers.setdefault("Cache-Control", "no-store")
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(resp.body)

        do_GET = do_POST = do_PATCH = do_DELETE = do_HEAD = _handle

        def log_message(self, fmt, *args):
            log.debug("%s %s", self.address_string(), fmt % args)

    return Handler


def serve(app: App, host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(app))
    server.daemon_threads = True
    return server
