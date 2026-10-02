"""Dados sintéticos de demonstração (nenhuma varredura real é executada).

Usa domínios reservados (RFC 2606, *.example) e IPs de documentação (RFC 5737).
"""
from __future__ import annotations

import secrets

from ..models import HTTPInfo, Service, Snapshot, TLSInfo
from ..rules import evaluate
from . import auth, partners
from .db import Database, now
from .engine import EngineSettings, finalize

DEMO_PASSWORD = "demo-password-123"


def _service(host: str, ip: str, port: int, **kw) -> Service:
    return Service(host, ip, port, **kw)


def _web(host: str, ip: str, *, days: int = 200, self_signed: bool = False, headers: bool = True,
         title: str = "Home", server: str = "nginx", tls_proto: str = "TLSv1.3") -> list[Service]:
    missing = [] if headers else ["content-security-policy", "x-frame-options"]
    return [
        _service(host, ip, 80, http=HTTPInfo(url=f"http://{host}/", status=301,
                                             redirect_to_https=True, server=server)),
        _service(host, ip, 443,
                 tls=TLSInfo(subject=f"CN={host}", issuer="CN=Demo CA", days_left=days,
                             not_after="2027-01-01T00:00:00+00:00", self_signed=self_signed,
                             protocol=tls_proto, san=[host]),
                 http=HTTPInfo(url=f"https://{host}/", status=200, title=title, server=server,
                               missing_security_headers=missing)),
    ]


def _org_snapshots(domain: str, ip: str, profile: str) -> list[list[Service]]:
    """Sequência de estados da superfície ao longo do tempo (para tendência)."""
    base = _web(f"www.{domain}", ip) + _web(f"api.{domain}", ip)
    legacy = _web(f"old.{domain}", ip, headers=False, server="Apache/2.4.41")
    if profile == "good":
        return [base + legacy + [_service(f"ftp.{domain}", ip, 21)], base + legacy, base]
    if profile == "medium":
        portal = _web(f"portal.{domain}", ip, days=12, headers=False, server="Apache/2.4.41")
        rdp = [_service(f"vpn.{domain}", ip, 3389)]
        return [base + portal + rdp + [_service(f"db.{domain}", ip, 3306)],
                base + portal + rdp, base + portal, base + _web(f"portal.{domain}", ip, headers=False)]
    bad = base + _web(f"admin.{domain}", ip, self_signed=True, title="Jenkins",
                      tls_proto="TLSv1", headers=False) \
        + [_service(f"cache.{domain}", ip, 6379), _service(f"files.{domain}", ip, 21,
                                                          banner="220 ProFTPD 1.3.5 Server")]
    return [base, bad, bad + [_service(f"search.{domain}", ip, 9200)]]


def _record(db: Database, *, org_id=None, watch_id=None, mode: str, services: list[Service]) -> None:
    snap = Snapshot(started_at=now(), finished_at=now(),
                    hosts={s.host: [s.ip] for s in services},
                    services=services, findings=evaluate(services))
    sid = db.execute("INSERT INTO scans (org_id, watch_id, mode, status, trigger, queued_at,"
                     " started_at) VALUES (?, ?, ?, 'running', 'manual', ?, ?)",
                     (org_id, watch_id, mode, now(), now()))
    row = db.one("SELECT * FROM scans WHERE id = ?", (sid,))
    finalize(db, row, snap, EngineSettings(send_alerts=False))


def seed(db: Database) -> dict:
    if db.one("SELECT 1 FROM users WHERE email = 'admin@demo.example'"):
        raise ValueError("dados de demonstração já existem")
    auth.create_user(db, "admin@demo.example", DEMO_PASSWORD, "admin", name="Admin da plataforma")

    pid = db.execute(
        "INSERT INTO partners (name, website, status, referral_code, brand_name, brand_color,"
        " support_email, created_at, approved_at) VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?)",
        ("Aurora Cyber Consultoria", "https://aurora.example", partners.new_referral_code(),
         "Aurora Cyber", "#7048e8", "soc@aurora.example", now(), now()))
    auth.create_user(db, "parceiro@demo.example", DEMO_PASSWORD, "partner_admin",
                     name="Gestora Aurora", partner_id=pid)
    auth.create_user(db, "analista@demo.example", DEMO_PASSWORD, "partner_analyst",
                     name="Analista Aurora", partner_id=pid)
    db.execute("INSERT INTO partners (name, website, referral_code, created_at)"
               " VALUES (?, ?, ?, ?)", ("Nova Sec Ltda", "https://novasec.example",
                                         partners.new_referral_code(), now()))

    clients = [("Banco Horizonte", "horizonte.example", "198.51.100.10", "enterprise", "medium"),
               ("Varejo Estrela", "estrela.example", "198.51.100.20", "professional", "bad"),
               ("Clínica Vida", "vida.example", "198.51.100.30", "essentials", "good")]
    for name, domain, ip, plan, profile in clients:
        oid = db.execute("INSERT INTO organizations (name, partner_id, plan, created_at)"
                         " VALUES (?, ?, ?, ?)", (name, pid, plan, now()))
        db.execute("INSERT INTO assets (org_id, kind, value, verification_token, verified_at,"
                   " verified_method, created_at) VALUES (?, 'domain', ?, ?, ?, 'dns', ?)",
                   (oid, domain, secrets.token_hex(16), now(), now()))
        for services in _org_snapshots(domain, ip, profile):
            _record(db, org_id=oid, mode="active", services=services)
        if profile == "medium":
            auth.create_user(db, "cliente@demo.example", DEMO_PASSWORD, "org_admin",
                             name="CISO Horizonte", org_id=oid)
            wid = db.execute("INSERT INTO watchlist (org_id, kind, name, domain, criticality,"
                             " created_at) VALUES (?, 'vendor', ?, ?, 'high', ?)",
                             (oid, "Processadora de Pagamentos", "pagamentos.example", now()))
            _record(db, watch_id=wid, mode="passive",
                    services=_web("pagamentos.example", "203.0.113.5", days=-3, headers=False))

    # Cliente direto indicado pelo parceiro (comissão recorrente).
    db.execute("INSERT INTO organizations (name, referred_by, plan, created_at) VALUES (?, ?, ?, ?)",
               ("Logística Rota", pid, "professional", now()))
    wid = db.execute("INSERT INTO watchlist (partner_id, kind, name, domain, created_at)"
                     " VALUES (?, 'prospect', ?, ?, ?)", (pid, "Indústria Prospect", "prospect.example",
                                                          now()))
    _record(db, watch_id=wid, mode="passive",
            services=_web("prospect.example", "203.0.113.9", self_signed=True, tls_proto="TLSv1.1",
                          server="Microsoft-IIS/8.5", headers=False))
    return {"password": DEMO_PASSWORD,
            "users": ["admin@demo.example", "parceiro@demo.example", "analista@demo.example",
                      "cliente@demo.example"]}
