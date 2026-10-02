"""Execução de varreduras na plataforma e ciclo de vida dos achados."""
from __future__ import annotations

import ipaddress
import json
import logging
from dataclasses import asdict, dataclass, field

from ..config import DEFAULT_PORTS
from ..diff import compare
from ..discovery import discover
from ..models import Finding, Snapshot
from ..report import alert_text, send_webhook
from ..rules import evaluate
from ..scanner import scan
from . import scoring
from .db import Database, now

log = logging.getLogger(__name__)

# Modo passivo (fornecedores/prospects sem autorização de teste): só o que um
# navegador comum veria — CT logs, DNS e uma requisição HTTP(S) por host.
PASSIVE_PORTS = [80, 443]
PASSIVE_MAX_HOSTS = 200
SUPPRESSED = ("accepted", "false_positive")


@dataclass
class EngineSettings:
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    timeout: float = 3.0
    workers: int = 50
    cert_warning_days: int = 30
    ct_discovery: bool = True
    send_alerts: bool = True
    allow_private: bool = False   # só laboratório: permite varrer IPs internos


def public_hosts(hosts: dict[str, list[str]]) -> dict[str, list[str]]:
    """Descarta IPs internos/reservados.

    Um domínio verificado pode ter subdomínios que resolvem para a rede
    interna (10.x, 127.x, 169.254.x...). Sem este filtro o worker varreria
    a infraestrutura da própria plataforma (SSRF).
    """
    out = {}
    for host, ips in hosts.items():
        keep = [ip for ip in ips if ipaddress.ip_address(ip).is_global]
        if keep:
            out[host] = keep
    return out


class ScanError(Exception):
    pass


def _org_targets(db: Database, org_id: int) -> tuple[list[str], list[str]]:
    rows = db.all("SELECT kind, value FROM assets WHERE org_id = ? AND verified_at IS NOT NULL",
                  (org_id,))
    domains = [r["value"] for r in rows if r["kind"] == "domain"]
    ips = [r["value"] for r in rows if r["kind"] in ("ip", "cidr")]
    if not domains and not ips:
        raise ScanError("nenhum ativo verificado — verifique a posse antes de varrer")
    return domains, ips


def _sync_issues(db: Database, org_id: int, findings: list[Finding], seen_at: str) -> set[str]:
    """Atualiza o ciclo de vida dos achados; retorna as chaves suprimidas."""
    current = {f.key: f for f in findings}
    with db.connect() as conn:
        existing = {r["key"]: dict(r) for r in conn.execute(
            "SELECT id, key, status FROM issues WHERE org_id = ?", (org_id,))}
        for key, f in current.items():
            row = existing.get(key)
            if row is None:
                conn.execute(
                    "INSERT INTO issues (org_id, key, rule, severity, category, asset, title,"
                    " detail, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (org_id, key, f.rule, f.severity, scoring.category_of(f.rule), f.asset,
                     f.title, f.detail, seen_at, seen_at))
                continue
            reopen = row["status"] == "resolved"
            conn.execute(
                "UPDATE issues SET severity = ?, title = ?, detail = ?, last_seen = ?"
                + (", status = 'open', resolved_at = NULL" if reopen else "")
                + " WHERE id = ?", (f.severity, f.title, f.detail, seen_at, row["id"]))
        for key, row in existing.items():
            if key not in current and row["status"] == "open":
                conn.execute("UPDATE issues SET status = 'resolved', resolved_at = ? WHERE id = ?",
                             (seen_at, row["id"]))
    return {k for k, r in existing.items() if r["status"] in SUPPRESSED}


def _previous_snapshot(db: Database, scan_row: dict) -> Snapshot | None:
    col, ref = ("org_id", scan_row["org_id"]) if scan_row["org_id"] else (
        "watch_id", scan_row["watch_id"])
    prev = db.one(f"SELECT data FROM scans WHERE {col} = ? AND mode = ? AND status = 'done'"
                  " AND id < ? ORDER BY id DESC LIMIT 1", (ref, scan_row["mode"], scan_row["id"]))
    return Snapshot.from_dict(json.loads(prev["data"])) if prev else None


def run(db: Database, scan_id: int, settings: EngineSettings | None = None) -> dict:
    """Executa uma varredura enfileirada e persiste resultado, nota e achados."""
    settings = settings or EngineSettings()
    row = db.one("SELECT * FROM scans WHERE id = ?", (scan_id,))
    if row is None:
        raise ScanError(f"varredura {scan_id} não existe")
    db.execute("UPDATE scans SET status = 'running', started_at = ?, error = '' WHERE id = ?",
               (now(), scan_id))
    try:
        result = _execute(db, row, settings)
    except Exception as exc:  # noqa: BLE001 - erro fica registrado na varredura
        log.exception("Varredura %s falhou", scan_id)
        db.execute("UPDATE scans SET status = 'failed', finished_at = ?, error = ? WHERE id = ?",
                   (now(), str(exc)[:500], scan_id))
        raise
    return result


def _execute(db: Database, row: dict, settings: EngineSettings) -> dict:
    snap = Snapshot(started_at=now())
    org = db.one("SELECT * FROM organizations WHERE id = ?", (row["org_id"],)) if row["org_id"] else None

    if row["mode"] == "active":
        if org is None:
            raise ScanError("varredura ativa exige organização")
        domains, ips = _org_targets(db, org["id"])
        exclude = [e.strip().lower() for e in org["exclude"].splitlines() if e.strip()]
        snap.hosts = discover(domains, ips, exclude, use_ct=settings.ct_discovery,
                              workers=settings.workers)
        ports = settings.ports
    else:
        watch = db.one("SELECT * FROM watchlist WHERE id = ?", (row["watch_id"],))
        if watch is None:
            raise ScanError("alvo passivo removido")
        hosts = discover([watch["domain"]], [], [], use_ct=settings.ct_discovery,
                         workers=settings.workers)
        snap.hosts = dict(sorted(hosts.items())[:PASSIVE_MAX_HOSTS])
        ports = PASSIVE_PORTS

    if not settings.allow_private:
        snap.hosts = public_hosts(snap.hosts)
    snap.services = scan(snap.hosts, ports, settings.timeout, settings.workers)
    snap.findings = evaluate(snap.services, settings.cert_warning_days)
    snap.finished_at = now()
    return finalize(db, row, snap, settings)


def finalize(db: Database, row: dict, snap: Snapshot, settings: EngineSettings) -> dict:
    """Persiste um snapshot concluído: achados, nota, diff e alerta."""
    org = db.one("SELECT * FROM organizations WHERE id = ?", (row["org_id"],)) if row["org_id"] else None
    scored = snap.findings
    if row["mode"] == "active":
        suppressed = _sync_issues(db, org["id"], snap.findings, snap.finished_at)
        scored = [f for f in snap.findings if f.key not in suppressed]
    rating = scoring.compute(scored, len(snap.hosts))

    changes = compare(_previous_snapshot(db, row), snap)
    db.execute(
        "UPDATE scans SET status = 'done', finished_at = ?, score = ?, grade = ?, categories = ?,"
        " hosts = ?, services = ?, findings = ?, changes = ?, data = ? WHERE id = ?",
        (snap.finished_at, rating["score"], rating["grade"], json.dumps(rating["categories"]),
         len(snap.hosts), len(snap.services), len(snap.findings),
         json.dumps(asdict(changes)), json.dumps(snap.to_dict()), row["id"]))

    if org and row["mode"] == "active" and settings.send_alerts and org["webhook_url"]:
        text = alert_text(changes, org["alert_min_severity"])
        if text:
            send_webhook(org["webhook_url"],
                         f"[{org['name']}] nota {rating['grade']} ({rating['score']})\n{text}")
    log.info("Varredura %s concluída: nota %s (%s)", row["id"], rating["grade"], rating["score"])
    return rating
