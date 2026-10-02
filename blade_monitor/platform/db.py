"""Esquema SQLite multi-tenant e utilitários de acesso."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator

SCHEMA = """
PRAGMA foreign_keys = ON;

-- Consultorias / MSSPs do programa de parceiros.
CREATE TABLE IF NOT EXISTS partners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    website TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',          -- pending | active | suspended
    referral_code TEXT NOT NULL UNIQUE,
    brand_name TEXT NOT NULL DEFAULT '',
    brand_color TEXT NOT NULL DEFAULT '#2f6fed',
    logo_url TEXT NOT NULL DEFAULT '',
    support_email TEXT NOT NULL DEFAULT '',
    white_label INTEGER NOT NULL DEFAULT 0,          -- oculta a marca Blade nos relatórios
    tier_override TEXT,                              -- nível negociado manualmente
    created_at TEXT NOT NULL,
    approved_at TEXT
);

-- Clientes finais (gerenciados por um parceiro ou diretos).
CREATE TABLE IF NOT EXISTS organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    partner_id INTEGER REFERENCES partners(id),      -- parceiro que revende/gerencia
    referred_by INTEGER REFERENCES partners(id),     -- parceiro que indicou (cliente direto)
    plan TEXT NOT NULL DEFAULT 'essentials',
    status TEXT NOT NULL DEFAULT 'active',           -- active | suspended
    exclude TEXT NOT NULL DEFAULT '',                -- padrões glob, um por linha
    webhook_url TEXT NOT NULL DEFAULT '',
    alert_min_severity TEXT NOT NULL DEFAULT 'medium',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,          -- admin | partner_admin | partner_analyst | org_admin | org_viewer
    partner_id INTEGER REFERENCES partners(id),
    org_id INTEGER REFERENCES organizations(id),
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_login TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    last_used TEXT
);

-- Ativos-raiz declarados pelo cliente. Varredura ativa só após verificação.
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,                              -- domain | ip | cidr
    value TEXT NOT NULL,
    verification_token TEXT NOT NULL,
    verified_at TEXT,
    verified_method TEXT,                            -- dns | http | attestation
    verified_by INTEGER REFERENCES users(id),
    attestation_note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE (org_id, kind, value)
);

-- Terceiros monitorados passivamente: fornecedores (TPRM) e prospects (pré-venda).
CREATE TABLE IF NOT EXISTS watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    partner_id INTEGER REFERENCES partners(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,                              -- vendor | prospect
    name TEXT NOT NULL,
    domain TEXT NOT NULL,
    criticality TEXT NOT NULL DEFAULT 'medium',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    watch_id INTEGER REFERENCES watchlist(id) ON DELETE CASCADE,
    mode TEXT NOT NULL,                              -- active | passive
    status TEXT NOT NULL DEFAULT 'queued',           -- queued | running | done | failed
    trigger TEXT NOT NULL DEFAULT 'manual',          -- manual | schedule | api
    requested_by INTEGER REFERENCES users(id),
    queued_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    error TEXT NOT NULL DEFAULT '',
    score INTEGER,
    grade TEXT,
    categories TEXT,                                 -- JSON {categoria: nota}
    hosts INTEGER,
    services INTEGER,
    findings INTEGER,
    changes TEXT,                                    -- JSON (diff com a varredura anterior)
    data TEXT                                        -- JSON do Snapshot
);
CREATE INDEX IF NOT EXISTS scans_org ON scans(org_id, id);
CREATE INDEX IF NOT EXISTS scans_watch ON scans(watch_id, id);
CREATE INDEX IF NOT EXISTS scans_status ON scans(status);

-- Achados com ciclo de vida entre varreduras.
CREATE TABLE IF NOT EXISTS issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    asset TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',             -- open | resolved | accepted | false_positive
    note TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    resolved_at TEXT,
    UNIQUE (org_id, key)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    user_id INTEGER,
    partner_id INTEGER,
    org_id INTEGER,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    """Abre uma conexão por operação — seguro para o servidor multi-thread."""

    def __init__(self, path: str):
        self.path = path
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            conn.execute("PRAGMA journal_mode = WAL")

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    # Atalhos -----------------------------------------------------------------
    def one(self, sql: str, args: tuple = ()) -> dict | None:
        with self.connect() as conn:
            row = conn.execute(sql, args).fetchone()
        return dict(row) if row else None

    def all(self, sql: str, args: tuple = ()) -> list[dict]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute(sql, args).fetchall()]

    def execute(self, sql: str, args: tuple = ()) -> int:
        """Executa e retorna lastrowid (INSERT) ou rowcount (UPDATE/DELETE)."""
        with self.connect() as conn:
            cur = conn.execute(sql, args)
            return int(cur.lastrowid) if sql.lstrip().upper().startswith("INSERT") else cur.rowcount

    def audit(self, action: str, detail: str = "", user: dict | None = None,
              org_id: int | None = None, partner_id: int | None = None) -> None:
        self.execute(
            "INSERT INTO audit_log (at, user_id, partner_id, org_id, action, detail)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (now(), user["id"] if user else None,
             partner_id if partner_id is not None else (user or {}).get("partner_id"),
             org_id, action, detail[:1000]))
