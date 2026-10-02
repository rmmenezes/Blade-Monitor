"""Fila de varreduras e agendamento conforme o plano de cada cliente."""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone

from . import engine
from .db import Database, now
from .partners import PLANS

log = logging.getLogger(__name__)

WATCHLIST_RESCAN_HOURS = 168


def enqueue(db: Database, *, mode: str, org_id: int | None = None, watch_id: int | None = None,
            trigger: str = "manual", user_id: int | None = None) -> int:
    """Enfileira uma varredura; reaproveita a que já estiver pendente para o mesmo alvo."""
    col, ref = ("org_id", org_id) if org_id is not None and watch_id is None else ("watch_id", watch_id)
    pending = db.one(f"SELECT id FROM scans WHERE {col} = ? AND mode = ?"
                     " AND status IN ('queued', 'running')", (ref, mode))
    if pending:
        return pending["id"]
    return db.execute(
        "INSERT INTO scans (org_id, watch_id, mode, trigger, requested_by, queued_at)"
        " VALUES (?, ?, ?, ?, ?, ?)", (org_id, watch_id, mode, trigger, user_id, now()))


def claim_next(db: Database) -> int | None:
    with db.connect() as conn:
        row = conn.execute(
            "UPDATE scans SET status = 'running', started_at = ? WHERE id = ("
            " SELECT id FROM scans WHERE status = 'queued' ORDER BY id LIMIT 1)"
            " AND status = 'queued' RETURNING id", (now(),)).fetchone()
    return row["id"] if row else None


def _older_than(ts: str | None, hours: int) -> bool:
    if not ts:
        return True
    return datetime.fromisoformat(ts) < datetime.now(timezone.utc) - timedelta(hours=hours)


def schedule_due(db: Database) -> list[int]:
    """Enfileira varreduras vencidas: clientes (ativa) e watchlist (passiva)."""
    queued = []
    orgs = db.all(
        "SELECT o.id, o.plan, (SELECT MAX(queued_at) FROM scans s WHERE s.org_id = o.id"
        " AND s.mode = 'active') AS last FROM organizations o WHERE o.status = 'active'"
        " AND EXISTS (SELECT 1 FROM assets a WHERE a.org_id = o.id AND a.verified_at IS NOT NULL)")
    for org in orgs:
        if _older_than(org["last"], PLANS[org["plan"]]["scan_every_hours"]):
            queued.append(enqueue(db, mode="active", org_id=org["id"], trigger="schedule"))
    for w in db.all("SELECT w.id, (SELECT MAX(queued_at) FROM scans s WHERE s.watch_id = w.id)"
                    " AS last FROM watchlist w"):
        if _older_than(w["last"], WATCHLIST_RESCAN_HOURS):
            queued.append(enqueue(db, mode="passive", watch_id=w["id"], trigger="schedule"))
    return queued


class Worker:
    """Executa a fila em segundo plano (thread) ou passo a passo (run_once)."""

    def __init__(self, db: Database, settings: engine.EngineSettings | None = None,
                 poll_seconds: float = 5.0, schedule: bool = True):
        self.db = db
        self.settings = settings or engine.EngineSettings()
        self.poll = poll_seconds
        self.schedule = schedule
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # Varreduras interrompidas por queda do processo não ficam presas.
        db.execute("UPDATE scans SET status = 'failed', error = 'interrompida', finished_at = ?"
                   " WHERE status = 'running'", (now(),))

    def run_once(self) -> int | None:
        if self.schedule:
            schedule_due(self.db)
        scan_id = claim_next(self.db)
        if scan_id is not None:
            try:
                engine.run(self.db, scan_id, self.settings)
            except Exception:  # noqa: BLE001 - já registrado na varredura
                pass
        return scan_id

    def loop(self) -> None:
        log.info("Worker iniciado")
        while not self._stop.is_set():
            try:
                busy = self.run_once() is not None
            except Exception:  # noqa: BLE001 - worker não deve morrer
                log.exception("Falha no worker")
                busy = False
            if not busy:
                self._stop.wait(self.poll)

    def start(self) -> "Worker":
        self._thread = threading.Thread(target=self.loop, name="blade-worker", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
