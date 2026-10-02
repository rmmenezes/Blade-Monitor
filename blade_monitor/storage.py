"""Persistência de snapshots em SQLite para acompanhar a evolução da superfície."""
from __future__ import annotations

import json
import sqlite3

from .models import Snapshot

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    hosts INTEGER NOT NULL,
    services INTEGER NOT NULL,
    findings INTEGER NOT NULL,
    data TEXT NOT NULL
);
"""


class Storage:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)
        self.conn.executescript(SCHEMA)

    def save(self, snap: Snapshot) -> int:
        cur = self.conn.execute(
            "INSERT INTO snapshots (started_at, finished_at, hosts, services, findings, data)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (snap.started_at, snap.finished_at, len(snap.hosts), len(snap.services),
             len(snap.findings), json.dumps(snap.to_dict())),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def latest(self, before_id: int | None = None) -> tuple[int, Snapshot] | None:
        if before_id is None:
            row = self.conn.execute(
                "SELECT id, data FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()
        else:
            row = self.conn.execute(
                "SELECT id, data FROM snapshots WHERE id < ? ORDER BY id DESC LIMIT 1",
                (before_id,)).fetchone()
        return (row[0], Snapshot.from_dict(json.loads(row[1]))) if row else None

    def get(self, snap_id: int) -> Snapshot | None:
        row = self.conn.execute("SELECT data FROM snapshots WHERE id = ?", (snap_id,)).fetchone()
        return Snapshot.from_dict(json.loads(row[0])) if row else None

    def history(self, limit: int = 20) -> list[tuple]:
        return self.conn.execute(
            "SELECT id, started_at, hosts, services, findings FROM snapshots"
            " ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def close(self) -> None:
        self.conn.close()
