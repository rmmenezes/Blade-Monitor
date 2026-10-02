"""Carregamento e validação da configuração (TOML)."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389, 5000, 5432, 5601,
    5900, 5985, 6379, 6443, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 9300,
    11211, 27017,
]


@dataclass
class Config:
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    subdomain_discovery: bool = True
    timeout: float = 3.0
    workers: int = 50
    cert_expiry_warning_days: int = 30
    database: str = "blade_monitor.db"
    report_dir: str = "reports"
    webhook_url: str | None = None
    min_alert_severity: str = "medium"


def load_config(path: str | Path) -> Config:
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)

    targets = raw.get("targets", {})
    scan = raw.get("scan", {})
    storage = raw.get("storage", {})
    alerts = raw.get("alerts", {})

    cfg = Config(
        domains=[d.strip().lower().rstrip(".") for d in targets.get("domains", [])],
        ips=[i.strip() for i in targets.get("ips", [])],
        exclude=[e.strip().lower() for e in targets.get("exclude", [])],
        subdomain_discovery=scan.get("subdomain_discovery", True),
        timeout=float(scan.get("timeout", 3.0)),
        workers=int(scan.get("workers", 50)),
        cert_expiry_warning_days=int(scan.get("cert_expiry_warning_days", 30)),
        database=storage.get("database", "blade_monitor.db"),
        report_dir=storage.get("report_dir", "reports"),
        webhook_url=alerts.get("webhook_url") or None,
        min_alert_severity=alerts.get("min_severity", "medium"),
    )
    if "ports" in scan:
        cfg.ports = sorted({int(p) for p in scan["ports"]})

    if not cfg.domains and not cfg.ips:
        raise ValueError("Configuração sem alvos: defina targets.domains e/ou targets.ips")
    for p in cfg.ports:
        if not 0 < p < 65536:
            raise ValueError(f"Porta inválida: {p}")
    return cfg
