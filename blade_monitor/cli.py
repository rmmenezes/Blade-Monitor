"""Interface de linha de comando do Blade Monitor."""
from __future__ import annotations

import argparse
import logging
import sys
import time
from datetime import datetime, timezone

from . import __version__
from .config import load_config
from .diff import compare
from .discovery import discover
from .models import SEVERITY_ORDER, Snapshot
from .report import alert_text, render_markdown, send_webhook, write_reports
from .rules import evaluate
from .scanner import scan
from .storage import Storage

log = logging.getLogger("blade_monitor")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run_scan(config_path: str, no_alert: bool = False) -> int:
    cfg = load_config(config_path)
    snap = Snapshot(started_at=_now())

    log.info("Descobrindo ativos...")
    snap.hosts = discover(cfg.domains, cfg.ips, cfg.exclude,
                          use_ct=cfg.subdomain_discovery, workers=cfg.workers)
    log.info("%d hosts ativos", len(snap.hosts))

    snap.services = scan(snap.hosts, cfg.ports, cfg.timeout, cfg.workers)
    log.info("%d serviços expostos", len(snap.services))

    snap.findings = evaluate(snap.services, cfg.cert_expiry_warning_days)
    snap.finished_at = _now()

    store = Storage(cfg.database)
    try:
        previous = store.latest()
        snap_id = store.save(snap)
    finally:
        store.close()

    changes = compare(previous[1] if previous else None, snap)
    report = write_reports(snap, changes, snap_id, cfg.report_dir)
    print(f"Snapshot #{snap_id}: {len(snap.hosts)} hosts, {len(snap.services)} serviços, "
          f"{len(snap.findings)} achados. Relatório: {report}")

    text = alert_text(changes, cfg.min_alert_severity)
    if text:
        print("\n" + text)
        if cfg.webhook_url and not no_alert:
            send_webhook(cfg.webhook_url, text)

    worst = max((SEVERITY_ORDER[f.severity] for f in snap.findings), default=0)
    return 2 if worst >= SEVERITY_ORDER["high"] else 0


def cmd_history(config_path: str, limit: int) -> int:
    store = Storage(load_config(config_path).database)
    rows = store.history(limit)
    store.close()
    print(f"{'ID':>4}  {'Início':<26} {'Hosts':>6} {'Serviços':>9} {'Achados':>8}")
    for r in rows:
        print(f"{r[0]:>4}  {r[1]:<26} {r[2]:>6} {r[3]:>9} {r[4]:>8}")
    return 0


def cmd_show(config_path: str, snap_id: int | None) -> int:
    store = Storage(load_config(config_path).database)
    try:
        if snap_id is None:
            latest = store.latest()
            if not latest:
                print("Nenhum snapshot encontrado.")
                return 1
            snap_id, snap = latest
        else:
            snap = store.get(snap_id)
            if snap is None:
                print(f"Snapshot #{snap_id} não encontrado.")
                return 1
        prev = store.latest(before_id=snap_id)
    finally:
        store.close()
    print(render_markdown(snap, compare(prev[1] if prev else None, snap), snap_id))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="blade-monitor",
                                     description="Monitor de exposição externa (EASM)")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("-c", "--config", default="config.toml")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="executa descoberta + varredura")
    p_scan.add_argument("--no-alert", action="store_true", help="não envia webhook")
    p_scan.add_argument("--interval", type=int, default=0,
                        help="repete a cada N minutos (modo daemon)")
    p_hist = sub.add_parser("history", help="lista snapshots anteriores")
    p_hist.add_argument("-n", type=int, default=20)
    p_show = sub.add_parser("show", help="mostra relatório de um snapshot")
    p_show.add_argument("id", type=int, nargs="?")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if args.cmd == "scan":
        if args.interval <= 0:
            return run_scan(args.config, args.no_alert)
        while True:
            try:
                run_scan(args.config, args.no_alert)
            except Exception:  # noqa: BLE001 - daemon não deve morrer
                log.exception("Falha na varredura")
            log.info("Próxima varredura em %d min", args.interval)
            time.sleep(args.interval * 60)
    if args.cmd == "history":
        return cmd_history(args.config, args.n)
    return cmd_show(args.config, args.id)


if __name__ == "__main__":
    sys.exit(main())
