"""Relatórios (JSON + Markdown) e alertas via webhook."""
from __future__ import annotations

import json
import logging
import urllib.request
from pathlib import Path

from .diff import Changes
from .models import SEVERITY_ORDER, Finding, Snapshot

log = logging.getLogger(__name__)

ICONS = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}


def _sev_sort(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.asset))


def render_markdown(snap: Snapshot, changes: Changes, snap_id: int) -> str:
    lines = [f"# Blade Monitor — relatório de exposição externa (#{snap_id})", "",
             f"- Início: {snap.started_at}", f"- Fim: {snap.finished_at}",
             f"- Hosts ativos: {len(snap.hosts)}", f"- Serviços expostos: {len(snap.services)}",
             f"- Achados: {len(snap.findings)}", ""]

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in snap.findings:
        counts[f.severity] += 1
    lines += ["| Severidade | Qtde |", "|---|---|"]
    lines += [f"| {ICONS[s]} {s} | {counts[s]} |" for s in reversed(list(SEVERITY_ORDER))]
    lines.append("")

    lines += ["## Mudanças desde a última execução", ""]
    if changes.empty:
        lines.append("Nenhuma mudança.")
    for label, items in (("Novos hosts", changes.new_hosts),
                         ("Hosts removidos", changes.removed_hosts),
                         ("Novos serviços", changes.new_services),
                         ("Serviços fechados", changes.closed_services)):
        if items:
            lines += [f"**{label}:** " + ", ".join(f"`{i}`" for i in items), ""]
    if changes.new_findings:
        lines += ["**Novos achados:**", ""]
        lines += [f"- {ICONS[f.severity]} `{f.asset}` — {f.title}" for f in _sev_sort(changes.new_findings)]
        lines.append("")
    if changes.resolved_findings:
        lines += ["**Achados resolvidos:**", ""]
        lines += [f"- ✅ `{f.asset}` — {f.title}" for f in changes.resolved_findings]
        lines.append("")

    lines += ["## Achados", "", "| Sev. | Ativo | Achado | Detalhe |", "|---|---|---|---|"]
    for f in _sev_sort(snap.findings):
        detail = f.detail.replace("|", "\\|")[:150]
        lines.append(f"| {ICONS[f.severity]} {f.severity} | `{f.asset}` | {f.title} | {detail} |")

    lines += ["", "## Inventário de serviços", "",
              "| Host | IP | Porta | TLS | HTTP | Banner |", "|---|---|---|---|---|---|"]
    for s in snap.services:
        tls = f"{s.tls.protocol} ({s.tls.days_left}d)" if s.tls and s.tls.days_left is not None else (
            s.tls.protocol if s.tls else "")
        web = f"{s.http.status} {s.http.title}".strip() if s.http and s.http.status else ""
        banner = s.banner.replace("|", "\\|")
        lines.append(f"| {s.host} | {s.ip} | {s.port} | {tls} | {web} | {banner} |")
    return "\n".join(lines) + "\n"


def write_reports(snap: Snapshot, changes: Changes, snap_id: int, report_dir: str) -> Path:
    out = Path(report_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = snap.started_at.replace(":", "").replace("-", "")[:15]
    base = out / f"snapshot-{snap_id}-{stamp}"
    base.with_suffix(".json").write_text(json.dumps(snap.to_dict(), indent=2, ensure_ascii=False))
    md = base.with_suffix(".md")
    md.write_text(render_markdown(snap, changes, snap_id), encoding="utf-8")
    return md


def alert_text(changes: Changes, min_severity: str) -> str | None:
    """Monta a mensagem de alerta; None se não há nada relevante."""
    threshold = SEVERITY_ORDER[min_severity]
    relevant = [f for f in changes.new_findings if SEVERITY_ORDER[f.severity] >= threshold]
    if not (relevant or changes.new_hosts or changes.new_services):
        return None
    parts = ["*Blade Monitor — mudanças na exposição externa*"]
    if changes.new_hosts:
        parts.append("Novos hosts: " + ", ".join(changes.new_hosts[:20]))
    if changes.new_services:
        parts.append("Novos serviços: " + ", ".join(changes.new_services[:20]))
    for f in _sev_sort(relevant)[:25]:
        parts.append(f"{ICONS[f.severity]} [{f.severity}] {f.asset} — {f.title}")
    return "\n".join(parts)


def send_webhook(url: str, text: str, timeout: float = 10.0) -> bool:
    """Envia payload compatível com Slack/Mattermost/Teams ({"text": ...})."""
    data = json.dumps({"text": text}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:  # noqa: BLE001
        log.error("Falha ao enviar webhook: %s", exc)
        return False
