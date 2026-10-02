"""Relatório executivo em HTML (imprimível em PDF), com a marca do parceiro."""
from __future__ import annotations

import json
import re
from html import escape

from ..models import SEVERITY_ORDER

_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
SEV_LABEL = {"critical": "Crítica", "high": "Alta", "medium": "Média", "low": "Baixa",
             "info": "Info"}
GRADE_COLOR = {"A": "#2b8a3e", "B": "#5c940d", "C": "#e67700", "D": "#d9480f", "F": "#c92a2a"}


def branding(partner: dict | None, white_label_allowed: bool) -> dict:
    if not partner:
        return {"name": "Blade Monitor", "color": "#2f6fed", "logo": "", "email": "",
                "powered_by": False}
    color = partner["brand_color"] if _COLOR_RE.match(partner["brand_color"] or "") else "#2f6fed"
    logo = partner["logo_url"] if (partner["logo_url"] or "").startswith("https://") else ""
    return {"name": partner["brand_name"] or partner["name"], "color": color, "logo": logo,
            "email": partner["support_email"],
            "powered_by": not (partner["white_label"] and white_label_allowed)}


def render(subject: str, scan: dict, issues: list[dict], brand: dict,
           history: list[dict] | None = None) -> str:
    cats = json.loads(scan["categories"] or "{}")
    issues = sorted(issues, key=lambda i: (-SEVERITY_ORDER[i["severity"]], i["asset"]))
    counts = {s: sum(1 for i in issues if i["severity"] == s) for s in SEVERITY_ORDER}
    g = scan["grade"] or "?"
    e = escape

    cat_rows = "".join(
        f"<tr><td>{e(c['label'])}</td><td><b style='color:{GRADE_COLOR.get(c['grade'], '#555')}'>"
        f"{e(c['grade'])}</b> {c['score']}</td><td>{c['findings']}</td></tr>" for c in cats.values())
    issue_rows = "".join(
        f"<tr><td><span class='sev {e(i['severity'])}'>{SEV_LABEL[i['severity']]}</span></td>"
        f"<td><code>{e(i['asset'])}</code></td><td>{e(i['title'])}"
        f"<div class='muted'>{e(i['detail'][:200])}</div></td></tr>" for i in issues[:200])
    trend = ""
    if history and len(history) > 1:
        trend = "<p class='muted'>Evolução da nota: " + " → ".join(
            f"{e(h['grade'])} ({h['score']})" for h in history[-8:]) + "</p>"
    logo = f"<img src='{e(brand['logo'])}' alt='' style='height:36px'>" if brand["logo"] else ""
    footer = "Relatório gerado com Blade Monitor." if brand["powered_by"] else ""
    contact = f" Contato: {e(brand['email'])}." if brand["email"] else ""

    return f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Relatório de exposição — {e(subject)}</title>
<style>
:root{{--brand:{brand['color']};--text:#16181d;--muted:#5d6472;--border:#e2e5eb}}
body{{margin:0;font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--text);background:#fff}}
.wrap{{max-width:920px;margin:0 auto;padding:24px 16px}}
header{{display:flex;align-items:center;justify-content:space-between;gap:12px;border-bottom:3px solid var(--brand);padding-bottom:12px}}
header .org{{font-weight:700;font-size:18px;color:var(--brand)}}
h1{{font-size:26px;margin:24px 0 4px}}h2{{font-size:19px;margin:28px 0 8px}}
.muted{{color:var(--muted);font-size:13px}}
.hero{{display:flex;gap:24px;align-items:center;flex-wrap:wrap;margin:16px 0}}
.grade{{width:110px;height:110px;border-radius:16px;display:grid;place-items:center;color:#fff;font-size:56px;font-weight:800;background:{GRADE_COLOR.get(g, '#555')}}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;flex:1}}
.kpi{{border:1px solid var(--border);border-radius:10px;padding:10px}}.kpi b{{display:block;font-size:22px}}
table{{border-collapse:collapse;width:100%;font-size:14px}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}}
th{{font-size:12px;text-transform:uppercase;color:var(--muted)}}
code{{font-size:13px;word-break:break-all}}
.sev{{font-weight:600;white-space:nowrap}}
.critical{{color:#c92a2a}}.high{{color:#d9480f}}.medium{{color:#b08800}}.low{{color:#1c7ed6}}.info{{color:#868e96}}
footer{{margin-top:32px;border-top:1px solid var(--border);padding-top:10px}}
@media print{{.wrap{{padding:0}}a{{color:inherit}}}}
</style></head><body><div class="wrap">
<header><div class="org">{e(brand['name'])}</div>{logo}</header>
<h1>Relatório de exposição externa</h1>
<div class="muted">{e(subject)} · varredura #{scan['id']} ({e(scan['mode'])}) · {e(scan['finished_at'] or '')}</div>
<div class="hero"><div class="grade">{e(g)}</div><div class="kpis">
<div class="kpi"><b>{scan['score']}</b><span class="muted">nota (0–100)</span></div>
<div class="kpi"><b>{scan['hosts']}</b><span class="muted">hosts</span></div>
<div class="kpi"><b>{scan['services']}</b><span class="muted">serviços expostos</span></div>
<div class="kpi"><b class="critical">{counts['critical']}</b><span class="muted">críticos</span></div>
<div class="kpi"><b class="high">{counts['high']}</b><span class="muted">altos</span></div>
</div></div>
{trend}
<h2>Notas por categoria</h2>
<table><thead><tr><th>Categoria</th><th>Nota</th><th>Achados</th></tr></thead><tbody>{cat_rows}</tbody></table>
<h2>Achados priorizados</h2>
<table><thead><tr><th>Severidade</th><th>Ativo</th><th>Achado</th></tr></thead>
<tbody>{issue_rows or "<tr><td colspan=3>Nenhum achado aberto.</td></tr>"}</tbody></table>
<footer class="muted">{footer}{contact}</footer>
</div></body></html>"""
