"""Programa de parceiros: planos, níveis, benefícios e extrato mensal.

Dois modelos de receita para consultorias:
  * Revenda gerenciada — o parceiro gerencia o cliente na plataforma, paga
    o preço de atacado (lista − desconto do nível) e fica com a margem.
  * Indicação — o cliente contrata direto com o código do parceiro; o
    parceiro recebe comissão recorrente sobre o preço de lista.
"""
from __future__ import annotations

import calendar
import secrets

from .db import Database

PLANS: dict[str, dict] = {
    "essentials": {"label": "Essentials", "price": 149.0, "max_assets": 5,
                   "scan_every_hours": 168, "vendors": 5},
    "professional": {"label": "Professional", "price": 499.0, "max_assets": 25,
                     "scan_every_hours": 24, "vendors": 25},
    "enterprise": {"label": "Enterprise", "price": 1499.0, "max_assets": 200,
                   "scan_every_hours": 6, "vendors": 100},
}

# (nível, clientes gerenciados mínimos, desconto, benefícios)
TIERS: list[tuple[str, int, float, dict]] = [
    ("platinum", 40, 0.40, {"white_label": True, "prospects_per_month": None,
                            "label": "Platinum"}),
    ("gold", 15, 0.30, {"white_label": True, "prospects_per_month": 50, "label": "Gold"}),
    ("silver", 5, 0.20, {"white_label": True, "prospects_per_month": 20, "label": "Silver"}),
    ("registered", 0, 0.10, {"white_label": False, "prospects_per_month": 5,
                             "label": "Registered"}),
]
REFERRAL_COMMISSION = 0.20
CURRENCY = "USD"


def new_referral_code() -> str:
    return "BM-" + secrets.token_hex(4).upper()


def managed_clients(db: Database, partner_id: int) -> int:
    row = db.one("SELECT COUNT(*) AS n FROM organizations WHERE partner_id = ? AND status = 'active'",
                 (partner_id,))
    return row["n"] if row else 0


def tier_for(db: Database, partner: dict) -> dict:
    """Nível vigente: o negociado (override) ou o conquistado por volume."""
    clients = managed_clients(db, partner["id"])
    by_name = {t[0]: t for t in TIERS}
    if partner.get("tier_override") in by_name:
        name, minimum, discount, perks = by_name[partner["tier_override"]]
    else:
        name, minimum, discount, perks = next(t for t in TIERS if clients >= t[1])
    nxt = next((t for t in reversed(TIERS) if t[1] > clients), None)
    return {"tier": name, "label": perks["label"], "discount": discount,
            "white_label": perks["white_label"],
            "prospects_per_month": perks["prospects_per_month"],
            "managed_clients": clients,
            "next_tier": ({"tier": nxt[0], "label": nxt[3]["label"],
                           "clients_needed": nxt[1] - clients} if nxt else None)}


def program_overview() -> dict:
    """Tabela pública do programa (planos e níveis)."""
    return {
        "currency": CURRENCY,
        "plans": PLANS,
        "tiers": [{"tier": n, "label": p["label"], "min_clients": m, "discount": d,
                   "white_label": p["white_label"],
                   "prospects_per_month": p["prospects_per_month"]}
                  for n, m, d, p in reversed(TIERS)],
        "referral_commission": REFERRAL_COMMISSION,
    }


def statement(db: Database, partner: dict, month: str) -> dict:
    """Extrato do mês (AAAA-MM): faturas de atacado, margens e comissões."""
    year, mon = (int(x) for x in month.split("-"))
    if not 1 <= mon <= 12:
        raise ValueError("mês inválido")
    month_end = f"{year:04d}-{mon:02d}-{calendar.monthrange(year, mon)[1]:02d}T23:59:59"
    tier = tier_for(db, partner)

    managed, referred = [], []
    for org in db.all("SELECT * FROM organizations WHERE partner_id = ? AND status = 'active'"
                      " AND created_at <= ? ORDER BY name", (partner["id"], month_end)):
        price = PLANS[org["plan"]]["price"]
        wholesale = round(price * (1 - tier["discount"]), 2)
        managed.append({"org_id": org["id"], "org": org["name"], "plan": org["plan"],
                        "list_price": price, "wholesale": wholesale,
                        "margin": round(price - wholesale, 2)})
    for org in db.all("SELECT * FROM organizations WHERE referred_by = ? AND partner_id IS NULL"
                      " AND status = 'active' AND created_at <= ? ORDER BY name",
                      (partner["id"], month_end)):
        price = PLANS[org["plan"]]["price"]
        referred.append({"org_id": org["id"], "org": org["name"], "plan": org["plan"],
                         "list_price": price,
                         "commission": round(price * REFERRAL_COMMISSION, 2)})

    due = round(sum(m["wholesale"] for m in managed), 2)
    commission = round(sum(r["commission"] for r in referred), 2)
    return {
        "month": f"{year:04d}-{mon:02d}", "currency": CURRENCY, "tier": tier,
        "managed": managed, "referrals": referred,
        "totals": {"wholesale_due": due,
                   "resale_margin": round(sum(m["margin"] for m in managed), 2),
                   "referral_commission": commission,
                   "net_payable": round(due - commission, 2)},
    }
