"""Nota de segurança da superfície externa: 0–100 e conceito A–F.

Modelo (inspirado em ratings de risco cibernético):
  * cada achado pertence a uma categoria e pesa conforme a severidade;
  * a penalidade é normalizada pelo tamanho da superfície (mais hosts
    diluem achados isolados, mas não os escondem);
  * nota da categoria = 100 · e^(−penalidade/20);
  * nota geral = média ponderada das categorias, com teto quando há
    achado crítico (≤ 59, F) ou alto (≤ 79, C).
"""
from __future__ import annotations

import math

from ..models import Finding

CATEGORIES: dict[str, tuple[str, float]] = {
    "network": ("Segurança de rede", 0.35),
    "tls": ("Certificados e TLS", 0.25),
    "web": ("Higiene de aplicações web", 0.25),
    "disclosure": ("Vazamento de informação", 0.15),
}

RULE_CATEGORY = {
    "risky-port": "network",
    "cert-expired": "tls",
    "cert-expiring": "tls",
    "cert-self-signed": "tls",
    "cert-untrusted": "tls",
    "cert-hostname-mismatch": "tls",
    "weak-tls": "tls",
    "http-no-redirect": "web",
    "missing-security-headers": "web",
    "sensitive-panel": "web",
    "server-version-disclosure": "disclosure",
    "banner-version": "disclosure",
}

SEVERITY_WEIGHT = {"critical": 40.0, "high": 20.0, "medium": 8.0, "low": 3.0, "info": 1.0}
CAPS = {"critical": 59, "high": 79}
GRADES = ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F"))


def category_of(rule: str) -> str:
    return RULE_CATEGORY.get(rule, "web")


def grade(score: int) -> str:
    return next(g for floor, g in GRADES if score >= floor)


def compute(findings: list[Finding], host_count: int) -> dict:
    size_factor = 1 + math.log2(max(1, host_count))
    penalty = {c: 0.0 for c in CATEGORIES}
    counts = {c: 0 for c in CATEGORIES}
    for f in findings:
        cat = category_of(f.rule)
        penalty[cat] += SEVERITY_WEIGHT.get(f.severity, 0)
        counts[cat] += 1

    categories = {}
    for cat, (label, _) in CATEGORIES.items():
        s = round(100 * math.exp(-(penalty[cat] / size_factor) / 20))
        categories[cat] = {"label": label, "score": s, "grade": grade(s), "findings": counts[cat]}

    overall = round(sum(categories[c]["score"] * w for c, (_, w) in CATEGORIES.items()))
    severities = {f.severity for f in findings}
    for sev, cap in CAPS.items():
        if sev in severities:
            overall = min(overall, cap)
            break
    return {"score": overall, "grade": grade(overall), "categories": categories}
