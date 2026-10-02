"""Regras de risco aplicadas ao inventário de serviços expostos."""
from __future__ import annotations

from .models import Finding, Service

# Serviços que raramente devem estar acessíveis pela internet.
RISKY_PORTS: dict[int, tuple[str, str]] = {
    21: ("high", "FTP (credenciais em texto claro)"),
    23: ("critical", "Telnet (texto claro)"),
    111: ("medium", "RPCbind"),
    135: ("high", "MS-RPC"),
    139: ("high", "NetBIOS"),
    445: ("critical", "SMB"),
    389: ("high", "LDAP"),
    1433: ("high", "Microsoft SQL Server"),
    1521: ("high", "Oracle DB"),
    2049: ("high", "NFS"),
    2375: ("critical", "Docker API sem TLS"),
    3306: ("high", "MySQL/MariaDB"),
    3389: ("high", "RDP"),
    5432: ("high", "PostgreSQL"),
    5601: ("medium", "Kibana"),
    5900: ("high", "VNC"),
    5985: ("high", "WinRM (HTTP)"),
    6379: ("critical", "Redis"),
    6443: ("medium", "Kubernetes API"),
    9200: ("critical", "Elasticsearch"),
    9300: ("high", "Elasticsearch (transport)"),
    11211: ("high", "Memcached"),
    27017: ("critical", "MongoDB"),
}

WEAK_TLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def evaluate(services: list[Service], cert_warning_days: int = 30) -> list[Finding]:
    findings: list[Finding] = []
    for svc in services:
        asset = f"{svc.host}:{svc.port}"
        if svc.port in RISKY_PORTS:
            sev, name = RISKY_PORTS[svc.port]
            findings.append(Finding("risky-port", sev, asset,
                                    f"{name} exposto à internet", f"IP {svc.ip}"))
        findings.extend(_tls_findings(svc, asset, cert_warning_days))
        findings.extend(_http_findings(svc, asset))
        if svc.banner and any(ch.isdigit() for ch in svc.banner):
            findings.append(Finding("banner-version", "low", asset,
                                    "Banner revela software/versão", svc.banner))

    # Remove duplicatas (mesmo host resolvendo para vários IPs).
    unique: dict[str, Finding] = {}
    for f in findings:
        unique.setdefault(f.key, f)
    return sorted(unique.values(), key=lambda f: (f.asset, f.rule))


def _tls_findings(svc: Service, asset: str, warn_days: int) -> list[Finding]:
    t = svc.tls
    if not t:
        return []
    out: list[Finding] = []
    if t.days_left is not None:
        if t.days_left < 0:
            out.append(Finding("cert-expired", "high", asset, "Certificado TLS expirado",
                               f"expirou em {t.not_after}"))
        elif t.days_left <= warn_days:
            out.append(Finding("cert-expiring", "medium", asset,
                               f"Certificado expira em {t.days_left} dias", t.not_after))
    if t.self_signed:
        out.append(Finding("cert-self-signed", "medium", asset,
                           "Certificado autoassinado", t.issuer))
    elif t.error.startswith("cadeia inválida"):
        out.append(Finding("cert-untrusted", "medium", asset,
                           "Cadeia de certificado não confiável", t.error))
    if not t.hostname_match:
        out.append(Finding("cert-hostname-mismatch", "medium", asset,
                           "Certificado não cobre o hostname", ", ".join(t.san[:10])))
    if t.protocol in WEAK_TLS:
        out.append(Finding("weak-tls", "medium", asset,
                           f"Protocolo TLS fraco negociado ({t.protocol})"))
    return out


def _http_findings(svc: Service, asset: str) -> list[Finding]:
    h = svc.http
    if not h or h.status is None:
        return []
    out: list[Finding] = []
    is_https = svc.tls is not None
    if not is_https and h.redirect_to_https is False:
        out.append(Finding("http-no-redirect", "low", asset,
                           "HTTP sem redirecionamento para HTTPS", f"status {h.status}"))
    if h.missing_security_headers:
        out.append(Finding("missing-security-headers", "info", asset,
                           "Cabeçalhos de segurança ausentes",
                           ", ".join(h.missing_security_headers)))
    disclosed = [v for v in (h.server, h.powered_by) if v and any(c.isdigit() for c in v)]
    if disclosed:
        out.append(Finding("server-version-disclosure", "low", asset,
                           "Servidor revela versão", " | ".join(disclosed)))
    lowered = h.title.lower()
    for marker in ("index of /", "phpmyadmin", "jenkins", "grafana", "kibana",
                   "rabbitmq", "admin", "login"):
        if marker in lowered:
            sev = "high" if marker == "index of /" else "medium"
            out.append(Finding("sensitive-panel", sev, asset,
                               f"Página sensível exposta: {h.title}", h.url))
            break
    return out
