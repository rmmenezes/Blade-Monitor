"""Verificação de posse de ativos antes de qualquer varredura ativa.

Domínios: registro DNS TXT em ``_blade-monitor.<domínio>`` (ou no próprio
domínio) contendo ``blade-monitor-verification=<token>``, ou o arquivo
``https://<domínio>/.well-known/blade-monitor-verification.txt`` com o token.

IPs/CIDRs: não há prova técnica simples de posse; exigem atestado de um
administrador (contrato/carta de autorização), registrado na auditoria.
"""
from __future__ import annotations

import ipaddress
import random
import re
import socket
import struct
import urllib.request
from typing import Callable

TXT_PREFIX = "blade-monitor-verification="
WELL_KNOWN = "/.well-known/blade-monitor-verification.txt"
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalize_asset(kind: str, value: str, allow_private: bool = False) -> str:
    """Valida e normaliza o valor de um ativo; levanta ValueError se inválido.

    Endereços privados/loopback não são superfície externa e só são aceitos
    com ``allow_private`` (laboratório/testes).
    """
    value = value.strip().lower().rstrip(".")
    if kind == "domain":
        if value.startswith(("http://", "https://")) or not _DOMAIN_RE.match(value):
            raise ValueError(f"domínio inválido: {value}")
        return value
    if kind in ("ip", "cidr"):
        net = ipaddress.ip_network(value, strict=False)
        if kind == "ip" and net.num_addresses != 1:
            raise ValueError(f"IP inválido: {value}")
        if net.num_addresses > 4096:
            raise ValueError("rede maior que /20 não é suportada")
        if (net.is_private or net.is_loopback) and not allow_private:
            raise ValueError("endereço privado/loopback não é superfície externa")
        return str(net.network_address) if kind == "ip" else str(net)
    raise ValueError(f"tipo de ativo inválido: {kind}")


def instructions(domain: str, token: str) -> dict:
    return {
        "dns": {"type": "TXT", "name": f"_blade-monitor.{domain}",
                "value": f"{TXT_PREFIX}{token}"},
        "http": {"url": f"https://{domain}{WELL_KNOWN}", "content": token},
    }


# ---------------------------------------------------------------- DNS TXT

def _nameservers() -> list[str]:
    servers = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append(parts[1])
    except OSError:
        pass
    return servers or ["1.1.1.1", "8.8.8.8"]


def _skip_name(msg: bytes, pos: int) -> int:
    while True:
        length = msg[pos]
        if length & 0xC0 == 0xC0:
            return pos + 2
        if length == 0:
            return pos + 1
        pos += length + 1


def build_txt_query(name: str, qid: int) -> bytes:
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("idna") for p in name.split(".")) + b"\0"
    return header + qname + struct.pack(">HH", 16, 1)


def parse_txt_response(msg: bytes, qid: int) -> list[str]:
    rid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", msg[:12])
    if rid != qid or flags & 0x000F not in (0, 3):  # NOERROR / NXDOMAIN
        raise OSError("resposta DNS inválida")
    pos = 12
    for _ in range(qd):
        pos = _skip_name(msg, pos) + 4
    records = []
    for _ in range(an):
        pos = _skip_name(msg, pos)
        rtype, _, _, rdlen = struct.unpack(">HHIH", msg[pos:pos + 10])
        pos += 10
        rdata, pos = msg[pos:pos + rdlen], pos + rdlen
        if rtype == 16:
            parts, i = [], 0
            while i < len(rdata):
                n = rdata[i]
                parts.append(rdata[i + 1:i + 1 + n].decode("utf-8", "replace"))
                i += n + 1
            records.append("".join(parts))
    return records


def dns_txt(name: str, timeout: float = 3.0) -> list[str]:
    for server in _nameservers()[:3]:
        qid = random.randint(0, 0xFFFF)
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(build_txt_query(name, qid), (server, 53))
                data, _ = sock.recvfrom(4096)
            return parse_txt_response(data, qid)
        except (OSError, struct.error, IndexError):
            continue
    return []


def _resolves_public(domain: str) -> bool:
    try:
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        return False
    return bool(infos) and all(ipaddress.ip_address(i[4][0]).is_global for i in infos)


def http_token(domain: str, timeout: float = 5.0) -> str:
    # Não busca em domínios que apontam para a rede interna (SSRF).
    if not _resolves_public(domain):
        return ""
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{domain}{WELL_KNOWN}",
                                         headers={"User-Agent": "Blade-Monitor/0.2"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(512).decode("utf-8", "replace").strip()
        except Exception:  # noqa: BLE001 - ausência é o caso comum
            continue
    return ""


def verify_domain(domain: str, token: str,
                  txt_lookup: Callable[[str], list[str]] = dns_txt,
                  http_lookup: Callable[[str], str] = http_token) -> str | None:
    """Retorna o método que comprovou a posse ("dns"/"http") ou None."""
    expected = f"{TXT_PREFIX}{token}"
    for name in (f"_blade-monitor.{domain}", domain):
        if any(r.strip() == expected for r in txt_lookup(name)):
            return "dns"
    if http_lookup(domain) == token:
        return "http"
    return None
