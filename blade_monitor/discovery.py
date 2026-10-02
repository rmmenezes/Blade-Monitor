"""Descoberta de ativos: subdomínios (Certificate Transparency) e resolução DNS."""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import logging
import socket
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger(__name__)

CRT_SH_URL = "https://crt.sh/?q={query}&output=json"


def crtsh_subdomains(domain: str, timeout: float = 30.0) -> set[str]:
    """Consulta logs públicos de Certificate Transparency via crt.sh."""
    url = CRT_SH_URL.format(query=urllib.parse.quote(f"%.{domain}"))
    req = urllib.request.Request(url, headers={"User-Agent": "Blade-Monitor/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace") or "[]")
    except Exception as exc:  # noqa: BLE001 - fonte externa, falha não é fatal
        log.warning("crt.sh falhou para %s: %s", domain, exc)
        return set()
    return parse_crtsh(data, domain)


def parse_crtsh(entries: list[dict], domain: str) -> set[str]:
    found: set[str] = set()
    for entry in entries:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if name == domain or name.endswith("." + domain):
                found.add(name)
    return found


def resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        return []
    return sorted({info[4][0] for info in infos})


def is_excluded(host: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(host, p) for p in patterns)


def expand_ip_targets(items: list[str], max_hosts: int = 4096) -> list[str]:
    """Aceita IPs individuais ou redes CIDR."""
    ips: list[str] = []
    for item in items:
        net = ipaddress.ip_network(item, strict=False)
        if net.num_addresses > max_hosts:
            raise ValueError(f"Rede {item} muito grande (> {max_hosts} endereços)")
        hosts = list(net.hosts()) or [net.network_address]
        ips.extend(str(h) for h in hosts)
    return ips


def discover(domains: list[str], ips: list[str], exclude: list[str],
             use_ct: bool = True, workers: int = 50) -> dict[str, list[str]]:
    """Retorna mapa host -> lista de IPs para todos os ativos ativos."""
    names: set[str] = set(domains)
    if use_ct:
        for d in domains:
            subs = crtsh_subdomains(d)
            log.info("%d subdomínios via CT para %s", len(subs), d)
            names |= subs
    names = {n for n in names if not is_excluded(n, exclude)}

    hosts: dict[str, list[str]] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for name, addrs in zip(sorted(names), pool.map(resolve, sorted(names))):
            if addrs:
                hosts[name] = addrs

    for ip in expand_ip_targets(ips):
        if not is_excluded(ip, exclude):
            hosts.setdefault(ip, [ip])
    return hosts
