"""Varredura de serviços: portas TCP, banners, certificados TLS e HTTP."""
from __future__ import annotations

import http.client
import logging
import os
import re
import socket
import ssl
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .models import HTTPInfo, Service, TLSInfo

log = logging.getLogger(__name__)

HTTP_PORTS = {80, 443, 3000, 5000, 5601, 8000, 8008, 8080, 8443, 8888, 9000,
              9090, 9200, 9443}
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
]
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


# --------------------------------------------------------------------------- TCP

def tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def grab_banner(ip: str, port: int, timeout: float) -> str:
    """Lê o banner que serviços como SSH/FTP/SMTP enviam ao conectar."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(min(timeout, 2.0))
            data = sock.recv(256)
    except OSError:
        return ""
    text = data.decode("utf-8", "replace").strip()
    return "".join(c for c in text.splitlines()[0] if c.isprintable())[:200] if text else ""


# --------------------------------------------------------------------------- TLS

def _name(rdns) -> str:
    return ", ".join(f"{k}={v}" for rdn in rdns for k, v in rdn)


def _decode_der(der: bytes) -> dict:
    """Decodifica um certificado DER sem dependências externas."""
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(pem)
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    finally:
        os.unlink(path)


def tls_info(host: str, ip: str, port: int, timeout: float,
             now: datetime | None = None) -> TLSInfo | None:
    """Coleta dados do certificado. Retorna None se a porta não fala TLS."""
    now = now or datetime.now(timezone.utc)
    sni = None if _is_ip(host) else host
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                der = tls.getpeercert(binary_form=True)
                protocol = tls.version() or ""
    except (OSError, ssl.SSLError):
        return None
    if not der:
        return TLSInfo(protocol=protocol, error="sem certificado")

    info = TLSInfo(protocol=protocol)
    try:
        cert = _decode_der(der)
    except Exception as exc:  # noqa: BLE001
        info.error = f"falha ao decodificar certificado: {exc}"
        return info

    info.subject = _name(cert.get("subject", ()))
    info.issuer = _name(cert.get("issuer", ()))
    info.self_signed = cert.get("subject") == cert.get("issuer")
    info.san = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    if cert.get("notAfter"):
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]),
                                         tz=timezone.utc)
        info.not_after = expires.isoformat()
        info.days_left = (expires - now).days
    if sni:
        info.hostname_match = hostname_matches(host, info.san or _cn(cert))
    info.error = _verify_chain(host, ip, port, timeout, sni)
    return info


def _cn(cert: dict) -> list[str]:
    return [v for rdn in cert.get("subject", ()) for k, v in rdn if k == "commonName"]


def _verify_chain(host: str, ip: str, port: int, timeout: float, sni: str | None) -> str:
    """Valida a cadeia com o trust store do sistema. Retorna "" se válida."""
    if not sni:
        return ""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # hostname é verificado separadamente
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni):
                return ""
    except ssl.SSLCertVerificationError as exc:
        return f"cadeia inválida: {exc.verify_message}"
    except (OSError, ssl.SSLError):
        return ""


def hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower()
    for name in names:
        name = name.lower()
        if name == host:
            return True
        if name.startswith("*.") and "." in host:
            if host.split(".", 1)[1] == name[2:]:
                return True
    return False


def _is_ip(value: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in value else socket.AF_INET, value)
        return True
    except OSError:
        return False


# -------------------------------------------------------------------------- HTTP

def http_info(host: str, ip: str, port: int, use_tls: bool, timeout: float) -> HTTPInfo:
    scheme = "https" if use_tls else "http"
    info = HTTPInfo(url=f"{scheme}://{host}:{port}/")
    try:
        status, headers, body = _http_get(host, ip, port, use_tls, timeout)
    except Exception as exc:  # noqa: BLE001
        info.error = str(exc)[:200]
        return info

    info.status = status
    info.server = headers.get("server", "")
    info.powered_by = headers.get("x-powered-by", "")
    m = _TITLE_RE.search(body)
    if m:
        info.title = " ".join(m.group(1).decode("utf-8", "replace").split())[:120]
    if use_tls:
        info.missing_security_headers = [h for h in SECURITY_HEADERS if h not in headers]
    else:
        location = headers.get("location", "")
        info.redirect_to_https = status in (301, 302, 307, 308) and location.startswith("https://")
        info.missing_security_headers = [h for h in SECURITY_HEADERS
                                         if h not in headers and h != "strict-transport-security"]
    return info


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Conecta em um IP específico enviando o SNI do hostname."""

    def __init__(self, ip: str, port: int, sni: str | None, **kwargs):
        super().__init__(ip, port, **kwargs)
        self._sni = sni

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._sni)


def _http_get(host: str, ip: str, port: int, use_tls: bool, timeout: float):
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sni = None if _is_ip(host) else host
        conn: http.client.HTTPConnection = _PinnedHTTPSConnection(
            ip, port, sni, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(ip, port, timeout=timeout)
    default_port = 443 if use_tls else 80
    try:
        conn.request("GET", "/", headers={
            "Host": host if port == default_port else f"{host}:{port}",
            "User-Agent": "Blade-Monitor/0.1"})
        resp = conn.getresponse()
        body = resp.read(65536)
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, headers, body
    finally:
        conn.close()


# ---------------------------------------------------------------------- Pipeline

def scan(hosts: dict[str, list[str]], ports: list[int], timeout: float,
         workers: int, now: datetime | None = None) -> list[Service]:
    unique_ips = sorted({ip for ips in hosts.values() for ip in ips})
    jobs = [(ip, port) for ip in unique_ips for port in ports]
    log.info("Varrendo %d IPs x %d portas (%d conexões)", len(unique_ips), len(ports), len(jobs))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda j: (j, tcp_open(j[0], j[1], timeout)), jobs)
        open_ports = {j for j, ok in results if ok}

    services = [Service(host=h, ip=ip, port=port)
                for h, ips in sorted(hosts.items()) for ip in ips
                for port in ports if (ip, port) in open_ports]

    def enrich(svc: Service) -> Service:
        svc.tls = tls_info(svc.host, svc.ip, svc.port, timeout, now)
        if svc.tls is None and svc.port not in HTTP_PORTS:
            svc.banner = grab_banner(svc.ip, svc.port, timeout)
        if svc.tls is not None or svc.port in HTTP_PORTS or not svc.banner:
            web = http_info(svc.host, svc.ip, svc.port, svc.tls is not None, timeout)
            if web.status is not None or svc.port in HTTP_PORTS:
                svc.http = web
        return svc

    with ThreadPoolExecutor(max_workers=max(1, workers // 2)) as pool:
        return list(pool.map(enrich, services))
