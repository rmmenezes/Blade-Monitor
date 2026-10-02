"""Estruturas de dados do inventário de exposição."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class TLSInfo:
    subject: str = ""
    issuer: str = ""
    not_after: str = ""
    days_left: int | None = None
    san: list[str] = field(default_factory=list)
    hostname_match: bool = True
    self_signed: bool = False
    protocol: str = ""
    error: str = ""


@dataclass
class HTTPInfo:
    url: str = ""
    status: int | None = None
    title: str = ""
    server: str = ""
    powered_by: str = ""
    redirect_to_https: bool | None = None
    missing_security_headers: list[str] = field(default_factory=list)
    error: str = ""


@dataclass
class Service:
    host: str
    ip: str
    port: int
    banner: str = ""
    tls: TLSInfo | None = None
    http: HTTPInfo | None = None

    @property
    def key(self) -> str:
        return f"{self.host}|{self.ip}:{self.port}"


@dataclass
class Finding:
    rule: str
    severity: str
    asset: str
    title: str
    detail: str = ""

    @property
    def key(self) -> str:
        return f"{self.rule}|{self.asset}"


@dataclass
class Snapshot:
    started_at: str
    finished_at: str = ""
    hosts: dict[str, list[str]] = field(default_factory=dict)  # host -> IPs
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Snapshot":
        services = []
        for s in d.get("services", []):
            tls = TLSInfo(**s["tls"]) if s.get("tls") else None
            http = HTTPInfo(**s["http"]) if s.get("http") else None
            services.append(Service(host=s["host"], ip=s["ip"], port=s["port"],
                                    banner=s.get("banner", ""), tls=tls, http=http))
        return cls(
            started_at=d["started_at"],
            finished_at=d.get("finished_at", ""),
            hosts=d.get("hosts", {}),
            services=services,
            findings=[Finding(**f) for f in d.get("findings", [])],
        )
