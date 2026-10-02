"""Comparação entre snapshots: o que mudou na superfície exposta."""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Finding, Snapshot


@dataclass
class Changes:
    new_hosts: list[str] = field(default_factory=list)
    removed_hosts: list[str] = field(default_factory=list)
    new_services: list[str] = field(default_factory=list)
    closed_services: list[str] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not any(vars(self).values())


def _service_keys(snap: Snapshot) -> set[str]:
    return {f"{s.host}:{s.port}" for s in snap.services}


def compare(old: Snapshot | None, new: Snapshot) -> Changes:
    if old is None:
        # Primeira execução: tudo é novo, mas só achados geram alerta.
        return Changes(new_findings=list(new.findings))
    old_f = {f.key: f for f in old.findings}
    new_f = {f.key: f for f in new.findings}
    return Changes(
        new_hosts=sorted(set(new.hosts) - set(old.hosts)),
        removed_hosts=sorted(set(old.hosts) - set(new.hosts)),
        new_services=sorted(_service_keys(new) - _service_keys(old)),
        closed_services=sorted(_service_keys(old) - _service_keys(new)),
        new_findings=[new_f[k] for k in sorted(new_f.keys() - old_f.keys())],
        resolved_findings=[old_f[k] for k in sorted(old_f.keys() - new_f.keys())],
    )
