from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from typing import Iterable, List, Optional

from ..ecosystems import Ecosystem

@dataclass
class RegistryObservation:
    ecosystem: str
    package: str
    version: str
    resolved: bool
    exposed: bool
    present: bool
    level: str
    source: str
    identity: str
    detail: str

    def as_dict(self) -> dict:
        return asdict(self)

def observe(ecosystem: Ecosystem, package: str,
            version: Optional[str] = None) -> RegistryObservation:
    release = ecosystem.resolve(package, version)
    if not release.resolved:
        return RegistryObservation(
            ecosystem=ecosystem.name,
            package=package,
            version="",
            resolved=False,
            exposed=False,
            present=False,
            level=ecosystem.documented_level,
            source="",
            identity="",
            detail="package or version did not resolve",
        )

    evidence = ecosystem.registry_evidence(release)
    return RegistryObservation(
        ecosystem=ecosystem.name,
        package=package,
        version=release.version,
        resolved=True,
        exposed=evidence.present if evidence.exposed is None else evidence.exposed,
        present=evidence.present,
        level=evidence.level,
        source=evidence.source,
        identity=evidence.identity,
        detail=evidence.detail,
    )

def scan(
    ecosystem: Ecosystem,
    packages: Iterable[str],
    *,
    workers: int = 8,
    progress=None,
) -> List[RegistryObservation]:
    names = list(packages)
    total = len(names)

    def run(index_and_name):
        index, name = index_and_name
        observation = observe(ecosystem, name)
        if progress is not None:
            progress(index + 1, total, observation)
        return observation

    with ThreadPoolExecutor(workers) as pool:
        return list(pool.map(run, enumerate(names)))
