from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterable, List, Optional

from ..digest import DEFAULT_ALGORITHMS, digest_artifact
from ..ecosystems import Ecosystem
from ..rekor import EntryUnavailable, RekorClient

SCHEMA = "log-path/2"

@dataclass
class LogObservation:
    ecosystem: str
    package: str
    version: str
    status: str
    digests: Dict[str, str] = field(default_factory=dict)
    entries: Dict[str, List[str]] = field(default_factory=dict)
    hinted: List[str] = field(default_factory=list)
    detail: str = ""
    schema: str = SCHEMA
    verification: Optional[dict] = None

    @property
    def present(self) -> bool:
        return any(self.entries.values()) or bool(self.hinted)

    @property
    def verified(self) -> bool:
        return bool(self.verification
                    and self.verification.get("verified_and_bound", 0) > 0)

    @property
    def entry_ids(self) -> List[str]:
        seen: List[str] = []
        for found in list(self.entries.values()) + [self.hinted]:
            for uuid in found:
                if uuid not in seen:
                    seen.append(uuid)
        return seen

    def as_dict(self) -> dict:
        record = asdict(self)
        if record.get("verification") is None:
            record.pop("verification")
        return record

def observe(
    ecosystem: Ecosystem,
    rekor: RekorClient,
    package: str,
    version: Optional[str] = None,
) -> LogObservation:
    release = ecosystem.resolve(package, version)
    if not release.resolved:
        return LogObservation(
            ecosystem.name, package, "", "unresolved",
            detail="package or version did not resolve",
        )

    url = ecosystem.artifact_url(release)
    if not url:
        return LogObservation(
            ecosystem.name, release.package, release.version, "no artifact",
            detail="no artifact URL to hash",
        )
    try:
        computed = digest_artifact(ecosystem.client, url, DEFAULT_ALGORITHMS)
    except OSError as error:
        return LogObservation(
            ecosystem.name, release.package, release.version, "unreachable",
            detail=str(error),
        )
    digests = computed.values

    entries = rekor.search_all(digests)
    found = {uuid for group in entries.values() for uuid in group}
    hinted = [] if found else _from_hints(ecosystem, rekor, release, digests, found)

    return LogObservation(
        ecosystem=ecosystem.name,
        package=release.package,
        version=release.version,
        status="found" if (any(entries.values()) or hinted) else "not found",
        digests=digests,
        entries=entries,
        hinted=hinted,
        detail="recovered by log index" if hinted else "",
    )

def _from_hints(ecosystem, rekor, release, digests, already_found) -> List[str]:
    recovered: List[str] = []
    for index in ecosystem.log_hints(release):
        try:
            entry = rekor.entry_at_index(index)
        except Exception:
            continue
        if entry.uuid in already_found or entry.uuid in recovered:
            continue
        if _covers(entry, digests):
            recovered.append(entry.uuid)
    return recovered

def _covers(entry, digests: Dict[str, str]) -> bool:
    spec = entry.spec
    recorded = (spec.get("data") or {}).get("hash") or {}
    algorithm, value = recorded.get("algorithm"), recorded.get("value")
    if algorithm and value:
        return digests.get(algorithm, "").lower() == str(value).lower()
    payload = entry.payload_hash
    return bool(payload) and payload.lower() in {v.lower() for v in digests.values()}

def scan(
    ecosystem: Ecosystem,
    rekor: RekorClient,
    packages: Iterable[str],
    *,
    workers: int = 6,
    progress=None,
) -> List[LogObservation]:
    names = list(packages)
    total = len(names)

    def run(index_and_name):
        index, name = index_and_name
        observation = observe(ecosystem, rekor, name)
        if progress is not None:
            progress(index + 1, total, observation)
        return observation

    with ThreadPoolExecutor(workers) as pool:
        return list(pool.map(run, enumerate(names)))

def verify(
    ecosystem: Ecosystem,
    rekor: RekorClient,
    observation: LogObservation,
    *,
    verifier=None,
    classifier=None,
    expected_repository: str = "",
    use_registry_bundles: bool = True,
) -> LogObservation:
    from ..verify.log_check import (
        EntryVerification,
        UNAVAILABLE,
        summarise,
        verify_entry,
    )

    if not observation.present:
        observation.verification = summarise([]).as_dict()
        return observation

    from ..verify.log_material import index_bundles

    release = ecosystem.resolve(observation.package, observation.version)
    if verifier is None and ecosystem.name == "npm":
        from ..verify.npm_verifier import NpmLogVerifier

        verifier = NpmLogVerifier(client=ecosystem.client,
                                  artifact_url=ecosystem.artifact_url(release))
    bundles: Dict[int, dict] = {}
    if use_registry_bundles:
        try:
            bundles = index_bundles(ecosystem.registry_bundles(release))
        except Exception:
            bundles = {}

    hinted = set(observation.hinted)
    records: List[EntryVerification] = []
    for uuid in observation.entry_ids:
        try:
            entry = rekor.entry(uuid)
        except EntryUnavailable as error:
            records.append(EntryVerification(
                uuid=uuid, outcome=UNAVAILABLE, detail=str(error),
                source="log index hint" if uuid in hinted else "digest query"))
            continue

        record = verify_entry(
            entry, observation.digests, verifier=verifier,
            expected_repository=expected_repository,
            source="log index hint" if uuid in hinted else "digest query",
            registry_bundle=bundles.get(entry.log_index),
        )
        if classifier is not None:
            try:
                attribution = classifier(entry)
                record.role = str(attribution.role)
                record.signer = (attribution.identity.repository
                                 or attribution.identity.subject or "")
            except Exception:
                pass
        records.append(record)

    observation.verification = summarise(records).as_dict()
    return observation
