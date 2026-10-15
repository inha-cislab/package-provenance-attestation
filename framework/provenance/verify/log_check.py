from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from . import log_material
from .log_verifier import LogVerifier

VERIFIED = "verified"
POLICY_REFUSED = "policy refused"
SUBJECT_MISMATCH = "subject mismatch"
INVALID = "invalid signature"
NO_MATERIAL = "no material"
UNCERTIFIED = "uncertified key"
UNSUPPORTED = "unsupported entry kind"
UNAVAILABLE = "entry unavailable"
MALFORMED = "malformed entry"
TRUST_ROOT = "trust root unavailable"

SUCCESS = VERIFIED

@dataclass
class EntryVerification:
    uuid: str
    outcome: str
    kind: str = ""
    log_index: Optional[int] = None
    source: str = "digest query"
    verified: bool = False
    binds_artifact: bool = False
    asserts_build: bool = False
    subject_digests: Dict[str, List[str]] = field(default_factory=dict)
    identity_policy: str = ""
    identity_source: str = ""
    role: str = ""
    signer: str = ""
    detail: str = ""

    @property
    def succeeded(self) -> bool:
        return (self.verified and self.binds_artifact
                and self.identity_policy != "refused")

    def as_dict(self) -> dict:
        return asdict(self)

def _binds(material, verification, artifact_digests) -> bool:
    if material.signed_digest:
        return any(
            material.signed_digest.get(algorithm, "") == str(value).lower()
            for algorithm, value in artifact_digests.items())
    subjects = verification.subject_digests or {}
    return any(
        str(value).lower() in subjects.get(algorithm, [])
        for algorithm, value in artifact_digests.items())

def verify_entry(
    entry,
    artifact_digests: Dict[str, str],
    *,
    verifier: Optional[LogVerifier] = None,
    expected_repository: str = "",
    identity_source: str = "",
    source: str = "digest query",
    registry_bundle: Any = None,
) -> EntryVerification:
    record = EntryVerification(
        uuid=entry.uuid, outcome=NO_MATERIAL,
        kind=f"{entry.kind}/{entry.api_version}",
        log_index=entry.log_index, source=source)

    material = log_material.material_for(entry)
    if not material.usable and registry_bundle is not None:
        material = log_material.bundle_from_registry(registry_bundle)
        if material.usable:
            record.source = "registry-served bundle"

    if not material.usable:
        record.outcome = _missing_outcome(material.missing)
        record.detail = material.missing
        return record

    try:
        result = (verifier or LogVerifier()).verify_bundle(
            material.bundle, artifact_digests=artifact_digests,
            expected_repository=expected_repository)
    except Exception as error:
        record.outcome = TRUST_ROOT
        record.detail = str(error)[:200]
        return record

    record.subject_digests = result.subject_digests
    record.detail = result.detail

    if result.outcome in (TRUST_ROOT, UNCERTIFIED, "verifier unavailable", "artifact unavailable"):
        record.outcome = result.outcome
        return record

    if result.outcome == "unreadable bundle":
        if not log_material.carries_certificate(material.bundle):
            record.outcome = UNCERTIFIED
            record.detail = ("signed with a published key rather than a "
                             "certificate, so no Fulcio identity attaches to it")
            return record
        record.outcome = MALFORMED
        return record
    if not result.verified:
        record.outcome = INVALID
        return record

    record.verified = True
    record.binds_artifact = result.subject_matches and _binds(material, result, artifact_digests)
    record.asserts_build = bool(material.statement) and entry.kind in (
        log_material.STATEMENT_KINDS)
    if not record.binds_artifact:
        record.outcome = SUBJECT_MISMATCH
        record.detail = (result.detail
                         or "the record verifies but covers different bytes")
        return record

    if expected_repository:
        record.identity_policy = ("refused" if result.outcome == "policy refused"
                                  else "matches")
        record.identity_source = identity_source or "unstated"
    record.outcome = POLICY_REFUSED if record.identity_policy == "refused" else VERIFIED
    return record

def _missing_outcome(missing: str) -> str:
    if missing.startswith("unsupported entry kind"):
        return UNSUPPORTED
    if "bare key" in missing:
        return UNCERTIFIED
    return NO_MATERIAL

@dataclass
class ObservationVerification:

    entries: int = 0
    verified_records: int = 0
    verified_and_bound: int = 0
    verified_publisher: int = 0
    verified_project_signer: int = 0
    verified_build_provenance: int = 0
    observer_records: int = 0
    project_signer_records: int = 0
    registry_records: int = 0
    bare_key_records: int = 0
    unverified: int = 0
    outcomes: Dict[str, int] = field(default_factory=dict)
    records: List[dict] = field(default_factory=list)

    @property
    def any_verified(self) -> bool:
        return self.verified_and_bound > 0

    def as_dict(self) -> dict:
        return asdict(self)

def summarise(records: List[EntryVerification]) -> ObservationVerification:
    summary = ObservationVerification(entries=len(records))
    for record in records:
        summary.outcomes[record.outcome] = summary.outcomes.get(record.outcome, 0) + 1
        if record.verified:
            summary.verified_records += 1
        if record.verified and record.binds_artifact:
            summary.verified_and_bound += 1
        if record.succeeded:
            if record.asserts_build:
                summary.verified_build_provenance += 1
            if record.role == "publisher":
                summary.verified_publisher += 1
            elif record.role == "project signer":
                summary.verified_project_signer += 1
        else:
            summary.unverified += 1
        if record.role == "project signer":
            summary.project_signer_records += 1
        elif record.role == "observer":
            summary.observer_records += 1
        elif record.role == "registry":
            summary.registry_records += 1
        elif record.role in ("bare key", "bare-key"):
            summary.bare_key_records += 1
        summary.records.append(record.as_dict())
    return summary
