from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Dict, Optional

from . import identity as identity_module
from .identity import Identity
from .rekor import Entry

HOSTED_ISSUER_HOSTS = ("issuer.enforce.dev",)

class Assertion(str, enum.Enum):

    PROVENANCE = "provenance"
    ATTRIBUTION = "attribution"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return self.value

STATEMENT_KINDS = frozenset({"dsse", "intoto"})

class Role(str, enum.Enum):

    PUBLISHER = "publisher"
    PROJECT_SIGNER = "project signer"
    OBSERVER = "observer"
    REGISTRY = "registry"
    BARE_KEY = "bare key"
    UNREADABLE = "unreadable"

    def __str__(self) -> str:
        return self.value

    @property
    def token(self) -> str:
        return self.value.replace(" ", "_")

@dataclass(frozen=True)
class Attribution:
    role: Role
    identity: Identity
    detail: str = ""
    assertion: Assertion = Assertion.UNKNOWN

    @property
    def names_someone(self) -> bool:
        return self.role in (Role.PUBLISHER, Role.PROJECT_SIGNER,
                             Role.OBSERVER, Role.REGISTRY)

    @property
    def names_the_project(self) -> bool:
        return (self.role in (Role.PUBLISHER, Role.PROJECT_SIGNER)
                or (self.role is Role.OBSERVER
                    and "the package claims" in self.detail))

    @property
    def could_be_provenance(self) -> bool:
        return (self.names_the_project
                and self.assertion is Assertion.PROVENANCE)

    @property
    def registry_authorized(self) -> bool:
        return self.role is Role.PUBLISHER

def classify(
    entry: Entry,
    *,
    expected_repository: str = "",
    expected_identity: str = "",
    expected_issuer: str = "",
    registry_keys: Optional[Dict[bytes, str]] = None,
    registry_authorizes: bool = False,
    registry_answers: bool = False,
) -> Attribution:
    materials = entry.materials
    assertion = (Assertion.PROVENANCE if entry.kind in STATEMENT_KINDS
                 else Assertion.UNKNOWN)
    if not materials:
        return Attribution(Role.UNREADABLE, Identity(),
                           "entry carries no signer", assertion)

    for material in materials:
        owner = identity_module.matches_known_key(material, registry_keys or {})
        if owner is not None:
            return Attribution(
                Role.REGISTRY, Identity(key_fingerprint=identity_module.fingerprint(
                    _decode(material))), f"key published by {owner}", assertion
            )

        signer = identity_module.parse(material)
        if signer.describes_build:
            assertion = Assertion.PROVENANCE
        elif assertion is Assertion.UNKNOWN and signer.is_certificate:
            assertion = Assertion.ATTRIBUTION
        if signer.key_fingerprint:
            return Attribution(Role.BARE_KEY, signer,
                               "no certificate accompanies the key", assertion)
        if not signer.is_certificate:
            continue

        issuer_matches = bool(expected_issuer and signer.issuer == expected_issuer)
        if (expected_identity and signer.subject == expected_identity
                and issuer_matches):
            return Attribution(Role.PUBLISHER, signer,
                               "certificate names the identity the registry "
                               "recorded", assertion)

        if any(host in signer.issuer for host in HOSTED_ISSUER_HOSTS):
            return Attribution(Role.OBSERVER, signer, "hosted issuer", assertion)
        built = identity_module.repository_in(
            signer.build.get("source_repository", ""))
        built_from = built or signer.repository

        if expected_repository and built_from:
            if registry_authorizes:
                role, source = Role.PUBLISHER, "the registry's own record"
                if not issuer_matches:
                    return Attribution(Role.OBSERVER, signer,
                                       "issuer does not match the registry record",
                                       assertion)
            elif registry_answers:
                role, source = Role.OBSERVER, ("the repository the package "
                                               "claims, which the registry "
                                               "does not endorse")
            else:
                role, source = (Role.PROJECT_SIGNER,
                                "the repository the package claims, with no "
                                "registry able to endorse it")
            if built_from.lower() == expected_repository.lower():
                return Attribution(role, signer,
                                   f"repository matches {source}", assertion)
            if (not registry_authorizes
                    and built_from.split("/")[0].lower()
                    == expected_repository.split("/")[0].lower()):
                return Attribution(
                    role, signer,
                    f"different repository under the owner named by {source}",
                    assertion,
                )
            return Attribution(
                Role.OBSERVER,
                signer,
                f"signed from {built_from}, metadata names {expected_repository}",
                assertion,
            )
        return Attribution(Role.OBSERVER, signer,
                           "no repository to compare against", assertion)

    return Attribution(Role.UNREADABLE, Identity(),
                       "no material could be read", assertion)

def classify_for_release(entry: Entry, ecosystem, release,
                         registry_keys=None) -> Attribution:
    """Classify an entry using the registry's answer for one release."""
    records = (ecosystem.registry_publisher_records(release)
               if hasattr(ecosystem, "registry_publisher_records") else [])
    for recorded in records:
        attribution = classify(
            entry,
            expected_identity=recorded.get("subject", ""),
            expected_repository=recorded.get("repository", ""),
            expected_issuer=recorded.get("issuer", ""),
            registry_authorizes=True,
            registry_answers=ecosystem.answers_publisher_authorization,
            registry_keys=registry_keys,
        )
        if attribution.registry_authorized:
            return attribution
    return classify(
        entry,
        expected_repository=release.declared_repository,
        registry_answers=ecosystem.answers_publisher_authorization,
        registry_keys=registry_keys,
    )

def _decode(material: str) -> bytes:
    import base64

    try:
        return base64.b64decode(material)
    except Exception:
        return b""
