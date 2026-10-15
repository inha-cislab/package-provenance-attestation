from __future__ import annotations

import base64
import json
import re
from typing import Dict, List, Optional

from ..digest import decode_subresource_integrity
from ..http import quote
from .base import Ecosystem, Release, RegistryEvidence

REGISTRY = "https://registry.npmjs.org"
KEYS = f"{REGISTRY}/-/npm/v1/keys"
PROVENANCE_PREDICATES = (
    "https://slsa.dev/provenance/v1",
    "https://slsa.dev/provenance/v0.2",
)

class Npm(Ecosystem):
    name = "npm"
    documented_level = "provenance"
    answers_publisher_authorization = True
    verifier_requires_project = True

    def resolve(self, package: str, version: Optional[str] = None) -> Release:
        document = self.client.get_json(f"{REGISTRY}/{quote(package, safe='@/')}")
        if not document:
            return Release(package=package, version="")

        chosen = version or (document.get("dist-tags") or {}).get("latest") or ""
        release = (document.get("versions") or {}).get(chosen) or {}
        dist = release.get("dist") or {}
        return Release(
            package=package,
            version=chosen,
            artifact_url=dist.get("tarball", ""),
            declared_repository=_repository_of(release),
            published_at=(document.get("time") or {}).get(chosen, ""),
            metadata={
                "integrity": dist.get("integrity", ""),
                "attestations_url": (dist.get("attestations") or {}).get("url", ""),
            },
        )

    def registry_evidence(self, release: Release) -> RegistryEvidence:
        url = str(release.metadata.get("attestations_url") or "")
        if not url:
            return RegistryEvidence(False, "provenance", source="dist.attestations")

        document = self.client.get_json(url)
        if not document:
            return RegistryEvidence(
                False, "provenance", source="dist.attestations",
                detail="attestation document did not load",
            )
        predicates = [
            item.get("predicateType", "")
            for item in document.get("attestations") or []
        ]
        return RegistryEvidence(
            present=any(p in PROVENANCE_PREDICATES for p in predicates),
            level="provenance",
            source="dist.attestations",
            detail=", ".join(sorted({p.rsplit("/", 2)[0] for p in predicates if p})),
        )

    def registry_bundles(self, release: Release) -> List[dict]:
        url = str(release.metadata.get("attestations_url") or "")
        if not url:
            return []
        document = self.client.get_json(url) or {}
        return [item["bundle"] for item in document.get("attestations") or []
                if isinstance(item.get("bundle"), dict)]

    def expected_publisher(self, release: Release) -> str:
        url = str(release.metadata.get("attestations_url") or "")
        if not url:
            return ""
        document = self.client.get_json(url) or {}
        for item in document.get("attestations") or []:
            if item.get("predicateType") not in PROVENANCE_PREDICATES:
                continue
            bundle = item.get("bundle") or {}
            envelope = bundle.get("dsseEnvelope") or {}
            payload = envelope.get("payload")
            if not payload:
                continue
            found = _build_repository(json.loads(base64.b64decode(payload)))
            if found:
                return found
        return ""

    def published_digest(self, release: Release, algorithm: str) -> Optional[str]:
        integrity = str(release.metadata.get("integrity") or "")
        if algorithm != "sha512" or not integrity.startswith("sha512-"):
            return None
        return decode_subresource_integrity(integrity)

    def registry_publisher_records(self, release: Release) -> List[Dict[str, str]]:
        from ..identity import GITHUB_ACTIONS

        repository = self.registry_publisher(release)
        return [{"repository": repository, "issuer": GITHUB_ACTIONS}] if repository else []

    def verifier_command(self, release: Release) -> Optional[List[str]]:
        return ["npm", "audit", "signatures"]

    def registry_keys(self) -> Dict[bytes, str]:
        import base64

        document = self.client.get_json(KEYS) or {}
        keys: Dict[bytes, str] = {}
        for key in document.get("keys") or []:
            try:
                keys[base64.b64decode(key["key"])] = "npm"
            except Exception:
                continue
        return keys

def _build_repository(statement) -> str:
    predicate = statement.get("predicate") or {}
    build = predicate.get("buildDefinition") or {}
    workflow = (build.get("externalParameters") or {}).get("workflow") or {}
    source = workflow.get("repository")
    if not source:
        invocation = predicate.get("invocation") or {}
        source = (invocation.get("configSource") or {}).get("uri", "")
    return _repository_of({"repository": source})

def _repository_of(release) -> str:
    repository = release.get("repository")
    if isinstance(repository, dict):
        repository = repository.get("url")
    for candidate in (repository, release.get("homepage")):
        match = re.search(r"github\.com[:/]+([^/]+)/([^/#?@]+)", str(candidate or ""))
        if match:
            name = match.group(2)
            return f"{match.group(1)}/{name[:-4] if name.endswith('.git') else name}"
    return ""
