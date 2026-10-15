from __future__ import annotations

import sys
from typing import Dict, List, Optional, Tuple

from ..http import quote
from .base import Ecosystem, Release, RegistryEvidence

API = "https://pypi.org/pypi"
PROVENANCE = "https://pypi.org/integrity/{package}/{version}/{filename}/provenance"

SPONSORS = "/sponsors/"

class PyPI(Ecosystem):
    name = "pypi"
    documented_level = "provenance"
    answers_publisher_authorization = True

    def resolve(self, package: str, version: Optional[str] = None) -> Release:
        url = (
            f"{API}/{quote(package)}/json"
            if version is None
            else f"{API}/{quote(package)}/{quote(version)}/json"
        )
        document = self.client.get_json(url)
        if not document:
            return Release(package=package, version="")

        info = document.get("info") or {}
        files = document.get("urls") or []
        artifact = _preferred_file(files)
        return Release(
            package=package,
            version=info.get("version", version or ""),
            artifact_url=(artifact or {}).get("url", ""),
            declared_repository=_repository_of(info),
            published_at=(artifact or {}).get("upload_time_iso_8601", ""),
            metadata={"filename": (artifact or {}).get("filename", ""),
                      "files": len(files)},
        )

    def registry_evidence(self, release: Release) -> RegistryEvidence:
        document = self._provenance_document(release)
        if not document:
            return RegistryEvidence(False, "provenance", source="PEP 740 endpoint")

        publisher = _publisher_of(document)
        return RegistryEvidence(
            present=True,
            level="provenance",
            source="PEP 740 endpoint",
            identity=publisher.get("repository") or publisher.get("email") or "",
            detail=(f"{len(document.get('attestation_bundles') or [])} bundle(s); "
                    f"publisher kind: {publisher.get('kind') or 'unknown'}"),
        )

    def registry_bundles(self, release: Release) -> List[dict]:
        document = self._provenance_document(release)
        if not document:
            return []

        import json as _json

        from pypi_attestations import Attestation

        bundles = []
        for group in document.get("attestation_bundles") or []:
            for attestation in group.get("attestations") or []:
                try:
                    converted = Attestation.model_validate(attestation).to_bundle()
                    bundles.append(_json.loads(converted.to_json()))
                except Exception:
                    continue
        return bundles

    def expected_publisher(self, release: Release) -> str:
        recorded = self.registry_evidence(release).identity
        return recorded or release.declared_repository

    def registry_publisher(self, release: Release) -> str:
        return self.registry_evidence(release).identity

    def registry_publisher_records(self, release: Release) -> List[Dict[str, str]]:
        from ..identity import GITHUB_ACTIONS, GITLAB_CI, GOOGLE

        document = self._provenance_document(release) or {}
        records = []
        for group in document.get("attestation_bundles") or []:
            publisher = group.get("publisher") or {}
            kind = str(publisher.get("kind") or "").lower()
            repository = str(publisher.get("repository") or "")
            email = str(publisher.get("email") or "")
            if kind in ("github", "gitlab") and repository:
                records.append({"repository": repository,
                                "issuer": GITHUB_ACTIONS if kind == "github"
                                else GITLAB_CI})
            elif kind == "google" and email:
                records.append({"subject": email, "issuer": GOOGLE})
        return records

    def published_digest(self, release: Release, algorithm: str) -> Optional[str]:
        if algorithm != "sha256":
            return None
        document = self.client.get_json(
            f"{API}/{quote(release.package)}/{quote(release.version)}/json"
        )
        artifact = _preferred_file((document or {}).get("urls") or [])
        return (artifact or {}).get("digests", {}).get("sha256")

    def verifier_command(self, release: Release) -> Optional[List[str]]:
        commands = self.verifier_commands(release)
        return commands[-1][1] if commands else None

    def verifier_commands(self, release: Release) -> List[Tuple[str, List[str]]]:
        if not release.artifact_url:
            return []
        prefix = [sys.executable, "-m", "pypi_attestations", "verify", "pypi"]
        commands: List[Tuple[str, List[str]]] = []
        if release.declared_repository:
            commands.append(("1", prefix + [
                "--repository", _repository_url(release.declared_repository),
                release.artifact_url,
            ]))

        publisher = _publisher_of(self._provenance_document(release) or {})
        repository = publisher.get("repository") or ""
        email = publisher.get("email") or ""
        kind = (publisher.get("kind") or "").lower()
        if repository and repository.lower() != release.declared_repository.lower():
            commands.append(("2", prefix + [
                "--repository", _repository_url(repository), release.artifact_url,
            ]))
        if kind == "google" and email:
            commands.append(("3", prefix + [
                "--gcp-service-account", email, release.artifact_url,
            ]))
        return commands

    def _provenance_document(self, release: Release) -> Optional[Dict[str, object]]:
        filename = str(release.metadata.get("filename") or "")
        if not filename:
            return None
        return self.client.get_json(
            PROVENANCE.format(
                package=quote(release.package),
                version=quote(release.version),
                filename=quote(filename),
            )
        )

def _preferred_file(files):
    for kind in ("bdist_wheel", "sdist"):
        for entry in files:
            if entry.get("packagetype") == kind:
                return entry
    return files[0] if files else None

def _repository_of(info) -> str:
    candidates = [value for value in (info.get("project_urls") or {}).values() if value]
    if info.get("home_page"):
        candidates.append(info["home_page"])

    fallback = ""
    for candidate in candidates:
        repository = _github_path(candidate)
        if not repository:
            continue
        if SPONSORS in f"/{repository}/":
            fallback = fallback or repository
            continue
        return repository
    return fallback

def _github_path(url: str) -> str:
    import re

    match = re.search(r"github\.com[:/]+([^/]+)/([^/#?]+)", str(url or ""))
    if not match:
        return ""
    name = match.group(2)
    return f"{match.group(1)}/{name[:-4] if name.endswith('.git') else name}"

def _publisher_of(document) -> Dict[str, str]:
    for bundle in document.get("attestation_bundles") or []:
        publisher = bundle.get("publisher") or {}
        if publisher:
            return {
                "kind": str(publisher.get("kind") or ""),
                "repository": str(publisher.get("repository") or ""),
                "email": str(publisher.get("email") or ""),
            }
    return {}

def _repository_url(repository: str) -> str:
    return repository if "://" in repository else f"https://github.com/{repository}"
