from __future__ import annotations

import re
from typing import List, Optional

from .base import Ecosystem, Release, RegistryEvidence

CENTRAL = "https://repo1.maven.org/maven2"
SEARCH = "https://search.maven.org/solrsearch/select"

class Maven(Ecosystem):
    name = "maven"
    documented_level = "attribution"

    def resolve(self, package: str, version: Optional[str] = None) -> Release:
        if ":" not in package:
            return Release(package=package, version="")
        if version is None:
            version = self._latest_version(package) or ""
        if not version:
            return Release(package=package, version="")

        jar = self._path(package, version, "jar")
        return Release(
            package=package,
            version=version,
            artifact_url=jar,
            declared_repository=self._scm_repository(package, version),
            metadata={
                "pom_url": self._path(package, version, "pom"),
                "gpg_url": jar + ".asc",
                "sigstore_url": jar + ".sigstore.json",
            },
        )

    def registry_evidence(self, release: Release) -> RegistryEvidence:
        sigstore_url = str(release.metadata.get("sigstore_url") or "")
        if sigstore_url and self.client.request(sigstore_url).ok:
            return RegistryEvidence(
                True,
                "provenance",
                source=".jar.sigstore.json",
                detail="Sigstore bundle served alongside the artifact",
            )

        gpg_url = str(release.metadata.get("gpg_url") or "")
        if gpg_url and self.client.request(gpg_url).ok:
            return RegistryEvidence(
                True,
                "attribution",
                source=".jar.asc",
                detail="detached OpenPGP signature",
            )
        return RegistryEvidence(False, "attribution", source=".jar.asc")

    def verifier_command(self, release: Release) -> Optional[List[str]]:
        return ["gpg", "--verify", "<artifact>.jar.asc", "<artifact>.jar"]

    def _scm_repository(self, package: str, version: str) -> str:
        body = self.client.get_bytes(self._path(package, version, "pom"))
        if body is None:
            return ""
        pom = body.decode("utf-8", "replace")
        block = re.search(r"<scm>(.*?)</scm>", pom, re.S)
        if not block:
            return ""
        match = re.search(r"github\.com[:/]+([^/<]+)/([^/<\s]+)", block.group(1))
        if not match:
            return ""
        name = match.group(2)
        for suffix in (".git", "/"):
            if name.endswith(suffix):
                name = name[: -len(suffix)]
        return f"{match.group(1)}/{name}"

    def _latest_version(self, package: str) -> Optional[str]:
        group, artifact = package.split(":", 1)
        document = self.client.get_json(
            f"{SEARCH}?q=g:%22{group}%22+AND+a:%22{artifact}%22"
            "&core=gav&rows=1&sort=timestamp+desc&wt=json"
        )
        docs = ((document or {}).get("response") or {}).get("docs") or []
        return docs[0].get("v") if docs else None

    @staticmethod
    def _path(package: str, version: str, extension: str) -> str:
        group, artifact = package.split(":", 1)
        return (
            f"{CENTRAL}/{group.replace('.', '/')}/{artifact}/{version}/"
            f"{artifact}-{version}.{extension}"
        )
