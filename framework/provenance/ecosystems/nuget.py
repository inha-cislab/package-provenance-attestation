from __future__ import annotations

from typing import List, Optional

from .base import Ecosystem, Release, RegistryEvidence

FLAT = "https://api.nuget.org/v3-flatcontainer"
SIGNATURE_MEMBER = b".signature.p7s"

class NuGet(Ecosystem):
    name = "nuget"
    documented_level = "attribution"

    def resolve(self, package: str, version: Optional[str] = None) -> Release:
        name = package.lower()
        if version is None:
            index = self.client.get_json(f"{FLAT}/{name}/index.json") or {}
            published = index.get("versions") or []
            stable = [item for item in published if "-" not in item]
            version = (stable or published or [""])[-1]
        if not version:
            return Release(package=package, version="")

        stored = version.split("+", 1)[0].lower()
        return Release(
            package=package,
            version=version,
            artifact_url=f"{FLAT}/{name}/{stored}/{name}.{stored}.nupkg",
        )

    def registry_evidence(self, release: Release) -> RegistryEvidence:
        archive = self.client.get_bytes(release.artifact_url)
        if archive is None:
            return RegistryEvidence(False, "attribution", source=".nupkg")
        return RegistryEvidence(
            present=SIGNATURE_MEMBER in archive,
            level="attribution",
            source=".signature.p7s",
            detail="repository countersignature inside the package",
        )

    def verifier_command(self, release: Release) -> Optional[List[str]]:
        return ["nuget", "verify", "-Signatures", "<package>.nupkg"]
