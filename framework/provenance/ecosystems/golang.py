from __future__ import annotations

from typing import List, Optional

from .base import Ecosystem, Release, RegistryEvidence

PROXY = "https://proxy.golang.org"
SUMDB = "https://sum.golang.org"

class GoModules(Ecosystem):
    name = "go"
    documented_level = "integrity"
    verifier_requires_project = True

    def resolve(self, package: str, version: Optional[str] = None) -> Release:
        escaped = escape(package)
        if version is None:
            body = self.client.get_bytes(f"{PROXY}/{escaped}/@latest")
            if body is None:
                return Release(package=package, version="")
            import json

            version = (json.loads(body) or {}).get("Version", "")
        if not version:
            return Release(package=package, version="")

        return Release(
            package=package,
            version=version,
            artifact_url=f"{PROXY}/{escaped}/@v/{escape(version)}.zip",
        )

    def registry_evidence(self, release: Release) -> RegistryEvidence:
        body = self.client.get_bytes(
            f"{SUMDB}/lookup/{escape(release.package)}@{escape(release.version)}"
        )
        if body is None:
            return RegistryEvidence(False, "integrity", source="sum.golang.org")
        return RegistryEvidence(
            present=True,
            level="integrity",
            source="sum.golang.org",
            detail="module hash recorded in the checksum database",
        )

    def verifier_command(self, release: Release) -> Optional[List[str]]:
        return ["go", "mod", "verify"]

def escape(value: str) -> str:
    return "".join(f"!{c.lower()}" if "A" <= c <= "Z" else c for c in value)
