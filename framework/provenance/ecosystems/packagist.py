from __future__ import annotations

from typing import List, Optional

from .base import Ecosystem, Release, RegistryEvidence

REPO = "https://repo.packagist.org/p2/{package}.json"

PRERELEASE_MARKERS = ("dev", "alpha", "beta", "rc")

class Packagist(Ecosystem):
    name = "packagist"
    documented_level = "integrity"

    def resolve(self, package: str, version: Optional[str] = None) -> Release:
        document = self.client.get_json(REPO.format(package=package))
        releases = ((document or {}).get("packages") or {}).get(package) or []
        if not releases:
            return Release(package=package, version="")

        if version is not None:
            chosen = next(
                (item for item in releases if item.get("version") == version), {}
            )
        else:
            stable = [
                item
                for item in releases
                if not any(
                    marker in (item.get("version") or "").lower()
                    for marker in PRERELEASE_MARKERS
                )
            ]
            chosen = (stable or releases)[0]
        if not chosen:
            return Release(package=package, version="")

        dist = chosen.get("dist") or {}
        return Release(
            package=package,
            version=chosen.get("version", ""),
            artifact_url=dist.get("url", ""),
            declared_repository=package,
            published_at=chosen.get("time", ""),
            metadata={
                "shasum": dist.get("shasum", ""),
                "shasum_exposed": "shasum" in dist,
                "type": dist.get("type", ""),
            },
        )

    def registry_evidence(self, release: Release) -> RegistryEvidence:
        shasum = str(release.metadata.get("shasum") or "")
        return RegistryEvidence(
            present=bool(shasum),
            level="integrity",
            source="dist.shasum",
            detail=shasum or "dist record present, shasum empty",
            exposed=bool(release.metadata.get("shasum_exposed")),
        )

    def published_digest(self, release: Release, algorithm: str) -> Optional[str]:
        return None

    def verifier_command(self, release: Release) -> Optional[List[str]]:
        return None
