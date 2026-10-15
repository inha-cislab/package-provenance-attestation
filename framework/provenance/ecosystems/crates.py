from __future__ import annotations

import json
from typing import List, Optional

from .base import Ecosystem, Release, RegistryEvidence

INDEX = "https://index.crates.io"
DOWNLOAD = "https://static.crates.io/crates/{name}/{name}-{version}.crate"

class Crates(Ecosystem):
    name = "crates"
    documented_level = "integrity"

    def resolve(self, package: str, version: Optional[str] = None) -> Release:
        body = self.client.get_bytes(f"{INDEX}/{index_path(package)}")
        if body is None:
            return Release(package=package, version="")

        releases = [
            json.loads(line)
            for line in body.decode("utf-8").splitlines()
            if line.strip()
        ]
        if version is not None:
            releases = [item for item in releases if item.get("vers") == version]
        live = [item for item in releases if not item.get("yanked")] or releases
        chosen = live[-1] if live else {}
        if not chosen:
            return Release(package=package, version="")

        return Release(
            package=package,
            version=chosen.get("vers", ""),
            artifact_url=DOWNLOAD.format(name=package, version=chosen.get("vers", "")),
            metadata={"checksum": chosen.get("cksum", "")},
        )

    def registry_evidence(self, release: Release) -> RegistryEvidence:
        checksum = str(release.metadata.get("checksum") or "")
        return RegistryEvidence(
            present=bool(checksum),
            level="integrity",
            source="index checksum",
            detail=checksum,
        )

    def published_digest(self, release: Release, algorithm: str) -> Optional[str]:
        if algorithm != "sha256":
            return None
        return str(release.metadata.get("checksum") or "") or None

    def verifier_command(self, release: Release) -> Optional[List[str]]:
        return ["cargo", "install", "--locked", "<crate>"]

def index_path(name: str) -> str:
    lowered = name.lower()
    if len(lowered) <= 2:
        return f"{len(lowered)}/{lowered}"
    if len(lowered) == 3:
        return f"3/{lowered[0]}/{lowered}"
    return f"{lowered[:2]}/{lowered[2:4]}/{lowered}"
