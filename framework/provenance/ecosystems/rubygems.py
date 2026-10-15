from __future__ import annotations

import json
import re
from typing import List, Optional

from ..http import quote
from .base import Ecosystem, Release, RegistryEvidence

API = "https://rubygems.org/api/v1"
ATTESTATIONS = API + "/attestations/{package}-{version}.json"
PAGE = "https://rubygems.org/gems/{package}/versions/{version}"
DOWNLOAD = "https://rubygems.org/downloads/{package}-{version}.gem"

LOG_INDEX = re.compile(r"logIndex=(\d+)")
SOURCE_COMMIT = re.compile(r"Source Commit\s*</?[^>]*>?\s*([\w.-]+/[\w.-]+)@")

class RubyGems(Ecosystem):
    name = "rubygems"
    documented_level = "provenance"
    answers_publisher_authorization = True

    def resolve(self, package: str, version: Optional[str] = None) -> Release:
        document = self.client.get_json(f"{API}/gems/{quote(package)}.json")
        if not document:
            return Release(package=package, version="")

        chosen = version or document.get("version") or ""
        return Release(
            package=package,
            version=chosen,
            artifact_url=DOWNLOAD.format(package=quote(package), version=quote(chosen)),
            declared_repository=_repository_of(document),
            metadata={"sha256": self._version_sha(package, chosen)},
        )

    def registry_evidence(self, release: Release) -> RegistryEvidence:
        bundles = self._attestation_response(release)
        return RegistryEvidence(
            present=bool(bundles),
            level="provenance",
            source="attestations API",
            identity="",
            detail=f"{len(bundles)} bundle(s)",
        )

    def registry_bundles(self, release: Release) -> List[dict]:
        bundles = []
        for item in self._attestation_response(release):
            bundle = item.get("bundle") if isinstance(item, dict) else None
            if isinstance(bundle or item, dict):
                bundles.append(bundle or item)
        return bundles

    def expected_publisher(self, release: Release) -> str:
        body = self.client.get_bytes(
            PAGE.format(package=quote(release.package), version=quote(release.version))
        )
        if body is None:
            return ""
        page = body.decode("utf-8", "replace")
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page))
        match = re.search(r"Source Commit\s+([\w.-]+/[\w.-]+)@", text)
        return match.group(1) if match else ""

    def log_hints(self, release: Release) -> List[int]:
        body = self.client.get_bytes(
            PAGE.format(package=quote(release.package), version=quote(release.version))
        )
        if body is None:
            return []
        return [int(value) for value in
                dict.fromkeys(LOG_INDEX.findall(body.decode("utf-8", "replace")))]

    def registry_publisher_records(self, release: Release) -> List[dict]:
        from ..identity import GITHUB_ACTIONS

        repository = self.registry_publisher(release)
        return [{"repository": repository, "issuer": GITHUB_ACTIONS}] if repository else []

    def published_digest(self, release: Release, algorithm: str) -> Optional[str]:
        if algorithm != "sha256":
            return None
        return str(release.metadata.get("sha256") or "") or None

    def _version_sha(self, package: str, version: str) -> str:
        versions = self.client.get_json(f"{API}/versions/{quote(package)}.json") or []
        matching = [item for item in versions if item.get("number") == version]
        ruby = [item for item in matching if (item.get("platform") or "ruby") == "ruby"]
        chosen = (ruby or matching or [{}])[0]
        return chosen.get("sha") or ""

    def _attestation_response(self, release: Release) -> List[dict]:
        response = self.client.request(
            ATTESTATIONS.format(
                package=quote(release.package), version=quote(release.version)
            )
        )
        if not response.ok:
            return []
        try:
            document = response.json()
        except (ValueError, json.JSONDecodeError):
            return []
        return document if isinstance(document, list) else []

def _repository_of(document) -> str:
    for field in ("source_code_uri", "homepage_uri", "project_uri"):
        match = re.search(
            r"github\.com[:/]+([^/]+)/([^/#?]+)", str(document.get(field) or "")
        )
        if match:
            name = match.group(2)
            return f"{match.group(1)}/{name[:-4] if name.endswith('.git') else name}"
    return ""
