from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from ..http import Client

@dataclass(frozen=True)
class Release:
    package: str
    version: str
    artifact_url: str = ""
    declared_repository: str = ""
    published_at: str = ""
    metadata: Dict[str, object] = field(default_factory=dict)

    @property
    def resolved(self) -> bool:
        return bool(self.version)

@dataclass(frozen=True)
class RegistryEvidence:
    present: bool
    level: str
    source: str = ""
    identity: str = ""
    detail: str = ""
    exposed: Optional[bool] = None

class Ecosystem(abc.ABC):
    name: str = ""

    documented_level: str = "integrity"

    verifier_requires_project: bool = False

    answers_publisher_authorization: bool = False

    digest_algorithms: Sequence[str] = ("sha256", "sha512")

    def __init__(self, client: Client) -> None:
        self.client = client

    @abc.abstractmethod
    def resolve(self, package: str, version: Optional[str] = None) -> Release:
        pass

    @abc.abstractmethod
    def registry_evidence(self, release: Release) -> RegistryEvidence:
        pass

    def artifact_url(self, release: Release) -> str:
        return release.artifact_url

    def published_digest(self, release: Release, algorithm: str) -> Optional[str]:
        return None

    def expected_publisher(self, release: Release) -> str:
        return ""

    def registry_publisher(self, release: Release) -> str:
        return self.expected_publisher(release)

    def registry_publisher_records(self, release: Release) -> List[Dict[str, str]]:
        return []

    def registry_bundles(self, release: Release) -> List[dict]:
        return []

    def log_hints(self, release: Release) -> List[int]:
        return []

    def verifier_command(self, release: Release) -> Optional[List[str]]:
        return None

    def verifier_commands(self, release: Release) -> List[Tuple[str, List[str]]]:
        command = self.verifier_command(release)
        return [("", command)] if command else []

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.name}>"
