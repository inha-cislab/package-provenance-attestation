from __future__ import annotations

from provenance.ecosystems.base import Release
from provenance.ecosystems.golang import GoModules
from provenance.verify.registry_verifier import verify


class StubEcosystem:
    def __init__(self, name, command, *, requires_project=False):
        self.name = name
        self.command = command
        self.verifier_requires_project = requires_project

    def resolve(self, package, version=None):
        return Release(package=package, version=version or "1.0.0")

    def verifier_commands(self, release):
        return [("test", self.command)]


def test_placeholder_inside_filename_is_manual_not_failed():
    ecosystem = StubEcosystem(
        "maven",
        ["gpg", "--verify", "<artifact>.jar.asc", "<artifact>.jar"],
    )

    result = verify(ecosystem, "group:artifact", "1.0.0")

    assert result.outcome == "manual"
    assert result.command[2] == "<artifact>.jar.asc"


def test_project_scoped_verifier_is_manual():
    ecosystem = StubEcosystem(
        "go", ["go", "mod", "verify"], requires_project=True
    )

    result = verify(ecosystem, "example.org/module", "v1.0.0")

    assert result.outcome == "manual"
    assert "prepared project directory" in result.detail


def test_go_adapter_marks_its_verifier_as_project_scoped():
    assert GoModules.verifier_requires_project is True
