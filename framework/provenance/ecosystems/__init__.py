from __future__ import annotations

from typing import Dict, List, Type

from ..http import Client
from .base import Ecosystem, RegistryEvidence, Release
from .crates import Crates
from .golang import GoModules
from .maven import Maven
from .npm import Npm
from .nuget import NuGet
from .packagist import Packagist
from .pypi import PyPI
from .rubygems import RubyGems

REGISTRY: Dict[str, Type[Ecosystem]] = {
    cls.name: cls
    for cls in (PyPI, Npm, RubyGems, Maven, NuGet, Packagist, GoModules, Crates)
}

GROUPS: Dict[str, List[str]] = {
    "A": ["pypi", "npm", "rubygems"],
    "B": ["maven", "nuget", "crates"],
    "C": ["packagist", "go"],
}

def load(name: str, client: Client) -> Ecosystem:
    try:
        return REGISTRY[name](client)
    except KeyError:
        raise KeyError(
            f"unknown ecosystem {name!r}; known: {', '.join(sorted(REGISTRY))}"
        ) from None

def names() -> List[str]:
    return list(REGISTRY)

def group_of(name: str) -> str:
    for group, members in GROUPS.items():
        if name in members:
            return group
    return "?"

__all__ = [
    "Ecosystem",
    "Release",
    "RegistryEvidence",
    "REGISTRY",
    "GROUPS",
    "load",
    "names",
    "group_of",
]
