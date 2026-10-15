from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from ..ecosystems import Ecosystem

@dataclass
class VerificationRun:
    ecosystem: str
    package: str
    version: str
    outcome: str
    command: List[str] = field(default_factory=list)
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    detail: str = ""
    tier: str = ""
    attempts: List[Dict[str, object]] = field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        return self.outcome == "verified"

    def as_dict(self) -> dict:
        return asdict(self)

def verify(
    ecosystem: Ecosystem,
    package: str,
    version: Optional[str] = None,
    *,
    timeout: float = 600.0,
) -> VerificationRun:
    release = ecosystem.resolve(package, version)
    if not release.resolved:
        return VerificationRun(
            ecosystem.name, package, "", "unresolved",
            detail="package or version did not resolve",
        )

    if ecosystem.name == "npm":
        from .registry.npm import verify_release

        return VerificationRun(ecosystem.name, release.package, release.version,
                               **verify_release(ecosystem, release))

    commands = ecosystem.verifier_commands(release)
    if not commands:
        return VerificationRun(
            ecosystem.name, release.package, release.version, "no tool",
            detail="the ecosystem documents no consumer verification tool "
                   "at its highest level",
        )
    if ecosystem.verifier_requires_project:
        return VerificationRun(
            ecosystem.name, release.package, release.version, "manual",
            command=commands[0][1],
            detail="run the command from a prepared project directory; "
                   "the tool verifies a dependency tree rather than one package",
        )
    if any(
        re.search(r"<[^>]+>", part)
        for _, command in commands for part in command
    ):
        return VerificationRun(
            ecosystem.name, release.package, release.version, "manual",
            command=commands[0][1],
            detail="the tool needs a prepared artifact on disk",
        )
    if shutil.which(commands[0][1][0]) is None:
        return VerificationRun(
            ecosystem.name, release.package, release.version, "tool missing",
            command=commands[0][1],
            detail=f"{commands[0][1][0]} is not installed",
        )

    attempts = []
    for tier, command in commands:
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, timeout=timeout
            )
        except subprocess.TimeoutExpired:
            attempts.append({"tier": tier, "command": command, "outcome": "timeout"})
            continue

        outcome = _outcome(
            completed.returncode, completed.stdout + completed.stderr
        )
        attempts.append(
            {
                "tier": tier,
                "command": command,
                "outcome": outcome,
                "exit_code": completed.returncode,
            }
        )
        if outcome == "verified":
            return VerificationRun(
                ecosystem=ecosystem.name,
                package=release.package,
                version=release.version,
                outcome=outcome,
                command=command,
                exit_code=completed.returncode,
                stdout=completed.stdout[-4000:],
                stderr=completed.stderr[-4000:],
                tier=tier,
                attempts=attempts,
            )

    return VerificationRun(
        ecosystem=ecosystem.name,
        package=release.package,
        version=release.version,
        outcome=attempts[-1]["outcome"] if attempts else "timeout",
        command=command,
        exit_code=completed.returncode if attempts and "exit_code" in attempts[-1] else None,
        stdout=completed.stdout[-4000:] if attempts and "exit_code" in attempts[-1] else "",
        stderr=completed.stderr[-4000:] if attempts and "exit_code" in attempts[-1] else "",
        tier=tier,
        attempts=attempts,
    )

def _outcome(exit_code: int, output: str) -> str:
    lowered = output.lower()
    if exit_code == 0:
        return "verified"
    if "was not found" in lowered and "provenance" in lowered:
        return "no attestation"
    if "signed by repository" in lowered:
        return "publisher mismatch"
    if "service account" in lowered:
        return "identity refused"
    if "only supported for" in lowered or "unsupported" in lowered:
        return "unsupported entry type"
    return "failed"
