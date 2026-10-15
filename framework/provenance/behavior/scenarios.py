from __future__ import annotations

import re
import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence
from urllib.parse import urlsplit

SCENARIOS: Dict[str, Dict[str, Sequence[str]]] = {
    "pypi": {
        "default": ("pip", "install", "--no-cache-dir", "--target", ".", "{package}=={version}"),
        "bad-input": ("python", "-m", "pypi_attestations", "verify", "pypi", "--repository", "{mismatched_repository}", "{artifact}"),
        "missing-entry": ("python", "-m", "pypi_attestations", "verify", "pypi", "--repository", "{repository}", "{missing_artifact}"),
        "privacy": ("python", "-m", "provenance.behavior.python_trace", "pypi_attestations", "verify", "-v", "pypi", "--repository", "{repository}", "{artifact}"),
    },
    "npm": {
        "default": ("npm", "install", "--no-audit", "--no-fund", "{package}@{version}"),
        "bad-input": ("python", "-m", "provenance.behavior.npm_external", "--out", "{workdir}"),
        "missing-entry": ("npm", "audit", "signatures", "--loglevel=http"),
        "privacy": ("npm", "audit", "signatures", "--loglevel=http"),
    },
    "rubygems": {
        "default": ("gem", "install", "--no-document", "--install-dir", ".", "{package}", "-v", "{version}"),
        "bad-input": ("gem", "install", "--local", "--trust-policy", "HighSecurity", "{tampered_artifact}"),
        "privacy": ("gem", "install", "--local", "--trust-policy", "HighSecurity", "{artifact}"),
    },
    "maven": {
        "default": ("mvn", "-q", "-B", "dependency:get", "-Dartifact={package}:{version}"),
        "bad-input": ("gpg", "--verify", "{signature}", "{tampered_artifact}"),
        "privacy": ("gpg", "--verify", "{signature}", "{artifact}"),
    },
    "nuget": {
        "default": ("dotnet", "add", "package", "{package}", "--version", "{version}"),
        "bad-input": ("dotnet", "nuget", "verify", "{tampered_artifact}", "--all"),
        "privacy": ("dotnet", "nuget", "verify", "{artifact}", "--all"),
    },
    "packagist": {
        "default": ("composer", "require", "--no-interaction", "{package}:{version}"),
        "bad-input": ("composer", "install", "--no-interaction", "-vvv"),
    },
    "go": {
        "default": ("go", "mod", "download", "{package}@{version}"),
        "bad-input": ("go", "mod", "verify"),
        "privacy": ("go", "mod", "verify"),
    },
    "crates": {
        "default": ("cargo", "build", "--verbose"),
        "bad-input": ("python", "-m", "provenance.behavior.cargo_external", "--out", "{workdir}"),
    },
}

URL = re.compile(r"https?://[^\s'\"<>]+")


@dataclass
class ScenarioRun:
    ecosystem: str
    scenario: str
    command: List[str]
    exit_code: Optional[int]
    domains: List[str] = field(default_factory=list)
    requests: List[dict] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    trace_file: str = ""
    detail: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def command_for(
    ecosystem: str,
    scenario: str,
    values: Mapping[str, str],
) -> List[str]:
    try:
        template = SCENARIOS[ecosystem][scenario]
    except KeyError:
        return []
    required = {
        name
        for part in template
        for name in re.findall(r"\{([a-z_]+)\}", part)
    }
    if any(not values.get(name) for name in required):
        return []
    command = [part.format(**values) for part in template]
    if command[0] == "python":
        command[0] = sys.executable
    return command


def run_scenario(
    ecosystem: str,
    scenario: str,
    values: Mapping[str, str],
    *,
    workdir: Optional[str] = None,
    timeout: float = 900.0,
    trace_file: Optional[str] = None,
) -> ScenarioRun:
    command = command_for(ecosystem, scenario, values)
    if not command:
        return ScenarioRun(
            ecosystem,
            scenario,
            [],
            None,
            detail="the scenario is not applicable or a required input is missing",
        )
    if shutil.which(command[0]) is None:
        return ScenarioRun(
            ecosystem,
            scenario,
            command,
            None,
            detail=f"{command[0]} is not installed",
        )
    executed = command
    env = os.environ.copy()
    if ecosystem == 'npm' and scenario == 'privacy':
        hook = Path(__file__).with_name('node_trace.cjs').resolve()
        env['NODE_OPTIONS'] = (env.get('NODE_OPTIONS', '') + f' --require "{hook}"').strip()
    trace = ""
    if trace_file and shutil.which("strace"):
        trace = str(Path(trace_file).resolve())
        executed = [
            "strace",
            "-f",
            "-s",
            "300",
            "-e",
            "trace=connect,sendto,recvfrom",
            "-o",
            trace,
            *command,
        ]
    try:
        completed = subprocess.run(
            executed,
            cwd=workdir,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return ScenarioRun(
            ecosystem,
            scenario,
            command,
            None,
            trace_file=trace,
            detail=f"no result within {timeout:.0f}s",
        )
    output = completed.stdout + "\n" + completed.stderr
    if trace and Path(trace).exists():
        output += "\n" + Path(trace).read_text(encoding="utf-8", errors="replace")
    return ScenarioRun(
        ecosystem=ecosystem,
        scenario=scenario,
        command=command,
        exit_code=completed.returncode,
        domains=domains_in(output),
        requests=requests_in(completed.stderr),
        stdout=completed.stdout[-12000:],
        stderr=completed.stderr[-12000:],
        trace_file=trace,
    )


def domains_in(text: str) -> List[str]:
    domains = {
        urlsplit(match.group(0).rstrip(".,);]")).hostname
        for match in URL.finditer(text)
    }
    for request in requests_in(text):
        host = request.get('host')
        if isinstance(host, str):
            domains.add(urlsplit('//' + host).hostname)
    return sorted(domain for domain in domains if domain)


def requests_in(text: str) -> List[dict]:
    records = []
    for line in text.splitlines():
        if not line.startswith('network-request '):
            continue
        try:
            record = json.loads(line[len('network-request '):])
        except ValueError:
            continue
        if isinstance(record, dict) and record.get('event') == 'request':
            records.append(record)
    return records
