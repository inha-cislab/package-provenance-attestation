from __future__ import annotations

import csv
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import platform
import shutil
import subprocess

from .. import collect, ecosystems
from ..attestor import classify_for_release
from ..http import Client
from ..rekor import RekorClient
from .registry import crates, go, maven, nuget
from .registry_verifier import verify as verify_registry_tool


REGISTRY_MODULES = {"crates": crates, "go": go, "maven": maven, "nuget": nuget}


def load_coordinates(path: Path, ecosystem: str) -> list[dict]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        required = {"ecosystem", "package", "version"}
        missing = required.difference(reader.fieldnames or ())
        if missing:
            raise ValueError(f"coordinate CSV lacks column(s): {', '.join(sorted(missing))}")
        rows = []
        for row in reader:
            if (row.get("ecosystem") or "").strip().lower() != ecosystem:
                continue
            row = {key: value.strip() if isinstance(value, str) else value
                   for key, value in row.items()}
            row["ecosystem"] = ecosystem
            if not row.get("package"):
                raise ValueError("coordinate CSV contains an empty package name")
            if row.get("rank"):
                int(row["rank"])
            rows.append(row)
    if not rows:
        raise ValueError(f"no {ecosystem} coordinates in {path}")
    return rows


def toolchain_version(ecosystem: str) -> str:
    commands = {"go": ["go", "version"], "maven": ["gpg", "--version"],
                "nuget": ["dotnet", "--version"]}
    if ecosystem == "crates":
        return f"Python {platform.python_version()} hashlib.sha256"
    command = commands[ecosystem]
    if shutil.which(command[0]) is None:
        return f"{command[0]} not found"
    completed = subprocess.run(command, capture_output=True, text=True,
                               check=False, timeout=30)
    output = completed.stdout.strip() or completed.stderr.strip()
    return output.splitlines()[0] if output else f"{command[0]} version unknown"


def verify_package(ecosystem: str, row: dict, *, path: str,
                   work_root: Path, resolve_version: bool = False) -> dict:
    if ecosystem not in ecosystems.names():
        raise ValueError(f"unknown ecosystem: {ecosystem}")
    if path not in ("registry", "log"):
        raise ValueError(f"unknown verification path: {path}")
    if row.get("ecosystem", ecosystem) != ecosystem:
        raise ValueError("input ecosystem does not match the selected ecosystem")
    row = dict(row, ecosystem=ecosystem)
    record = {"ecosystem": ecosystem, "package": row["package"],
              "version": row.get("version") or "", "path": path}
    if row.get("rank"):
        record["rank"] = int(row["rank"])
    try:
        adapter = ecosystems.load(ecosystem, Client())
        if not row.get("version") and resolve_version:
            row["version"] = adapter.resolve(row["package"]).version
            record["version"] = row["version"]
        if not row.get("version"):
            return {**record, "outcome": "unresolved",
                    "detail": "no release version was supplied or resolved"}
        if path == "registry" and ecosystem not in REGISTRY_MODULES:
            return {**verify_registry_tool(adapter, row["package"], row["version"]).as_dict(),
                    **record}
        if path == "registry":
            work_root = work_root.resolve()
            work_root.mkdir(parents=True, exist_ok=True)
            module = REGISTRY_MODULES[ecosystem]
            if ecosystem == "crates":
                result = module.verify_crate(row)
            else:
                result = getattr(module, f"verify_{ecosystem}")(row, work_root=work_root)
            return {**result, **record}
        rekor = RekorClient(adapter.client)
        observation = collect.observe_log(adapter, rekor, row["package"], row["version"])
        if observation.present:
            release = adapter.resolve(row["package"], row["version"])
            keys = adapter.registry_keys() if hasattr(adapter, "registry_keys") else {}
            collect.verify_log(adapter, rekor, observation,
                               classifier=lambda entry: classify_for_release(entry, adapter, release, keys))
            outcome = "verified" if observation.verified else "not verified"
        else:
            outcome = "no evidence" if observation.status == "not found" else observation.status
        return {**observation.as_dict(), **record, "outcome": outcome}
    except Exception as error:
        return {**record, "outcome": "error", "detail": f"{type(error).__name__}: {error}"}


def run(ecosystem: str, rows, *, path: str, work_root: Path,
        workers: int = 6, resolve_version: bool = False, progress=None) -> list[dict]:
    if workers < 1:
        raise ValueError("workers must be positive")
    selected = list(rows)
    if any(row.get("ecosystem", ecosystem) != ecosystem for row in selected):
        raise ValueError("all input rows must belong to the selected ecosystem")
    version = toolchain_version(ecosystem) if path == "registry" and ecosystem in REGISTRY_MODULES else None

    def verify(row):
        result = verify_package(ecosystem, row, path=path, work_root=work_root,
                                resolve_version=resolve_version)
        if version:
            result["toolchain"] = version
        return result

    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for completed, result in enumerate(pool.map(verify, selected), start=1):
            results.append(result)
            if progress:
                progress(completed, len(selected), result)
    return results
