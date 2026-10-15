from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Dict
import urllib.parse

from .common import download_file


def verify_nuget(row: Dict[str, str], *, work_root: Path) -> dict:
    package = row["package"]
    version = row["version"]
    name = package.lower()
    stored_version = version.split("+", 1)[0].lower()
    quoted_name = urllib.parse.quote(name, safe="")
    quoted_version = urllib.parse.quote(stored_version, safe="")
    url = (
        "https://api.nuget.org/v3-flatcontainer/"
        f"{quoted_name}/{quoted_version}/{quoted_name}.{quoted_version}.nupkg"
    )
    expected_sha256 = (row.get("digest_sha256") or "").lower()
    record = {
        "ecosystem": "nuget",
        "rank": int(row["rank"]) if row.get("rank") else None,
        "package": package,
        "version": version,
        "level": "attribution",
        "source": ".signature.p7s verified by dotnet nuget verify",
        "artifact_url": url,
        "expected_sha256": expected_sha256,
    }
    dotnet = shutil.which("dotnet")
    if dotnet is None:
        return {
            **record,
            "outcome": "tool missing",
            "detail": "dotnet not found",
        }

    work_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="package-", dir=work_root
    ) as temporary:
        package_path = Path(temporary) / f"{name}.{stored_version}.nupkg"
        try:
            actual_sha256, size = download_file(url, package_path)
        except Exception as error:
            return {
                **record,
                "outcome": "error",
                "detail": f"{type(error).__name__}: {error}",
            }

        command = [
            dotnet,
            "nuget",
            "verify",
            str(package_path),
            "--all",
            "--verbosity",
            "minimal",
        ]
        env = {**os.environ, "DOTNET_CLI_UI_LANGUAGE": "en"}
        try:
            completed = subprocess.run(
                command,
                cwd=work_root,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                **record,
                "outcome": "timeout",
                "command": command,
                "actual_sha256": actual_sha256,
                "artifact_bytes": size,
                "detail": "dotnet nuget verify exceeded 300 seconds",
            }

    bytes_match = not expected_sha256 or actual_sha256 == expected_sha256
    signature_valid = completed.returncode == 0
    return {
        **record,
        "outcome": "verified"
        if bytes_match and signature_valid
        else "verification failed",
        "command": command,
        "exit_code": completed.returncode,
        "actual_sha256": actual_sha256,
        "bytes_match": bytes_match,
        "signature_valid": signature_valid,
        "artifact_bytes": size,
        "stdout": completed.stdout[-8000:],
        "stderr": completed.stderr[-8000:],
        "detail": "",
    }
