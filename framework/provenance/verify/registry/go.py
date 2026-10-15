from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from typing import Dict
import zipfile

from .common import hash_file


def go_h1(path: Path) -> str:
    """Return Go's dirhash.HashZip(Hash1) value for a module ZIP."""
    summary = hashlib.sha256()
    with zipfile.ZipFile(path) as archive:
        infos = list(archive.infolist())
        names = [item.filename for item in infos]
        if any("\n" in name for name in names):
            raise ValueError("module ZIP contains a filename with a newline")
        by_name = {item.filename: item for item in infos}
        for name in sorted(names):
            with archive.open(by_name[name]) as handle:
                content = hashlib.sha256()
                while chunk := handle.read(1 << 20):
                    content.update(chunk)
            summary.update(f"{content.hexdigest()}  {name}\n".encode())
    return "h1:" + base64.b64encode(summary.digest()).decode("ascii")


def verify_go(row: Dict[str, str], *, work_root: Path) -> dict:
    package = row["package"]
    version = row["version"]
    record = {
        "ecosystem": "go",
        "rank": int(row["rank"]) if row.get("rank") else None,
        "package": package,
        "version": version,
        "level": "integrity",
        "source": "sum.golang.org via go mod download",
    }


    if not version:
        return {
            **record,
            "outcome": "unresolved",
            "detail": "no release version was supplied",
        }

    go = shutil.which("go")
    if go is None:
        return {**record, "outcome": "tool missing", "detail": "go not found"}

    cache = work_root / "gomodcache"
    gopath = work_root / "gopath"
    cache.mkdir(parents=True, exist_ok=True)
    gopath.mkdir(parents=True, exist_ok=True)
    command = [go, "mod", "download", "-json", f"{package}@{version}"]
    env = {
        **os.environ,
        "GOMODCACHE": str(cache),
        "GOPATH": str(gopath),
        "GOPROXY": "https://proxy.golang.org",
        "GOSUMDB": "sum.golang.org",
        "GONOSUMDB": "",
        "GONOPROXY": "",
        "GOPRIVATE": "",
        "GOTOOLCHAIN": "auto",
    }
    completed = None
    result = {}
    parse_error = None
    timed_out = False
    for attempt in range(1, 4):
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
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
            if attempt < 3:
                time.sleep(attempt)
                continue
            return {
                **record,
                "outcome": "timeout",
                "command": command,
                "detail": "go mod download exceeded 300 seconds",
            }

        try:
            result = json.loads(completed.stdout or "{}")
            parse_error = None
        except json.JSONDecodeError as error:
            parse_error = error
            result = {}
        if (
            parse_error is None
            and completed.returncode == 0
            and not result.get("Error")
        ):
            break
        if attempt < 3:
            time.sleep(attempt)
    assert completed is not None and not timed_out
    if parse_error is not None:
        return {
            **record,
            "outcome": "error",
            "command": command,
            "exit_code": completed.returncode,
            "stderr": completed.stderr[-4000:],
            "detail": f"invalid go JSON output: {parse_error}",
        }
    if completed.returncode != 0 or result.get("Error"):
        return {
            **record,
            "outcome": "error",
            "command": command,
            "exit_code": completed.returncode,
            "stderr": completed.stderr[-4000:],
            "detail": str(result.get("Error") or "go mod download failed"),
        }

    zip_path = Path(result.get("Zip") or "")
    expected_h1 = str(result.get("Sum") or "")
    if not zip_path.is_file() or not expected_h1:
        return {
            **record,
            "outcome": "error",
            "command": command,
            "exit_code": completed.returncode,
            "detail": "go returned neither a module ZIP nor an authenticated sum",
        }
    try:
        actual_h1 = go_h1(zip_path)
        actual_sha256 = hash_file(zip_path)
    except Exception as error:
        return {
            **record,
            "outcome": "error",
            "command": command,
            "exit_code": completed.returncode,
            "detail": f"{type(error).__name__}: {error}",
        }

    fixed_sha256 = (row.get("digest_sha256") or "").lower()
    h1_matches = actual_h1 == expected_h1
    fixed_bytes_match = not fixed_sha256 or actual_sha256 == fixed_sha256
    return {
        **record,
        "outcome": "verified"
        if h1_matches and fixed_bytes_match
        else "digest mismatch",
        "command": command,
        "exit_code": completed.returncode,
        "expected_h1": expected_h1,
        "actual_h1": actual_h1,
        "fixed_sha256": fixed_sha256,
        "actual_sha256": actual_sha256,
        "h1_matches": h1_matches,
        "fixed_bytes_match": fixed_bytes_match,
        "artifact_bytes": zip_path.stat().st_size,
        "detail": "",
    }
