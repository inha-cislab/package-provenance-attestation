from __future__ import annotations

import json
from typing import Dict
import urllib.parse

from .common import read_bytes, stream_sha256


def verify_crate(row: Dict[str, str]) -> dict:
    package = row["package"]
    version = row["version"]
    quoted_package = urllib.parse.quote(package, safe="")
    quoted_version = urllib.parse.quote(version, safe="")
    artifact_url = (
        "https://static.crates.io/crates/"
        f"{quoted_package}/{quoted_package}-{quoted_version}.crate"
    )
    index_url = f"https://index.crates.io/{crate_index_path(package)}"
    fixed_sha256 = (row.get("digest_sha256") or "").lower()
    record = {
        "ecosystem": "crates",
        "rank": int(row["rank"]) if row.get("rank") else None,
        "package": package,
        "version": version,
        "level": "integrity",
        "source": "crates.io index checksum",
        "artifact_url": artifact_url,
        "index_url": index_url,
        "fixed_sha256": fixed_sha256,
    }
    try:
        releases = [
            json.loads(line)
            for line in read_bytes(index_url).decode("utf-8").splitlines()
            if line.strip()
        ]
        release = next(
            (item for item in releases if item.get("vers") == version), None
        )
        index_sha256 = str((release or {}).get("cksum") or "").lower()
    except Exception as error:
        return {
            **record,
            "outcome": "error",
            "detail": f"could not read index: {type(error).__name__}: {error}",
        }
    if not index_sha256:
        return {
            **record,
            "outcome": "no evidence",
            "detail": "the selected version has no index checksum",
        }
    try:
        actual, size = stream_sha256(artifact_url)
    except Exception as error:
        return {
            **record,
            "outcome": "error",
            "detail": f"{type(error).__name__}: {error}",
        }
    index_matches = actual == index_sha256
    fixed_bytes_match = not fixed_sha256 or actual == fixed_sha256
    return {
        **record,
        "outcome": "verified"
        if index_matches and fixed_bytes_match
        else "digest mismatch",
        "index_sha256": index_sha256,
        "actual_sha256": actual,
        "index_matches": index_matches,
        "fixed_bytes_match": fixed_bytes_match,
        "artifact_bytes": size,
        "detail": "",
    }


def crate_index_path(name: str) -> str:
    lowered = name.lower()
    if len(lowered) <= 2:
        return f"{len(lowered)}/{lowered}"
    if len(lowered) == 3:
        return f"3/{lowered[0]}/{lowered}"
    return f"{lowered[:2]}/{lowered[2:4]}/{lowered}"
