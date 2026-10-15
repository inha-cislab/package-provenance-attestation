from __future__ import annotations

import hashlib
from pathlib import Path
import time
import urllib.request

USER_AGENT = "package-provenance/1.0"


def read_bytes(url: str, *, attempts: int = 3, timeout: int = 180) -> bytes:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": USER_AGENT}
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except Exception as error:
            last_error = error
            if attempt < attempts:
                time.sleep(attempt)
    assert last_error is not None
    raise last_error


def stream_sha256(url: str, *, attempts: int = 3) -> tuple[str, int]:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": USER_AGENT}
            )
            digest = hashlib.sha256()
            size = 0
            with urllib.request.urlopen(request, timeout=180) as response:
                while chunk := response.read(1 << 20):
                    digest.update(chunk)
                    size += len(chunk)
            return digest.hexdigest(), size
        except Exception as error:
            last_error = error
            if attempt < attempts:
                time.sleep(attempt)
    assert last_error is not None
    raise last_error


def download_file(url: str, path: Path, *, attempts: int = 3) -> tuple[str, int]:
    """Download *url* to *path* and return its SHA-256 and byte length."""
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": USER_AGENT}
            )
            digest = hashlib.sha256()
            size = 0
            with (
                urllib.request.urlopen(request, timeout=180) as response,
                path.open("wb") as output,
            ):
                while chunk := response.read(1 << 20):
                    digest.update(chunk)
                    output.write(chunk)
                    size += len(chunk)
            return digest.hexdigest(), size
        except Exception as error:
            last_error = error
            path.unlink(missing_ok=True)
            if attempt < attempts:
                time.sleep(attempt)
    assert last_error is not None
    raise last_error


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()
