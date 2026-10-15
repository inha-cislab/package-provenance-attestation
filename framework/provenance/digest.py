from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Dict, Iterable, Optional

from .http import Client

DEFAULT_ALGORITHMS = ("sha256", "sha512")

@dataclass(frozen=True)
class Digests:
    values: Dict[str, str]
    size: int

    def __getitem__(self, algorithm: str) -> str:
        return self.values[algorithm]

    def get(self, algorithm: str) -> Optional[str]:
        return self.values.get(algorithm)

    def items(self):
        return self.values.items()

def digest_bytes(data: bytes, algorithms: Iterable[str] = DEFAULT_ALGORITHMS) -> Digests:
    return Digests(
        {name: hashlib.new(name, data).hexdigest() for name in algorithms}, len(data)
    )

def digest_artifact(
    client: Client,
    url: str,
    algorithms: Iterable[str] = DEFAULT_ALGORITHMS,
) -> Digests:
    algorithms = tuple(algorithms)
    computed = None

    def consume(response):
        nonlocal computed
        hashes = {name: hashlib.new(name) for name in algorithms}
        size = 0
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            for hasher in hashes.values():
                hasher.update(chunk)
        length = getattr(response, "headers", {}).get("Content-Length")
        if length is not None and size != int(length):
            raise OSError(f"incomplete artifact: expected {length} bytes, got {size}")
        computed = Digests({name: hasher.hexdigest() for name, hasher in hashes.items()}, size)

    request = client.request(url, method="GET", consume=consume)
    if not request.ok:
        raise OSError(f"GET {url} returned {request.status}")
    if computed is None:
        raise OSError(f"GET {url} did not yield artifact bytes")
    return computed

def decode_subresource_integrity(value: str) -> Optional[str]:
    if "-" not in value:
        return None
    algorithm, _, encoded = value.partition("-")
    try:
        return base64.b64decode(encoded).hex()
    except Exception:
        return None
